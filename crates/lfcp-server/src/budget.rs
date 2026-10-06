//! Byte budgets for outbound messages (security review H6, POST-004).
//!
//! Every outbound message holds a [`Reservation`] of its encoded size from
//! two [`ByteBudget`]s: its connection's (`max_outbound_bytes`) and the
//! server-wide one (`max_total_outbound_bytes`). The reservation is released
//! when the message has been written to the socket, or dropped with its
//! queue. A GET reply reserves room for a page before it reads the page
//! from the store, so the bytes it builds are counted too.
//!
//! Three ways to reserve:
//! - [`Budgets::try_reserve`] never waits; live pushes use it, and a push
//!   that does not fit closes its subscriber, as a full queue did before.
//! - [`Budgets::reserve`] waits until both budgets have room (backpressure),
//!   for bulk replies: GET pages and Snapshots.
//! - [`Budgets::reserve_control`] waits too, for every other reply (the
//!   handshake, ACK, NACK, PONG, Have vectors): small, and never queued
//!   behind bulk replies.
//!
//! Waiting parks the task and gives up when the connection is halted
//! (aborted, its writer gone, or the server shutting down). Waiters are
//! served first come, first served, control replies before bulk ones: a
//! release grants the bytes to the waiters at the head of the queues that
//! now fit, waking each of them once. A waiter is never woken to find no
//! room, so many waiters cost nothing while they wait. On the server-wide
//! budget, bulk replies may use only the limit less a reserved slice
//! ([`GLOBAL_CONTROL_SLICE`]), so other sessions' handshakes and ACKs get
//! through while GET pages fill the rest. A reservation that does not wait
//! ([`Budgets::try_reserve`]) may pass the queues: it is never larger than
//! one message and keeps live pushes flowing.
//!
//! A reservation larger than a budget's limit (for bulk replies on the
//! server-wide budget, the limit less the slice) is clamped to it, so it
//! can always be granted once the budget is empty. A connection waits for
//! its own budget first, then for the server-wide one.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{oneshot, Notify};

/// The share of the server-wide budget that bulk replies may not use, in
/// eighths: an eighth stays free for control replies.
pub const GLOBAL_CONTROL_SLICE: usize = 8;

/// A byte limit shared by reservations.
#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    /// Bytes bulk reservations leave free for control ones.
    slice: usize,
    state: Mutex<State>,
    /// The highest peak of any connection budget drawing on this one.
    connection_peak: AtomicUsize,
}

#[derive(Debug, Default)]
struct State {
    used: usize,
    peak: usize,
    control: VecDeque<Waiter>,
    bulk: VecDeque<Waiter>,
    next_waiter: u64,
}

/// What a reservation is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Control,
    Bulk,
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    bytes: usize,
    granted: oneshot::Sender<()>,
}

impl State {
    fn take(&mut self, bytes: usize) {
        self.used += bytes;
        self.peak = self.peak.max(self.used);
    }

    /// Grant the bytes to the waiters at the heads of the queues that fit,
    /// control ones first; bulk ones only while no control one waits. A
    /// granted waiter owns its bytes even if it is gone: its [`Pending`]
    /// guard gives them back.
    fn grant(&mut self, limit: usize, slice: usize) {
        while let Some(bytes) = self.control.front().map(|w| w.bytes) {
            if self.used + bytes > limit {
                return;
            }
            let waiter = self.control.pop_front().expect("a front waiter");
            self.take(bytes);
            let _ = waiter.granted.send(());
        }
        while let Some(bytes) = self.bulk.front().map(|w| w.bytes) {
            if self.used + bytes > limit - slice {
                return;
            }
            let waiter = self.bulk.pop_front().expect("a front waiter");
            self.take(bytes);
            let _ = waiter.granted.send(());
        }
    }

    fn queue(&mut self, kind: Kind) -> &mut VecDeque<Waiter> {
        match kind {
            Kind::Control => &mut self.control,
            Kind::Bulk => &mut self.bulk,
        }
    }
}

impl ByteBudget {
    /// A connection's budget of `limit` bytes.
    pub fn new(limit: usize) -> Arc<ByteBudget> {
        ByteBudget::with_slice(limit, 0)
    }

    /// The server-wide budget of `limit` bytes, of which bulk replies leave
    /// 1/[`GLOBAL_CONTROL_SLICE`] to control replies.
    pub fn server(limit: usize) -> Arc<ByteBudget> {
        ByteBudget::with_slice(limit, limit / GLOBAL_CONTROL_SLICE)
    }

    fn with_slice(limit: usize, slice: usize) -> Arc<ByteBudget> {
        Arc::new(ByteBudget {
            limit,
            slice,
            state: Mutex::default(),
            connection_peak: AtomicUsize::new(0),
        })
    }

    /// The limit.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The bytes reserved now.
    pub fn used(&self) -> usize {
        self.lock().used
    }

    /// The most bytes ever reserved at once.
    pub fn peak(&self) -> usize {
        self.lock().peak
    }

    /// How many reservations are waiting for room.
    pub fn waiting(&self) -> usize {
        let state = self.lock();
        state.control.len() + state.bulk.len()
    }

    /// The most a reservation of `kind` can hold.
    fn room(&self, kind: Kind) -> usize {
        match kind {
            Kind::Control => self.limit,
            Kind::Bulk => self.limit - self.slice,
        }
    }

    /// For the server-wide budget: the highest [`ByteBudget::peak`] of any
    /// connection's budget.
    pub fn connection_peak(&self) -> usize {
        self.connection_peak.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take `bytes` if they fit now, passing any waiters.
    fn try_take(&self, bytes: usize) -> bool {
        let mut state = self.lock();
        if state.used + bytes > self.limit {
            return false;
        }
        state.take(bytes);
        true
    }

    /// Take `bytes` for `kind`, waiting in turn for room; false if `halt`
    /// fires first.
    async fn take(self: &Arc<Self>, bytes: usize, kind: Kind, halt: &Halt) -> bool {
        let (granted, pending) = {
            let mut state = self.lock();
            let first = match kind {
                Kind::Control => state.control.is_empty(),
                Kind::Bulk => state.control.is_empty() && state.bulk.is_empty(),
            };
            if first && state.used + bytes <= self.room(kind) {
                state.take(bytes);
                return true;
            }
            let id = state.next_waiter;
            state.next_waiter += 1;
            let (sender, granted) = oneshot::channel();
            state.queue(kind).push_back(Waiter {
                id,
                bytes,
                granted: sender,
            });
            (
                granted,
                Pending {
                    budget: self.clone(),
                    id,
                    bytes,
                    armed: true,
                },
            )
        };
        let mut pending = pending;
        tokio::select! {
            biased;
            Ok(()) = granted => {
                pending.armed = false;
                true
            }
            () = halt.wait() => false,
        }
    }

    fn give(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut state = self.lock();
        state.used -= bytes;
        state.grant(self.limit, self.slice);
    }
}

/// A queued waiter: on drop before it has its bytes, it leaves the queue,
/// or gives back the bytes it was granted meanwhile.
struct Pending {
    budget: Arc<ByteBudget>,
    id: u64,
    bytes: usize,
    armed: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.budget.lock();
        let queued = [Kind::Control, Kind::Bulk].into_iter().find_map(|kind| {
            let queue = state.queue(kind);
            let index = queue.iter().position(|w| w.id == self.id)?;
            queue.remove(index)
        });
        if queued.is_none() {
            state.used -= self.bytes;
        }
        // Leaving the head may let the next waiters in.
        state.grant(self.budget.limit, self.budget.slice);
    }
}

/// Bytes taken from one budget, given back on drop unless kept.
struct Held {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl Held {
    fn keep(mut self) {
        self.bytes = 0;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.budget.give(self.bytes);
    }
}

#[derive(Debug, Default)]
struct Halt {
    halted: AtomicBool,
    notify: Notify,
}

impl Halt {
    /// Completes once halted; parks until then.
    async fn wait(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.halted.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

/// One connection's budgets: its own and the server-wide one.
#[derive(Clone, Debug)]
pub struct Budgets {
    connection: Arc<ByteBudget>,
    global: Arc<ByteBudget>,
    halt: Arc<Halt>,
}

impl Budgets {
    /// A connection budget of `limit` bytes drawing on `global`.
    pub fn new(limit: usize, global: Arc<ByteBudget>) -> Budgets {
        Budgets {
            connection: ByteBudget::new(limit),
            global,
            halt: Arc::default(),
        }
    }

    /// The connection's budget.
    pub fn connection(&self) -> &ByteBudget {
        &self.connection
    }

    /// Make every waiting and later reservation fail.
    pub fn halt(&self) {
        self.halt.halted.store(true, Ordering::SeqCst);
        self.halt.notify.notify_waiters();
    }

    fn halted(&self) -> bool {
        self.halt.halted.load(Ordering::SeqCst)
    }

    fn clamp(&self, bytes: usize, kind: Kind) -> usize {
        bytes
            .min(self.connection.room(kind))
            .min(self.global.room(kind))
    }

    fn reservation(&self, bytes: usize) -> Reservation {
        self.global
            .connection_peak
            .fetch_max(self.connection.peak(), Ordering::SeqCst);
        Reservation {
            budgets: self.clone(),
            bytes,
        }
    }

    /// Reserve `bytes` now, or `None` without waiting.
    pub fn try_reserve(&self, bytes: usize) -> Option<Reservation> {
        let bytes = self.clamp(bytes, Kind::Control);
        if self.halted() || !self.connection.try_take(bytes) {
            return None;
        }
        if !self.global.try_take(bytes) {
            self.connection.give(bytes);
            return None;
        }
        Some(self.reservation(bytes))
    }

    /// Reserve `bytes` for a bulk reply, waiting in turn until both
    /// budgets have room; `None` once the connection is halted.
    pub async fn reserve(&self, bytes: usize) -> Option<Reservation> {
        self.reserve_kind(bytes, Kind::Bulk).await
    }

    /// Reserve `bytes` for a control reply, waiting in turn (ahead of bulk
    /// replies) until both budgets have room; `None` once the connection
    /// is halted.
    pub async fn reserve_control(&self, bytes: usize) -> Option<Reservation> {
        self.reserve_kind(bytes, Kind::Control).await
    }

    async fn reserve_kind(&self, bytes: usize, kind: Kind) -> Option<Reservation> {
        let bytes = self.clamp(bytes, kind);
        if self.halted() || !self.connection.take(bytes, kind, &self.halt).await {
            return None;
        }
        let held = Held {
            budget: self.connection.clone(),
            bytes,
        };
        if !self.global.take(bytes, kind, &self.halt).await {
            return None;
        }
        held.keep();
        Some(self.reservation(bytes))
    }
}

/// Bytes reserved from a connection's budgets, released on drop.
#[derive(Debug)]
pub struct Reservation {
    budgets: Budgets,
    bytes: usize,
}

impl Reservation {
    /// The reserved bytes.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Release all but `bytes` (no-op if it holds no more).
    pub fn shrink_to(&mut self, bytes: usize) {
        if bytes < self.bytes {
            let surplus = self.bytes - bytes;
            self.bytes = bytes;
            self.budgets.global.give(surplus);
            self.budgets.connection.give(surplus);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.shrink_to(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn both_budgets_bound_a_reservation() {
        let global = ByteBudget::new(100);
        let a = Budgets::new(60, global.clone());
        let b = Budgets::new(60, global.clone());
        let first = a.try_reserve(50).unwrap();
        assert!(a.try_reserve(20).is_none(), "the connection budget is full");
        let second = b.try_reserve(50).unwrap();
        assert!(b.try_reserve(1).is_none(), "the global budget is full");
        assert_eq!(a.connection().used(), 50);
        assert_eq!(global.used(), 100);
        drop(first);
        assert_eq!(a.connection().used(), 0);
        assert_eq!(global.used(), 50);
        drop(second);
        let mut third = a.try_reserve(1_000).unwrap();
        assert_eq!(third.bytes(), 60, "clamped to the connection limit");
        third.shrink_to(10);
        assert_eq!(global.used(), 10);
        drop(third);
        assert_eq!(global.used(), 0);
        assert_eq!(global.peak(), 100);
        assert_eq!(global.connection_peak(), 60);
    }

    #[tokio::test]
    async fn reserve_waits_for_room_and_stops_when_halted() {
        let global = ByteBudget::new(100);
        let budgets = Budgets::new(100, global.clone());
        let held = budgets.try_reserve(80).unwrap();
        let waiting = tokio::spawn({
            let budgets = budgets.clone();
            async move { budgets.reserve(40).await.map(|r| r.bytes()) }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        assert_eq!(budgets.connection().waiting(), 1);
        drop(held);
        assert_eq!(waiting.await.unwrap(), Some(40));

        let held = budgets.try_reserve(100).unwrap();
        let waiting = tokio::spawn({
            let budgets = budgets.clone();
            async move { budgets.reserve(1).await.is_some() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        budgets.halt();
        assert!(!waiting.await.unwrap());
        assert!(budgets.try_reserve(0).is_none());
        drop(held);
        assert_eq!(global.used(), 0);
        assert_eq!(budgets.connection().waiting(), 0);
    }

    #[tokio::test]
    async fn waiters_are_served_in_order_and_a_cancelled_one_leaves() {
        let global = ByteBudget::new(10);
        let budgets = Budgets::new(10, global.clone());
        let held = budgets.try_reserve(10).unwrap();
        // A large waiter first: a later small one does not pass it.
        let large = tokio::spawn({
            let budgets = budgets.clone();
            async move { budgets.reserve(8).await.map(|r| r.bytes()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let small = tokio::spawn({
            let budgets = budgets.clone();
            async move { budgets.reserve(2).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let cancelled = tokio::spawn({
            let budgets = budgets.clone();
            async move { budgets.reserve(5).await.map(|r| r.bytes()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(budgets.connection().waiting(), 3);
        cancelled.abort();
        assert!(cancelled.await.is_err());
        assert_eq!(budgets.connection().waiting(), 2);
        drop(held);
        assert_eq!(large.await.unwrap(), Some(8));
        let small = small.await.unwrap().unwrap();
        assert_eq!(small.bytes(), 2);
        drop(small);
        assert_eq!(global.used(), 0);
        assert_eq!(budgets.connection().used(), 0);
    }

    #[tokio::test]
    async fn control_replies_pass_bulk_ones_and_keep_a_slice() {
        // 80 bytes: bulk replies may use 70, control ones all 80.
        let global = ByteBudget::server(80);
        let pages = Budgets::new(80, global.clone());
        let other = Budgets::new(80, global.clone());
        let page = pages.reserve(60).await.unwrap();
        assert!(pages.try_reserve(30).is_none());
        let waiting_page = tokio::spawn({
            let pages = pages.clone();
            async move { pages.reserve(20).await.map(|r| r.bytes()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Another session's ACK is not queued behind the waiting page: it
        // fits in the slice.
        let ack = tokio::time::timeout(Duration::from_secs(1), other.reserve_control(15))
            .await
            .expect("a control reply does not wait behind pages")
            .unwrap();
        assert_eq!(global.used(), 75);
        assert!(!waiting_page.is_finished());
        drop(ack);
        assert!(
            !waiting_page.is_finished(),
            "60 + 20 is beyond the bulk room"
        );
        drop(page);
        assert_eq!(waiting_page.await.unwrap(), Some(20));
        assert_eq!(global.used(), 0);
    }

    /// The POST-004 bench livelock: many connections waiting on a small
    /// server-wide budget while others release it. A waiter woken by every
    /// release retried without yielding and took every runtime thread, so
    /// nothing progressed; a tokio timeout could not even fire. The
    /// watchdog is therefore a plain thread.
    #[test]
    fn many_waiters_on_a_small_global_budget_make_progress() {
        let global = ByteBudget::new(24);
        let (done, finished) = std::sync::mpsc::channel();
        let budget = global.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .build()
                .unwrap();
            runtime.block_on(async {
                let mut tasks = Vec::new();
                for _ in 0..50 {
                    let budgets = Budgets::new(4, budget.clone());
                    tasks.push(tokio::spawn(async move {
                        for _ in 0..200 {
                            let mut page = budgets.reserve(2).await.unwrap();
                            page.shrink_to(1);
                            tokio::task::yield_now().await;
                            drop(page);
                        }
                    }));
                }
                for task in tasks {
                    task.await.unwrap();
                }
            });
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(20))
            .expect("every waiter is served");
        assert_eq!(global.used(), 0);
        assert!(global.peak() <= 24);
        assert_eq!(global.waiting(), 0);
    }
}
