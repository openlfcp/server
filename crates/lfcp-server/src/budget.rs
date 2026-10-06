//! Byte budgets for outbound messages (security review H6, POST-004).
//!
//! Every outbound message holds a [`Reservation`] of its encoded size from
//! two [`ByteBudget`]s: its connection's (`max_outbound_bytes`) and the
//! server-wide one (`max_total_outbound_bytes`). The reservation is released
//! when the message has been written to the socket, or dropped with its
//! queue. A GET reply reserves room for a page before it reads the page
//! from the store, so the bytes it builds are counted too.
//!
//! Two ways to reserve:
//! - [`Budgets::try_reserve`] never waits; live pushes use it, and a push
//!   that does not fit closes its subscriber, as a full queue did before.
//! - [`Budgets::reserve`] waits until both budgets have room (backpressure):
//!   the session's replies and GET pages use it. It gives up when the
//!   connection is halted (aborted, its writer gone, or the server shutting
//!   down).
//!
//! A reservation larger than a budget's limit is clamped to it, so it can
//! always be granted once the budget is empty.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// A byte limit shared by reservations.
#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    state: Mutex<State>,
    freed: Notify,
    /// The highest peak of any connection budget drawing on this one.
    connection_peak: AtomicUsize,
}

#[derive(Debug, Default)]
struct State {
    used: usize,
    peak: usize,
}

impl ByteBudget {
    /// A budget of `limit` bytes.
    pub fn new(limit: usize) -> Arc<ByteBudget> {
        Arc::new(ByteBudget {
            limit,
            state: Mutex::default(),
            freed: Notify::new(),
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

    /// For the server-wide budget: the highest [`ByteBudget::peak`] of any
    /// connection's budget.
    pub fn connection_peak(&self) -> usize {
        self.connection_peak.load(Ordering::SeqCst)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn take(&self, bytes: usize) -> bool {
        let mut state = self.lock();
        if state.used + bytes > self.limit {
            return false;
        }
        state.used += bytes;
        state.peak = state.peak.max(state.used);
        true
    }

    fn give(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.lock().used -= bytes;
        self.freed.notify_waiters();
    }
}

/// One connection's budgets: its own and the server-wide one.
#[derive(Clone, Debug)]
pub struct Budgets {
    connection: Arc<ByteBudget>,
    global: Arc<ByteBudget>,
    halt: Arc<Halt>,
}

#[derive(Debug, Default)]
struct Halt {
    halted: AtomicBool,
    notify: Notify,
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

    /// Make every waiting and later [`Budgets::reserve`] fail.
    pub fn halt(&self) {
        self.halt.halted.store(true, Ordering::SeqCst);
        self.halt.notify.notify_waiters();
    }

    fn halted(&self) -> bool {
        self.halt.halted.load(Ordering::SeqCst)
    }

    fn clamp(&self, bytes: usize) -> usize {
        bytes.min(self.connection.limit).min(self.global.limit)
    }

    fn take(&self, bytes: usize) -> Option<Reservation> {
        if !self.connection.take(bytes) {
            return None;
        }
        if !self.global.take(bytes) {
            self.connection.give(bytes);
            return None;
        }
        self.global
            .connection_peak
            .fetch_max(self.connection.peak(), Ordering::SeqCst);
        Some(Reservation {
            budgets: self.clone(),
            bytes,
        })
    }

    /// Reserve `bytes` now, or `None` without waiting.
    pub fn try_reserve(&self, bytes: usize) -> Option<Reservation> {
        if self.halted() {
            return None;
        }
        self.take(self.clamp(bytes))
    }

    /// Reserve `bytes`, waiting until both budgets have room; `None` once
    /// the connection is halted.
    pub async fn reserve(&self, bytes: usize) -> Option<Reservation> {
        let bytes = self.clamp(bytes);
        loop {
            // Registered before the check, so a release in between is not
            // missed.
            let connection = self.connection.freed.notified();
            let global = self.global.freed.notified();
            let halt = self.halt.notify.notified();
            tokio::pin!(connection, global, halt);
            connection.as_mut().enable();
            global.as_mut().enable();
            halt.as_mut().enable();
            if self.halted() {
                return None;
            }
            if let Some(reservation) = self.take(bytes) {
                return Some(reservation);
            }
            tokio::select! {
                () = connection => {}
                () = global => {}
                () = halt => {}
            }
        }
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
    }
}
