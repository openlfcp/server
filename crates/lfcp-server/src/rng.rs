//! Randomness from the operating system, for the server ID, the
//! per-connection server nonce and session ID (WIRE-01 §35) and message
//! IDs (§5.4). sdk-rs has no random source of its own; the server owns it.
//!
//! The session draws its values through [`Random`], so a test can inject
//! fixed values and compare the server's messages byte for byte with the
//! published vectors. Production uses [`OsRandom`].

/// A source of random bytes for the LFCP session.
pub trait Random: Send + Sync + 'static {
    /// Fill `bytes`, or fail if no randomness is available.
    fn fill(&self, bytes: &mut [u8]) -> Result<(), String>;

    /// A fresh 16-byte value: a server nonce, session ID or message ID.
    fn nonce16(&self) -> Result<[u8; 16], String> {
        let mut bytes = [0u8; 16];
        self.fill(&mut bytes)?;
        Ok(bytes)
    }
}

/// The operating system's random source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), String> {
        getrandom::fill(bytes).map_err(|e| e.to_string())
    }
}

/// `N` bytes from the operating system's random source.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// A fresh 16-byte server nonce or session ID (WIRE-01 §35).
pub fn nonce16() -> Result<[u8; 16], String> {
    random_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_differ() {
        let a = nonce16().unwrap();
        let b = nonce16().unwrap();
        assert_ne!(a, b);
        assert_ne!(random_bytes::<32>().unwrap(), [0; 32]);
        assert_ne!(OsRandom.nonce16().unwrap(), OsRandom.nonce16().unwrap());
    }
}
