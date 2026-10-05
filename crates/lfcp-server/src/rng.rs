//! Randomness from the operating system, for the server ID and, from
//! LFCP-047/048, the per-connection server nonce and session ID (WIRE-01
//! §35). sdk-rs has no random source of its own; the server owns it.

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
    }
}
