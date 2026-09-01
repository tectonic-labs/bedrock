//! Operating-system randomness for cryptographic operations.

use thiserror::Error as ThisError;

/// Failure to obtain cryptographically secure operating-system randomness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
#[error("operating-system randomness failed")]
pub struct RandomError;

/// Fills `destination` with cryptographically secure operating-system randomness.
pub fn fill(destination: &mut [u8]) -> Result<(), RandomError> {
    getrandom_v04::fill(destination).map_err(|_| RandomError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_the_requested_buffer() {
        let mut bytes = [0u8; 32];
        assert!(fill(&mut bytes).is_ok());
        assert_ne!(bytes, [0u8; 32]);
    }
}
