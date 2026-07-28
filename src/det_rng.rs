//! Deterministic CSPRNG following RFC 6979's HMAC_DRBG construction, used to
//! make otherwise-randomized signing reproducible.
//!
//! Construction: the RFC 6979 §3.2 HMAC_DRBG `K`/`V` ladder over HMAC-SHA-512,
//! instantiated with the signing key as the private input and the message as
//! the data. HMAC keys the PRF with secret material; unlike a bare
//! `H(secret || message)` prefix hash, it has no length-extension weakness and
//! is the standardized deterministic-nonce construction. After instantiation
//! the key `K` is fixed and each 64-byte output block is `V = HMAC_K(V)`, so
//! the stream is unbounded.

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const LEN: usize = 64;
const BYTE_00: &[u8] = &[0x00];
const BYTE_01: &[u8] = &[0x01];

/// Deterministic RFC 6979 HMAC_DRBG over HMAC-SHA-512.
pub struct DetRng {
    /// HMAC pre-keyed with the DRBG key `K`.
    mac: HmacSha512,
    v: [u8; LEN],
    buf: [u8; LEN],
    pos: usize,
}

impl core::fmt::Debug for DetRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DetRng")
            .field("mac", &"<redacted>")
            .field("v", &"<redacted>")
            .field("buf", &"<redacted>")
            .field("pos", &self.pos)
            .finish()
    }
}

/// HMAC-SHA-512 over `parts` under `key`.
fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; LEN]> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|_| Error::DetRngError("failed to initialize HMAC-SHA-512".to_string()))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

impl DetRng {
    /// Instantiate per RFC 6979 §3.2.
    pub fn new(domain: &[u8], secret: &[u8], message: &[u8]) -> Result<Self> {
        let mut v = [0x01u8; LEN];
        let mut k = [0x00u8; LEN];

        k = hmac(&k, &[&v, BYTE_00, domain, secret, message])?;
        v = hmac(&k, &[&v])?;
        k = hmac(&k, &[&v, BYTE_01, domain, secret, message])?;
        v = hmac(&k, &[&v])?;

        let mac = HmacSha512::new_from_slice(&k)
            .map_err(|_| Error::DetRngError("failed to initialize HMAC-SHA-512".to_string()))?;
        k.zeroize();

        Ok(Self {
            mac,
            v,
            buf: [0u8; LEN],
            pos: LEN,
        })
    }

    /// RFC 6979 §3.2 generate step: `V = HMAC_K(V)`, emit `V`.
    fn refill(&mut self) {
        let mut mac = self.mac.clone();
        mac.update(&self.v);
        let out = mac.finalize().into_bytes();
        self.v.copy_from_slice(&out);
        self.buf.copy_from_slice(&out);
        self.pos = 0;
    }
}

impl RngCore for DetRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut off = 0usize;
        while off < dest.len() {
            if self.pos == LEN {
                self.refill();
            }
            let take = (LEN - self.pos).min(dest.len() - off);
            dest[off..off + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            off += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DetRng {}

impl Drop for DetRng {
    fn drop(&mut self) {
        self.v.zeroize();
        self.buf.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn draw(domain: &[u8], secret: &[u8], message: &[u8], n: usize) -> Vec<u8> {
        let mut rng = DetRng::new(domain, secret, message).unwrap();
        let mut out = vec![0u8; n];
        rng.fill_bytes(&mut out);
        out
    }

    #[test]
    fn same_inputs_give_same_stream() {
        assert_eq!(
            draw(b"dom", b"key", b"msg", 200),
            draw(b"dom", b"key", b"msg", 200)
        );
    }

    #[test]
    fn each_input_separately_changes_the_stream() {
        let base = draw(b"dom", b"key", b"msg", 64);
        assert_ne!(base, draw(b"dom", b"key", b"msg2", 64), "message is bound");
        assert_ne!(base, draw(b"dom", b"key2", b"msg", 64), "secret is bound");
        assert_ne!(base, draw(b"dom2", b"key", b"msg", 64), "domain is bound");
    }

    /// A single large draw must equal the concatenation of smaller draws that
    /// straddle the 64-byte block boundary, otherwise the refill bookkeeping is
    /// dropping or repeating bytes.
    #[test]
    fn draws_are_consistent_across_block_boundaries() {
        let whole = draw(b"dom", b"seed", b"m", 130);

        let mut split = DetRng::new(b"dom", b"seed", b"m").unwrap();
        let mut first = [0u8; 50];
        let mut second = [0u8; 80];
        split.fill_bytes(&mut first);
        split.fill_bytes(&mut second);

        assert_eq!(&whole[..50], &first[..]);
        assert_eq!(&whole[50..], &second[..]);
    }

    /// Consecutive output blocks must differ. If `refill` failed to advance `V`,
    /// every block would be identical and the stream would silently repeat.
    #[test]
    fn consecutive_blocks_differ() {
        let stream = draw(b"dom", b"key", b"msg", LEN * 3);
        assert_ne!(&stream[..LEN], &stream[LEN..LEN * 2]);
        assert_ne!(&stream[LEN..LEN * 2], &stream[LEN * 2..]);
        assert!(
            stream.iter().any(|&b| b != 0),
            "stream must not be all zero"
        );
    }

    #[test]
    fn next_u32_and_u64_match_the_equivalent_fill_bytes_draw() {
        let mut rng = DetRng::new(b"dom", b"key", b"msg").unwrap();
        let a = rng.next_u32();
        let b = rng.next_u64();

        let raw = draw(b"dom", b"key", b"msg", 12);
        assert_eq!(a, u32::from_le_bytes(raw[..4].try_into().unwrap()));
        assert_eq!(b, u64::from_le_bytes(raw[4..12].try_into().unwrap()));
    }

    /// The `Debug` impl exists to satisfy `missing_debug_implementations` without
    /// leaking key material, so it must not print any state but the cursor.
    #[test]
    fn debug_redacts_state() {
        let rng = DetRng::new(b"dom", b"key", b"msg").unwrap();
        let rendered = format!("{:?}", rng);
        assert!(rendered.contains("<redacted>"));
        assert_eq!(rendered.matches("<redacted>").count(), 3);
    }
}
