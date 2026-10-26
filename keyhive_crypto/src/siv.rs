//! Synthetic nonces: derived from what a ciphertext authenticates rather than
//! drawn at random, and checked after decryption.
//!
//! A replica that recomputes the nonce from the decrypted plaintext, and finds
//! the one it was given, knows the ciphertext is committed to this key:
//! XChaCha20-Poly1305 alone is not key-committing. See
//! `design/ciphersuite.md`.

/// A synthetic nonce: the first 24 bytes of keyed BLAKE3 under `nonce_key`,
/// over `parts` in order.
///
/// The parts are concatenated as they are, so together they must be
/// unambiguous: every part but the last of a fixed or prefixed length.
pub fn synthetic_nonce(nonce_key: &[u8; 32], parts: &[&[u8]]) -> [u8; 24] {
    let mut hasher = blake3::Hasher::new_keyed(nonce_key);
    for part in parts {
        hasher.update(part);
    }
    let mut nonce = [0; 24];
    hasher.finalize_xof().fill(&mut nonce);
    nonce
}

/// Whether two nonces are equal, comparing every byte whatever the first
/// difference, so the time taken does not tell where they differ. For the
/// check after decryption that a nonce is the synthetic nonce of what it
/// decrypted to.
pub fn nonces_match(expected: &[u8; 24], received: &[u8; 24]) -> bool {
    expected
        .iter()
        .zip(received)
        .fold(0u8, |differ, (a, b)| differ | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checked with `b3sum --keyed --length 24`, the key `[1; 32]` on stdin,
    /// over the file `"key" ‖ "ed"`.
    #[test]
    fn a_synthetic_nonce_is_keyed_blake3_over_its_parts() {
        let nonce = synthetic_nonce(&[1; 32], &[b"key", b"ed"]);
        assert_eq!(nonce, synthetic_nonce(&[1; 32], &[b"keyed"]));
        assert_eq!(
            crate::hex::bytes_to_hex_string(&nonce),
            "0x539a3d613a403b3e1b4d883efb6133c0eb92fd6a49103ea1"
        );
    }

    #[test]
    fn nonces_match_only_when_every_byte_does() {
        let nonce = [7u8; 24];
        assert!(nonces_match(&nonce, &nonce));

        for at in [0, 11, 23] {
            let mut other = nonce;
            other[at] ^= 0x80;
            assert!(!nonces_match(&nonce, &other), "byte {at} differs");
        }

        // Two bytes that differ by the same bit: an XOR of the differences
        // would cancel, so every difference has to count.
        let mut twice = nonce;
        twice[3] ^= 1;
        twice[17] ^= 1;
        assert!(!nonces_match(&nonce, &twice));
    }
}
