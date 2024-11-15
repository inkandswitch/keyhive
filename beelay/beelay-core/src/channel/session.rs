use super::encrypted::Encrypted;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret};

/// Pairwise channel state.
///
/// This channel implements a simple causal delivery mechanism,
/// and buffers messages delivered out of sequence.
pub struct Session {
    /// Root session secret.
    ///
    /// All other Session keys are derived from this root secret.
    /// This value must not be changed. To rotate the secret, open a new channel.
    secret: SharedSecret,

    /// Latest ratchet for items that we send.
    our_ratchet: [u8; 32],

    /// The number of messages that we've sent on this channel.
    our_seq_id: u64,

    /// Latest ratchet for items that we receive.
    their_ratchet: [u8; 32],

    /// The number of messages that they've sent on this channel.
    their_seq_id: u64,

    /// Messages that have been delivered out of order.
    message_buffer: HashMap<u64, Vec<u8>>,
}

impl Session {
    pub fn new(our_sk: &ReusableSecret, their_pk: &PublicKey) -> Self {
        let secret = our_sk.diffie_hellman(&their_pk);
        let secret_bytes: [u8; 32] = secret.to_bytes();

        let mut our_pk_bytes: Vec<u8> = PublicKey::from(our_sk).to_bytes().to_vec();
        our_pk_bytes.extend(secret_bytes);
        let our_ratchet: [u8; 32] = *blake3::hash(our_pk_bytes.as_slice()).as_bytes();

        let mut their_pk_bytes: Vec<u8> = their_pk.to_bytes().to_vec();
        their_pk_bytes.extend(secret_bytes);
        let their_ratchet: [u8; 32] = *blake3::hash(their_pk_bytes.as_slice()).as_bytes();

        Self {
            secret,

            our_ratchet,
            our_seq_id: 0,

            their_ratchet,
            their_seq_id: 0,

            message_buffer: HashMap::new(),
        }
    }

    pub fn try_encrypt(
        &mut self,
        our_id: &VerifyingKey,
        msg: &[u8],
    ) -> Result<Encrypted, chacha20poly1305::Error> {
        let (key, nonce, new_ratchet, assoc_data) = step_ratchet(
            &mut self.our_ratchet,
            &self.secret,
            *our_id,
            self.our_seq_id,
        );

        let mut ciphertext = msg.to_vec();
        key.encrypt_in_place(&nonce, assoc_data.as_slice(), &mut ciphertext)?;

        self.our_ratchet = new_ratchet;
        self.our_seq_id += 1;

        let encrypted = Encrypted {
            ciphertext,
            seq_id: self.our_seq_id,
        };

        Ok(encrypted)
    }

    pub fn try_decrypt(
        &mut self,
        their_id: &VerifyingKey,
        envelope: Encrypted,
    ) -> Result<Vec<u8>, DecryptError> {
        if envelope.seq_id != self.their_seq_id + 1 {
            self.message_buffer
                .insert(envelope.seq_id, envelope.ciphertext);

            return Err(DecryptError::OutOfSequence {
                next: self.their_seq_id,
                got: envelope.seq_id,
            });
        }

        let (key, nonce, new_ratchet, assoc_data) = step_ratchet(
            &mut self.their_ratchet,
            &self.secret,
            *their_id,
            self.their_seq_id,
        );

        // Cloning here in case decryption fails and we want to inspect the message
        let mut plaintext = envelope.ciphertext.clone();
        key.decrypt_in_place(&nonce, assoc_data.as_slice(), &mut plaintext)
            .map_err(DecryptError::ChaChaError)?;

        self.their_ratchet = new_ratchet;
        self.their_seq_id += 1;

        Ok(plaintext)
    }
}

#[derive(Debug, Clone, Error)]
pub enum DecryptError {
    #[error("Unable to decrypt")]
    ChaChaError(chacha20poly1305::Error),

    #[error("Message out of sequence; expected {next} but got {got}")]
    OutOfSequence { next: u64, got: u64 },
}

fn step_ratchet(
    ratchet: &mut [u8; 32],
    channel_secret: &SharedSecret,
    encrypter: VerifyingKey,
    seq_id: u64,
) -> (XChaCha20Poly1305, XNonce, [u8; 32], Vec<u8>) {
    let mut new_ratchet = [0; 32];
    let mut key_preimage = [0; 32];
    let mut nonce_bytes = [0; 24];

    let mut hasher = blake3::Hasher::new_keyed(&ratchet);
    hasher.update(b"/beelay/channel/ratchet/");
    let mut source = hasher.finalize_xof();
    source.fill(&mut new_ratchet);
    source.fill(&mut key_preimage);
    source.fill(&mut nonce_bytes);

    let key_bytes = blake3::derive_key(&"/beelay/channel/kdf/", &key_preimage);
    let key = XChaCha20Poly1305::new_from_slice(key_bytes.as_slice()).unwrap(); // Only fails if not 32 bytes
    let nonce = XNonce::from_mut_slice(&mut nonce_bytes);

    let mut assoc_data = channel_secret.to_bytes().to_vec();
    assoc_data.extend_from_slice(&encrypter.to_bytes());
    assoc_data.extend_from_slice(&seq_id.to_le_bytes());

    (key, *nonce, new_ratchet, assoc_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use x25519_dalek::EphemeralSecret;

    #[test]
    fn test_setup() {
        let us = ReusableSecret::random();
        let us_pk = PublicKey::from(&us);

        let them = ReusableSecret::random();
        let them_pk = PublicKey::from(&them);

        let s1 = Session::new(&us, &them_pk);
        let s2 = Session::new(&them, &us_pk);

        assert_eq!(s1.our_seq_id, 0);
        assert_eq!(s1.their_seq_id, 0);
        assert_ne!(s1.our_ratchet, s1.their_ratchet);

        assert_eq!(s1.secret.to_bytes(), s2.secret.to_bytes());

        assert_eq!(s1.our_ratchet, s2.their_ratchet);
        assert_eq!(s1.their_ratchet, s2.our_ratchet);

        assert_eq!(s1.our_seq_id, s2.their_seq_id);
        assert_eq!(s1.their_seq_id, s2.our_seq_id);

        assert_eq!(s1.message_buffer, s2.message_buffer);
    }

    #[test]
    fn test_try_encrypt() {
        let signer = SigningKey::generate(&mut rand::thread_rng());
        let our_id = signer.verifying_key();

        let us = ReusableSecret::random();
        let them = PublicKey::from(&EphemeralSecret::random());
        let mut s = Session::new(&us, &them);

        let encrypted = s.try_encrypt(&our_id, b"hello world").unwrap();

        assert_ne!(encrypted.ciphertext, b"hello world");
        assert_eq!(encrypted.seq_id, 1);
        assert_eq!(s.our_seq_id, 1);
    }

    #[test]
    fn test_try_decrypt() {
        let signer = SigningKey::generate(&mut rand::thread_rng());
        let alice_id = signer.verifying_key();

        let alice = ReusableSecret::random();
        let alice_pk = PublicKey::from(&alice);

        let bob = ReusableSecret::random();
        let bob_pk = PublicKey::from(&bob);

        let mut s1 = Session::new(&alice, &bob_pk);
        let mut s2 = Session::new(&bob, &alice_pk);

        let encrypted = s1.try_encrypt(&alice_id, b"hello world").unwrap();
        let decrypted = s2.try_decrypt(&alice_id, encrypted).unwrap();

        assert_eq!(decrypted, b"hello world");
    }
}
