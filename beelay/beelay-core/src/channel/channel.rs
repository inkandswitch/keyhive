use super::encrypted::Encrypted;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::SharedSecret;

/// Pairwise channel state
pub struct Channel {
    secret: SharedSecret,

    our_id: VerifyingKey,
    our_ratchet: [u8; 32],
    our_seq_id: u64,

    their_id: VerifyingKey,
    their_ratchet: [u8; 32],
    their_seq_id: u64,

    message_buffer: HashMap<u64, Vec<u8>>,
}

impl Channel {
    pub fn new(channel_secret: SharedSecret, us: VerifyingKey, them: VerifyingKey) -> Self {
        Self {
            secret: channel_secret,

            our_id: us,
            our_ratchet: us.to_bytes(),
            our_seq_id: 0,

            their_id: them,
            their_ratchet: them.to_bytes(),
            their_seq_id: 0,

            message_buffer: HashMap::new(),
        }
    }

    pub fn try_encrypt(&mut self, msg: &[u8]) -> Result<Encrypted, chacha20poly1305::Error> {
        let (key, nonce, new_ratchet, assoc_data) = step_ratchet(
            &mut self.our_ratchet,
            &self.secret,
            self.our_id,
            self.our_seq_id,
        );

        let mut ciphertext = msg.to_vec();
        key.encrypt_in_place(&nonce, assoc_data.as_slice(), &mut ciphertext)?;

        let encrypted = Encrypted {
            ciphertext,
            seq_id: self.our_seq_id,
        };

        self.our_ratchet = new_ratchet;
        self.our_seq_id += 1;

        Ok(encrypted)
    }

    pub fn try_decrypt(&mut self, envelope: Encrypted) -> Result<Vec<u8>, DecryptError> {
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
            self.their_id,
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
