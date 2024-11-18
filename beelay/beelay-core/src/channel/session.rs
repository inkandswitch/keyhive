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

        Ok(Encrypted {
            ciphertext,
            seq_id: self.our_seq_id,
        })
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
    use std::{cell::OnceCell, rc::Rc};
    use x25519_dalek::EphemeralSecret;

    mod new {
        use super::*;

        const FIXTURE: OnceCell<(Rc<Session>, Rc<Session>)> = OnceCell::new();

        fn fixie() -> (Rc<Session>, Rc<Session>) {
            FIXTURE
                .get_or_init(|| {
                    let us = ReusableSecret::random();
                    let us_pk = PublicKey::from(&us);

                    let them = ReusableSecret::random();
                    let them_pk = PublicKey::from(&them);

                    let ours = Session::new(&us, &them_pk);
                    let theirs = Session::new(&them, &us_pk);

                    (Rc::new(ours), Rc::new(theirs))
                })
                .clone()
        }

        #[test]
        fn test_init_our_seq_id() {
            let (ours, _) = fixie();
            assert_eq!(ours.our_seq_id, 0);
        }

        #[test]
        fn test_init_their_seq_id() {
            let (ours, _) = fixie();
            assert_eq!(ours.their_seq_id, 0);
        }

        #[test]
        fn test_ratchets_match() {
            let (ours, _) = fixie();
            assert_ne!(ours.our_ratchet, ours.their_ratchet);
        }

        #[test]
        fn test_starts_with_different_ratchets() {
            let (ours, _) = fixie();
            assert_ne!(ours.our_ratchet, ours.their_ratchet);
        }

        #[test]
        fn test_same_channel_secret_on_both() {
            let (ours, theirs) = fixie();
            assert_eq!(ours.secret.to_bytes(), theirs.secret.to_bytes());
        }

        #[test]
        fn test_agree_on_our_initial_ratchet() {
            let (ours, theirs) = fixie();
            assert_eq!(ours.our_ratchet, theirs.their_ratchet);
        }

        #[test]
        fn test_agree_on_their_initial_ratchet() {
            let (ours, theirs) = fixie();
            assert_eq!(ours.their_ratchet, theirs.our_ratchet);
        }

        #[test]
        fn test_agree_on_our_initial_seq_id() {
            let (ours, theirs) = fixie();
            assert_eq!(ours.our_seq_id, theirs.their_seq_id);
        }

        #[test]
        fn test_agree_on_their_initial_seq_id() {
            let (ours, theirs) = fixie();
            assert_eq!(ours.their_seq_id, theirs.our_seq_id);
        }

        #[test]
        fn test_same_starting_message_buffer() {
            let (ours, theirs) = fixie();
            assert_eq!(ours.message_buffer, theirs.message_buffer);
        }
    }

    mod try_encrypt {
        use super::*;

        #[derive(Clone)]
        struct Fixture1 {
            session: Rc<Session>,
            encrypted: Rc<Encrypted>,
        }

        const FIXTURE1: OnceCell<Fixture1> = OnceCell::new();

        fn fixie1() -> Fixture1 {
            FIXTURE1
                .get_or_init(|| {
                    let signer = SigningKey::generate(&mut rand::thread_rng());
                    let our_id = signer.verifying_key();

                    let us = ReusableSecret::random();
                    let them = PublicKey::from(&EphemeralSecret::random());
                    let mut s = Session::new(&us, &them);

                    let encrypted = s.try_encrypt(&our_id, b"hello world").unwrap();

                    Fixture1 {
                        session: Rc::new(s),
                        encrypted: Rc::new(encrypted),
                    }
                })
                .clone()
        }

        #[test]
        fn test_message_is_encrypted() {
            assert_ne!(fixie1().encrypted.ciphertext, b"hello world");
        }

        #[test]
        fn test_encrypted_seq_id_is_correct() {
            assert_eq!(fixie1().encrypted.seq_id, 1);
        }

        #[test]
        fn test_our_seq_id_updates() {
            assert_eq!(fixie1().session.our_seq_id, 1);
        }

        #[test]
        fn test_their_seq_id_is_unchanged() {
            assert_eq!(fixie1().session.their_seq_id, 0);
        }

        #[derive(Clone)]
        struct Fixture2 {
            session: Rc<Session>,
            reencrypted: Rc<Encrypted>,
            key: [u8; 32],
        }
        const FIXTURE2: OnceCell<Fixture2> = OnceCell::new();

        fn fixie2() -> Fixture2 {
            FIXTURE2
                .get_or_init(|| {
                    let signer = SigningKey::generate(&mut rand::thread_rng());
                    let our_id = signer.verifying_key();

                    let us = ReusableSecret::random();
                    let them = PublicKey::from(&EphemeralSecret::random());
                    let mut s = Session::new(&us, &them);
                    s.try_encrypt(&our_id, b"hello world").unwrap();
                    let key1 = s.our_ratchet.clone();

                    let reencrypted = s.try_encrypt(&our_id, b"hello again, world").unwrap();

                    Fixture2 {
                        session: Rc::new(s),
                        reencrypted: Rc::new(reencrypted),
                        key: key1,
                    }
                })
                .clone()
        }

        #[test]
        fn test_key_changes() {
            assert_ne!(fixie2().key, fixie2().session.our_ratchet);
        }

        #[test]
        fn test_next_message_bumps_id() {
            assert_eq!(fixie2().reencrypted.seq_id, 2);
        }

        #[test]
        fn test_our_se_id_updates_after_next_message() {
            assert_eq!(fixie2().session.our_seq_id, 2);
        }

        #[test]
        fn test_their_seq_id_is_unchanged_after_next_message() {
            assert_eq!(fixie2().session.their_seq_id, 0);
        }
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

        let reencrypted = s1.try_encrypt(&alice_id, b"hello again, world").unwrap();
        let redecrypted = s2.try_decrypt(&alice_id, reencrypted).unwrap();

        assert_eq!(redecrypted, b"hello again, world");
    }
}
