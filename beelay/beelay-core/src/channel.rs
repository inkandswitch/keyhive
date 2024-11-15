use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret};

/// Pairwise channel
pub struct Channel {
    pub secret: SharedSecret,

    pub our_ratchet: [u8; 32],
    pub our_last_hash: Option<blake3::Hash>,

    pub their_ratchet: [u8; 32],
    pub their_last_hash: Option<blake3::Hash>,

    /// Messages that we can't decrypt yet
    /// {hash waiting on => message}
    pub message_buffer: HashMap<blake3::Hash, Signed<Vec<u8>>>,
}

impl Channel {
    pub fn new(channel_secret: SharedSecret, us: VerifyingKey, them: VerifyingKey) -> Self {
        Self {
            secret: channel_secret,
            our_ratchet: us.to_bytes(),
            their_ratchet: them.to_bytes(),
            their_last_hash: None,
            message_buffer: HashMap::new(),
        }
    }

    pub fn try_encrypt(&mut self, msg: &[u8]) -> Result<Encrypted, ()> {
        let mut new_secret = [0; 32];
        let mut key_preimage = [0; 32];
        let mut nonce_bytes = [0; 24];

        let mut hasher = blake3::Hasher::new_keyed(&self.our_ratchet);
        hasher.update(b"/beelay/channel/ratchet/");

        let mut source = hasher.finalize_xof();
        source.fill(&mut new_secret);
        source.fill(&mut key_preimage);
        source.fill(&mut nonce_bytes);

        let key_bytes = blake3::derive_key(&"/beelay/channel/kdf/", &key_preimage);
        let key = XChaCha20Poly1305::new_from_slice(key_bytes.as_slice()).unwrap(); // Only fails if not 32 bytes
        let nonce = XNonce::from_mut_slice(&mut nonce_bytes);

        let mut ciphertext = msg.to_vec();
        let mac = key
            .encrypt_in_place_detached(&nonce, &[], &mut ciphertext) // FIXME use VK for assoc data?
            .map_err(|_| ())?;

        self.our_ratchet = new_secret;

        let encrypted = Encrypted {
            ciphertext,
            mac,
            pred: self.our_last_hash,
        };

        self.our_last_hash = Some(blake3::hash(msg));

        Ok(encrypted)
    }

    pub fn try_decrypt(&mut self, msg: &Encrypted) -> Result<(), ()> {
        todo!()
    }
}

pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub mac: Tag,
    pub pred: Option<blake3::Hash>,
}

pub struct Channels {
    pub channels: HashMap<VerifyingKey, Channel>,
}

#[derive(Debug, Clone)]
pub struct Knock {
    pub session_public_key: PublicKey,
}

impl From<Knock> for Vec<u8> {
    fn from(knock: Knock) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(knock.session_public_key.as_bytes());
        v
    }
}

pub struct Signed<T: Clone>
where
    Vec<u8>: From<T>,
{
    pub payload: T,
    pub verifier: VerifyingKey,
    pub signature: Signature,
}

impl<T: Clone> Signed<T>
where
    Vec<u8>: From<T>,
{
    pub fn verify(&self) -> Result<(), signature::Error> {
        let msg = Vec::<u8>::from(self.payload.clone());
        self.verifier.verify(msg.as_slice(), &self.signature)
    }
}

pub struct State {
    pub public_key: PublicKey,
    pub ephemeral_secret_key: ReusableSecret,
    pub signer: SigningKey,
}

impl State {
    pub fn new<R: rand::CryptoRng + rand::RngCore + Clone>(csprng: &mut R) -> Self {
        let ephemeral_secret_key = ReusableSecret::random_from_rng(csprng.clone());

        Self {
            public_key: PublicKey::from(&ephemeral_secret_key),
            signer: SigningKey::generate(csprng),
            ephemeral_secret_key,
        }
    }

    pub fn handshake<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        them: &Signed<Knock>,
        csprng: &mut R,
    ) -> Result<(VerifyingKey, SharedSecret), ()> {
        them.verify().map_err(|_| ())?;

        let sk = self.refresh_ephemeral(csprng);
        let shared_secret: SharedSecret = sk.diffie_hellman(&them.payload.session_public_key);

        Ok((them.verifier, shared_secret))
    }

    pub fn refresh_ephemeral<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> ReusableSecret {
        let eph_sec = self.ephemeral_secret_key.clone();
        self.ephemeral_secret_key = ReusableSecret::random_from_rng(csprng);
        eph_sec
    }
}
