use super::{
    connect::Connect, encrypted::Encrypted, hash::Hash, hello::Hello, message::Message,
    secret::Secret, seed::Seed, signed::Signed,
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use thiserror::Error;

pub struct Server {
    my_id: String,
    secret_swarm_seed: Seed,
}

impl Server {
    pub fn new(my_id: String, secret_swarm_seed: Seed) -> Self {
        Self {
            my_id,
            secret_swarm_seed,
        }
    }

    pub fn receive_hello<R: rand::RngCore + rand::CryptoRng>(
        &self,
        hello: Signed<Hello>,
        csprng: &mut R,
    ) -> Result<Connect, ReceiveHelloError> {
        if hello.payload.server_id_hash != Hash::hash(&self.my_id) {
            return Err(ReceiveHelloError::InvalidServerId);
        }

        let sk = x25519_dalek::EphemeralSecret::random_from_rng(csprng);
        let pk = x25519_dalek::PublicKey::from(&sk);

        let shared_secret = sk.diffie_hellman(&hello.payload.client_pk);

        let mut secret: Vec<u8> = shared_secret.as_bytes().to_vec();
        secret.extend_from_slice(hello.verifier.as_bytes());
        let secret = secret.as_slice();

        let mut nonce_buf = [0u8; 24];
        let mut key_preimage_buf = [0u8; 32];

        let mut hasher = blake3::Hasher::new_keyed(shared_secret.as_bytes())
            .update(b"/beelay/handshake/preimages/")
            .update(secret)
            .finalize_xof();

        hasher.fill(&mut nonce_buf);
        hasher.fill(&mut key_preimage_buf);

        let mut secret_preimage = self.secret_swarm_seed.0.to_vec();
        secret_preimage.extend_from_slice(hello.payload.client_pk.as_bytes());
        let secret: Secret =
            blake3::derive_key(&"/beelay/handshake/secret/", &secret_preimage).into();

        let key = XChaCha20Poly1305::new_from_slice(&key_preimage_buf)
            .expect("we're passing it exactly 32 bytes");

        let encrypted_secret = Encrypted::encrypt(
            secret,
            key,
            XNonce::from_slice(&nonce_buf),
            hello.payload.server_id_hash.raw.as_bytes(),
        )
        .map_err(ReceiveHelloError::EncryptionError)?;

        Ok(Connect {
            client_vk: hello.verifier,
            server_pk: pk,
            encrypted_secret,
        })
    }

    pub fn receive_message(&self, message: Message) -> Result<Vec<u8>, String> {
        let mut buf = b"/beelay/message/".to_vec();
        buf.extend_from_slice(message.content.as_slice());

        let mut preimage = self.secret_swarm_seed.0.to_vec();
        preimage.extend_from_slice(message.sender.as_bytes());

        let mac_key: [u8; 32] = blake3::derive_key(&"/beelay/handshake/secret/", &preimage);
        let mac = blake3::keyed_hash(&mac_key, &buf);

        if *mac.as_bytes() != message.mac.0 {
            return Err("Invalid MAC".to_string());
        }

        Ok(message.content)
    }
}

#[derive(Debug, Clone, Error)]
pub enum ReceiveHelloError {
    #[error("Invalid server ID")]
    InvalidServerId,

    #[error("Encryption error: {0}")]
    EncryptionError(chacha20poly1305::Error),
}
