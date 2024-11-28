use super::{
    super::{connect::Connect, encrypted::DecryptionError, hash::Hash, hello::Hello},
    connected::Connected,
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use thiserror::Error;

pub struct Connecting {
    my_secret_key: x25519_dalek::EphemeralSecret,
    my_verifying_key: ed25519_dalek::VerifyingKey,
    server_id: String,
}

impl Connecting {
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        csprng: &mut R,
        my_verifying_key: ed25519_dalek::VerifyingKey,
        server_id: String,
    ) -> Self {
        Self {
            my_secret_key: x25519_dalek::EphemeralSecret::random_from_rng(csprng),
            my_verifying_key,
            server_id,
        }
    }

    pub fn hello(&self) -> Hello {
        let server_id_hash = Hash::hash(&self.server_id);

        Hello {
            client_pk: (&self.my_secret_key).into(),
            server_id_hash,
        }
    }

    // NOTE: Intentionally destroyed if fails
    pub fn receive_connect(self, connect: Connect) -> Result<Connected, ReceiveConnectError> {
        if connect.client_vk != self.my_verifying_key {
            return Err(ReceiveConnectError::InvalidReceiver);
        }

        let shared_secret = self.my_secret_key.diffie_hellman(&connect.server_pk);

        let mut secret: Vec<u8> = shared_secret.as_bytes().to_vec();
        secret.extend_from_slice(self.server_id.as_bytes());
        secret.extend_from_slice(self.my_verifying_key.as_bytes());
        let secret = secret.as_slice();

        let mut nonce_buf = [0u8; 24];
        let mut key_preimage_buf = [0u8; 32];
        let mut hasher = blake3::Hasher::new_keyed(shared_secret.as_bytes())
            .update(b"/beelay/handshake/preimages/")
            .update(secret)
            .finalize_xof();
        hasher.fill(&mut nonce_buf);
        hasher.fill(&mut key_preimage_buf);

        let key =
            XChaCha20Poly1305::new_from_slice(&key_preimage_buf).expect("take exactly 32 bytes");

        let secret = connect.encrypted_secret.decrypt(
            key,
            XNonce::from_slice(&nonce_buf),
            Hash::hash(&self.server_id).raw.as_bytes(),
        )?;

        Ok(Connected {
            secret,
            sender: self.my_verifying_key,
        })
    }
}

#[derive(Debug, Error)]
pub enum ReceiveConnectError {
    #[error("Invalid receiver")]
    InvalidReceiver,

    #[error(transparent)]
    DecryptionError(#[from] DecryptionError),
}
