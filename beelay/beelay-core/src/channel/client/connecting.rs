use super::{
    super::{
        connect::Connect, encrypted::DecryptionError, hash::Hash, hello::Hello, signed::Signed,
    },
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
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
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

    pub fn hello(
        &self,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Signed<Hello>, signature::Error> {
        Signed::try_sign(
            Hello {
                client_pk: (&self.my_secret_key).into(),
                server_id_hash: self.server_id_hash(),
            },
            &signing_key,
        )
    }

    // NOTE: Intentionally destroyed if fails
    pub fn receive_connect(self, connect: Connect) -> Result<Connected, ReceiveConnectError> {
        if connect.client_vk != self.my_verifying_key {
            return Err(ReceiveConnectError::InvalidReceiver);
        }

        let server_id_hash = self.server_id_hash();
        let shared_secret = self.my_secret_key.diffie_hellman(&connect.server_pk);

        let mut nonce_buf = [0u8; 24];
        let mut key_preimage_buf = [0u8; 32];

        let mut hasher = blake3::Hasher::new_keyed(shared_secret.as_bytes())
            .update(b"/beelay/handshake/preimages/")
            .update(server_id_hash.raw.as_bytes())
            .update(self.my_verifying_key.as_bytes())
            .finalize_xof();

        hasher.fill(&mut nonce_buf);
        hasher.fill(&mut key_preimage_buf);

        let key =
            XChaCha20Poly1305::new_from_slice(&key_preimage_buf).expect("take exactly 32 bytes");

        let secret = connect.encrypted_secret.decrypt(
            key,
            XNonce::from_slice(&nonce_buf),
            server_id_hash.raw.as_bytes(),
        )?;

        Ok(Connected {
            secret,
            sender: self.my_verifying_key,
        })
    }

    fn server_id_hash(&self) -> Hash<String> {
        Hash::from(&self.server_id)
    }
}

#[derive(Debug, Error)]
pub enum ReceiveConnectError {
    #[error("Invalid receiver")]
    InvalidReceiver,

    #[error(transparent)]
    DecryptionError(#[from] DecryptionError),
}
