//! Symmetric cipher newtype.

use super::{domain_separator::SEPARATOR, separable::Separable, siv::Siv};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use x25519_dalek::SharedSecret;

/// Newtype wrapper around ChaCha20 key that's serializable.
///
/// # Example
///
/// ```
/// # use keyhive_core::{
/// #     crypto::{siv::Siv, symmetric_key::SymmetricKey, signer::memory::MemorySigner},
/// #     listener::no_listener::NoListener,
/// #     principal::{agent::Agent, document::Document, individual::Individual},
/// #     store::{delegation::DelegationStore, revocation::RevocationStore}
/// # };
/// # use std::sync::Arc;
/// # use futures::lock::Mutex;
/// # use nonempty::nonempty;
/// #
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() {
///     let mut plaintext = b"hello world";
///
///     let mut csprng = rand::rngs::OsRng;
///
///     let sk = MemorySigner::generate(&mut csprng);
///     let user = Individual::generate(&sk, &mut csprng).await.unwrap();
///     let user_agent: Agent<MemorySigner, String> = Agent::Individual(user.id(), Arc::new(Mutex::new(user)));
///
///     let delegation_store = DelegationStore::new();
///     let revocation_store = RevocationStore::new();
///     let doc = Document::generate(
///         nonempty![user_agent],
///         nonempty!["commit-1".to_string()],
///         delegation_store,
///         revocation_store,
///         NoListener,
///         &sk,
///         Arc::new(Mutex::new(csprng)),
///     ).await.unwrap();
///
///     let key = SymmetricKey::generate(&mut csprng);
///     let nonce = Siv::new(&key, plaintext, doc.doc_id()).unwrap();
///
///     let mut roundtrip_buf = plaintext.to_vec();
///     key.try_encrypt(nonce, &mut roundtrip_buf).unwrap();
///     key.try_decrypt(nonce, &mut roundtrip_buf).unwrap();
///
///     assert_eq!(roundtrip_buf.as_slice(), plaintext);
/// }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    /// Get the key as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Generate a new random symmetric key.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let mut key = [0u8; 32];
        csprng.fill_bytes(&mut key);
        Self(key)
    }

    /// Convert into an [`XChaCha20Poly1305`] key.
    pub fn to_xchacha(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }

    /// Encrypt data with the [`SymmetricKey`].
    #[instrument(skip(self))]
    pub fn try_encrypt(
        &self,
        nonce: Siv,
        data: &mut Vec<u8>,
    ) -> Result<(), chacha20poly1305::Error> {
        self.to_xchacha()
            .encrypt_in_place(nonce.as_xnonce(), SEPARATOR, data)
    }

    /// Decrypt data with the [`SymmetricKey`].
    #[instrument(skip(self))]
    pub fn try_decrypt(
        &self,
        nonce: Siv,
        data: &mut Vec<u8>,
    ) -> Result<(), chacha20poly1305::Error> {
        self.to_xchacha()
            .decrypt_in_place(nonce.as_xnonce(), SEPARATOR, data)
    }
}

impl From<[u8; 32]> for SymmetricKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<SymmetricKey> for [u8; 32] {
    fn from(key: SymmetricKey) -> Self {
        key.0
    }
}

impl From<SymmetricKey> for XChaCha20Poly1305 {
    fn from(key: SymmetricKey) -> Self {
        key.to_xchacha()
    }
}

impl From<SharedSecret> for SymmetricKey {
    fn from(secret: SharedSecret) -> Self {
        (*secret.as_bytes()).into()
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        "<SymmetricKey>".fmt(f)
    }
}

impl Separable for SymmetricKey {
    fn directly_from_32_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
