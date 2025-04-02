//! Newtype around [ECDH] "sharing" public keys.
//!
//! [ECDH]: https://wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

use super::{
    digest::Digest, encrypted::EncryptedSecret, separable::Separable, symmetric_key::SymmetricKey,
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::{self, Debug},
    future::Future,
    num::NonZero,
    rc::Rc,
};
use tracing::instrument;

/// Newtype around [x25519_dalek::PublicKey].
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareKey(x25519_dalek::PublicKey);

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for ShareKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).unwrap();
        Ok(Self(x25519_dalek::PublicKey::from(arr)))
    }
}

impl ShareKey {
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self(x25519_dalek::PublicKey::from(
            &x25519_dalek::EphemeralSecret::random_from_rng(csprng),
        ))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Dupe for ShareKey {
    fn dupe(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::LowerHex for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::util::hex::bytes_as_hex(self.0.as_bytes().iter(), f)
    }
}

impl fmt::Display for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl PartialOrd for ShareKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ShareKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl From<ShareKey> for x25519_dalek::PublicKey {
    fn from(key: ShareKey) -> Self {
        key.0
    }
}

impl From<x25519_dalek::PublicKey> for ShareKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        ShareKey(key)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct ShareSecretKey([u8; 32]);

impl ShareSecretKey {
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        x25519_dalek::StaticSecret::random_from_rng(csprng).into()
    }

    pub fn share_key(&self) -> ShareKey {
        ShareKey(x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(*self),
        ))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn force_from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<ShareSecretKey> for ShareKey {
    fn from(secret: ShareSecretKey) -> Self {
        secret.share_key()
    }
}

impl<T: Into<ShareKey>> From<Rc<T>> for ShareKey {
    fn from(secret: Rc<T>) -> Self {
        secret.into()
    }
}

impl From<ShareSecretKey> for x25519_dalek::StaticSecret {
    fn from(secret: ShareSecretKey) -> Self {
        x25519_dalek::StaticSecret::from(secret.0)
    }
}

impl From<x25519_dalek::StaticSecret> for ShareSecretKey {
    fn from(secret: x25519_dalek::StaticSecret) -> Self {
        Self(secret.to_bytes())
    }
}

impl From<&ShareSecretKey> for Vec<u8> {
    fn from(secret: &ShareSecretKey) -> Self {
        secret.0.to_vec()
    }
}

impl Separable for ShareSecretKey {
    fn directly_from_32_bytes(bytes: [u8; 32]) -> Self {
        ShareSecretKey(bytes)
    }
}

impl fmt::LowerHex for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::util::hex::bytes_as_hex(self.0.iter(), f)
    }
}

impl fmt::Display for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareSecretKey(SECRET)")
    }
}

pub trait AsyncSecretKey {
    type EcdhError: Debug;

    fn to_share_key(&self) -> ShareKey;

    async fn ecdh_derive_shared_secret(
        &self,
        counterparty: ShareKey,
    ) -> Result<x25519_dalek::SharedSecret, Self::EcdhError>;

    // FIXME derive against public key of initial signer... or something
    async fn derive_bytes(&self, counterparty: ShareKey) -> Result<[u8; 32], Self::EcdhError> {
        let secret = self
            .ecdh_derive_shared_secret(counterparty)
            .await?
            .to_bytes();

        let extended = secret.to_vec().extend(b"/keyhive/ecdh/derive-bytes/");
        Ok(Digest::hash(&extended).into())
    }

    #[instrument(skip(self), fields(pk = %self.to_share_key()))]
    async fn derive_symmetric_key(&self, other: ShareKey) -> Result<SymmetricKey, Self::EcdhError> {
        let secret = self.derive_bytes(other).await?;
        Ok(SymmetricKey::from(secret))
    }

    #[instrument(skip(self), fields(pk = %self.to_share_key()))]
    async fn ratchet_forward(&self, other: ShareKey) -> Result<ShareSecretKey, Self::EcdhError> {
        let bytes = self.derive_bytes(other).await?;
        Ok(ShareSecretKey::force_from_bytes(bytes))
    }

    #[instrument(skip(self), fields(pk = %self.to_share_key()))]
    async fn ratchet_n_forward(
        &self,
        other: ShareKey,
        n: NonZero<usize>,
    ) -> Result<ShareSecretKey, Self::EcdhError> {
        let mut acc = self.derive_bytes(other).await?;
        let max = n.get() - 1;
        for _ in 0..max {
            let acc_sk = ShareSecretKey::force_from_bytes(acc);
            let acc_pk = acc_sk.share_key();
            acc = self.derive_bytes(acc_pk).await?;
        }
        Ok(ShareSecretKey::force_from_bytes(acc))
    }
}

impl AsyncSecretKey for ShareSecretKey {
    type EcdhError = Infallible;

    fn to_share_key(&self) -> ShareKey {
        self.share_key()
    }

    async fn ecdh_derive_shared_secret(
        &self,
        counterparty: ShareKey,
    ) -> Result<x25519_dalek::SharedSecret, Self::EcdhError> {
        Ok(x25519_dalek::StaticSecret::from(*self).diffie_hellman(&counterparty.0))
    }
}

impl<T: AsyncSecretKey> AsyncSecretKey for Rc<T> {
    type EcdhError = T::EcdhError;

    fn to_share_key(&self) -> ShareKey {
        self.as_ref().to_share_key()
    }

    async fn ecdh_derive_shared_secret(
        &self,
        counterparty: ShareKey,
    ) -> Result<x25519_dalek::SharedSecret, Self::EcdhError> {
        self.as_ref().ecdh_derive_shared_secret(counterparty).await
    }
}

pub trait ShareSecretStore {
    type SecretKey: AsyncSecretKey;

    type GetSecretError: Debug;
    type GetIndexError: Debug;
    type ImportKeyError: Debug;
    type GenerateSecretError: Debug;

    async fn get_index(&self) -> Result<HashMap<ShareKey, Self::SecretKey>, Self::GetIndexError>;

    fn get_secret_key(
        &self,
        public_key: &ShareKey,
    ) -> impl Future<Output = Result<Option<Self::SecretKey>, Self::GetSecretError>>;

    fn import_secret_key(
        &mut self,
        secret_key: ShareSecretKey,
    ) -> impl Future<Output = Result<Self::SecretKey, Self::ImportKeyError>>;

    async fn import_secret_key_directly(
        &mut self,
        secret_key: Self::SecretKey,
    ) -> Result<Self::SecretKey, Self::ImportKeyError>;

    fn generate_share_secret_key<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> impl Future<Output = Result<Self::SecretKey, Self::GenerateSecretError>>;

    async fn try_decrypt_encryption(
        &self,
        encrypter_pk: ShareKey,
        encrypted: &EncryptedSecret<ShareSecretKey>,
    ) -> Result<Vec<u8>, ()> {
        let sk = self
            .get_secret_key(&encrypted.paired_pk)
            .await
            .expect("FIXME")
            .expect("FIXME");
        let key = sk.derive_symmetric_key(encrypter_pk).await.expect("FIXME");
        let mut buf = encrypted.ciphertext.clone();
        key.try_decrypt(encrypted.nonce, &mut buf).expect("FIXME");
        Ok(buf)
    }
}

impl ShareSecretStore for HashMap<ShareKey, Rc<ShareSecretKey>> {
    type SecretKey = Rc<ShareSecretKey>;

    type GetSecretError = Infallible;
    type GetIndexError = Infallible;
    type ImportKeyError = Infallible;
    type GenerateSecretError = Infallible;

    async fn get_index(&self) -> Result<HashMap<ShareKey, Self::SecretKey>, Self::GetIndexError> {
        Ok(self.clone())
    }

    async fn get_secret_key(
        &self,
        public_key: &ShareKey,
    ) -> Result<Option<Self::SecretKey>, Self::GetSecretError> {
        Ok(self.get(public_key).cloned())
    }

    async fn import_secret_key(
        &mut self,
        secret_key: ShareSecretKey,
    ) -> Result<Self::SecretKey, Self::ImportKeyError> {
        let rc = Rc::new(secret_key);
        self.insert(secret_key.share_key(), rc.dupe());
        Ok(rc)
    }

    async fn import_secret_key_directly(
        &mut self,
        secret_key: Self::SecretKey,
    ) -> Result<Self::SecretKey, Self::ImportKeyError> {
        self.insert(secret_key.to_share_key(), secret_key.dupe());
        Ok(secret_key)
    }

    async fn generate_share_secret_key<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Self::SecretKey, Self::GenerateSecretError> {
        let sk = Rc::new(ShareSecretKey::generate(csprng));
        let pk = sk.share_key();
        self.insert(pk, sk.dupe());
        Ok(sk)
    }
}
