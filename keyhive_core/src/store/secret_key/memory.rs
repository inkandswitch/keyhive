use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    hash::Hash,
    rc::Rc,
};

use dupe::Dupe;

use crate::crypto::share_key::{AsyncSecretKey, ShareKey, ShareSecretKey};

use super::traits::ShareSecretStore;

#[derive(Debug, Clone, Default)]
pub struct MemorySecretKeyStore<R: rand::CryptoRng + rand::RngCore + Clone> {
    pub csprng: R,
    pub keys: HashMap<ShareKey, Rc<ShareSecretKey>>,
}

impl<R: rand::CryptoRng + rand::RngCore + Clone> MemorySecretKeyStore<R> {
    pub fn new(csprng: R) -> Self {
        Self {
            csprng,
            keys: HashMap::new(),
        }
    }
}

impl<R: rand::CryptoRng + rand::RngCore + Clone> PartialEq for MemorySecretKeyStore<R> {
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys
    }
}

impl<R: rand::CryptoRng + rand::RngCore + Clone> Hash for MemorySecretKeyStore<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.keys.keys().collect::<BTreeSet<_>>().hash(state);
    }
}

impl<R: rand::CryptoRng + rand::RngCore + Clone> Eq for MemorySecretKeyStore<R> {}

impl<R: rand::CryptoRng + rand::RngCore + Clone> ShareSecretStore for MemorySecretKeyStore<R> {
    type SecretKey = Rc<ShareSecretKey>;

    type GetSecretError = Infallible;
    type GetIndexError = Infallible;
    type ImportKeyError = Infallible;
    type GenerateSecretError = Infallible;

    async fn get_index(&self) -> Result<HashMap<ShareKey, Self::SecretKey>, Self::GetIndexError> {
        Ok(self.keys.clone())
    }

    async fn get_secret_key(
        &self,
        public_key: &ShareKey,
    ) -> Result<Option<Self::SecretKey>, Self::GetSecretError> {
        Ok(self.keys.get(public_key).cloned())
    }

    async fn import_secret_key(
        &mut self,
        secret_key: ShareSecretKey,
    ) -> Result<Self::SecretKey, Self::ImportKeyError> {
        let rc = Rc::new(secret_key);
        self.keys.insert(secret_key.share_key(), rc.dupe());
        Ok(rc)
    }

    async fn import_secret_key_directly(
        &mut self,
        secret_key: Self::SecretKey,
    ) -> Result<Self::SecretKey, Self::ImportKeyError> {
        self.keys
            .insert(secret_key.to_share_key(), secret_key.dupe());
        Ok(secret_key)
    }

    async fn generate_share_secret_key(
        &mut self,
    ) -> Result<Self::SecretKey, Self::GenerateSecretError> {
        let sk = Rc::new(ShareSecretKey::generate(&mut self.csprng));
        let pk = sk.share_key();
        self.keys.insert(pk, sk.dupe());
        Ok(sk)
    }
}
