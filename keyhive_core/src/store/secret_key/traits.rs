use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    future::Future,
};

use crate::crypto::{
    encrypted::EncryptedSecret,
    share_key::{AsyncSecretKey, ShareKey, ShareSecretKey},
};

pub trait ShareSecretStore: Clone {
    type SecretKey: AsyncSecretKey + Debug + Clone;

    type GetSecretError: Debug + Display;
    type GetIndexError: Debug + Display;
    type ImportKeyError: Debug + Display;
    type GenerateSecretError: Debug + Display;

    fn get_index(
        &self,
    ) -> impl Future<Output = Result<HashMap<ShareKey, Self::SecretKey>, Self::GetIndexError>>;

    fn get_secret_key(
        &self,
        public_key: &ShareKey,
    ) -> impl Future<Output = Result<Option<Self::SecretKey>, Self::GetSecretError>>;

    fn import_secret_key(
        &mut self,
        secret_key: ShareSecretKey,
    ) -> impl Future<Output = Result<Self::SecretKey, Self::ImportKeyError>>;

    fn import_secret_key_directly(
        &mut self,
        secret_key: Self::SecretKey,
    ) -> impl Future<Output = Result<Self::SecretKey, Self::ImportKeyError>>;

    fn generate_share_secret_key(
        &mut self,
    ) -> impl Future<Output = Result<Self::SecretKey, Self::GenerateSecretError>>;

    fn try_decrypt_encryption(
        &self,
        encrypter_pk: ShareKey,
        encrypted: &EncryptedSecret<ShareSecretKey>,
    ) -> impl Future<Output = Result<Vec<u8>, ()>> {
        async move {
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
}
