use chacha20poly1305::{aead::AeadInPlace, Tag, XChaCha20Poly1305, XNonce};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Encrypted<T> {
    pub ciphertext: Vec<u8>,
    pub tag: Tag,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Encrypted<T> {
    pub fn encrypt(
        value: T,
        key: XChaCha20Poly1305,
        nonce: &XNonce,
        associated_data: &[u8],
    ) -> Result<Self, chacha20poly1305::Error>
    where
        Vec<u8>: From<T>,
    {
        let mut buf: Vec<u8> = value.into();
        let tag = key.encrypt_in_place_detached(&nonce, associated_data, &mut buf)?;

        Ok(Encrypted {
            ciphertext: buf,
            tag,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn decrypt(
        self,
        key: XChaCha20Poly1305,
        nonce: &XNonce,
        associated_data: &[u8],
    ) -> Result<T, DecryptionError>
    where
        T: TryFrom<Vec<u8>>,
    {
        let mut buf = self.ciphertext;
        key.decrypt_in_place_detached(&nonce, associated_data, &mut buf, &self.tag)
            .map_err(DecryptionError::CryptoError)?;

        let value: T = buf
            .try_into()
            .map_err(|_| DecryptionError::CannotDeserialize)?;

        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error)]
pub enum DecryptionError {
    #[error("Cannot deserialize the decrypted value")]
    CannotDeserialize,

    #[error("Crypto error: {0}")]
    CryptoError(chacha20poly1305::Error),
}
