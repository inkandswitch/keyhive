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
        let tag = key.encrypt_in_place_detached(nonce, associated_data, &mut buf)?;

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
        key.decrypt_in_place_detached(nonce, associated_data, &mut buf, &self.tag)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{AeadCore, KeyInit};

    #[test]
    fn test_round_trip() {
        let key_bytes = XChaCha20Poly1305::generate_key(&mut rand::thread_rng());
        let key = XChaCha20Poly1305::new(&key_bytes);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());

        #[derive(Debug, Clone, PartialEq, Eq)]
        struct MyString(String);

        impl From<MyString> for Vec<u8> {
            fn from(value: MyString) -> Vec<u8> {
                value.0.into_bytes()
            }
        }

        impl TryFrom<Vec<u8>> for MyString {
            type Error = std::convert::Infallible;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Ok(MyString(String::from_utf8(value).unwrap()))
            }
        }

        let msg = MyString("hello world".to_string());

        let encrypted =
            Encrypted::encrypt(msg.clone(), key.clone(), &nonce, b"some associated data").unwrap();

        let decrypted = encrypted
            .decrypt(key, &nonce, b"some associated data")
            .unwrap();

        assert_eq!(decrypted, msg);
    }
}
