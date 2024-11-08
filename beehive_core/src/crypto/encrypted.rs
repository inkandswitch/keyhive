//! Ciphertext with public metadata.

use super::{
    share_key::{ShareKey, ShareSecretKey},
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use crate::principal::document::id::DocumentId;
use nonempty::NonEmpty;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use std::marker::PhantomData;

/// The public information for a ciphertext.
///
/// This wraps a ciphertext that includes the [`Siv`] and the type of the data
/// that was encrypted (or that the plaintext is _expected_ to be).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Encrypted<T> {
    /// The nonce used to encrypt the data.
    pub nonce: Siv,

    /// The encrypted data.
    pub ciphertext: Vec<u8>,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T> Encrypted<T> {
    /// Associate a nonce with a ciphertext and assert the plaintext type.
    pub fn new(nonce: Siv, ciphertext: Vec<u8>) -> Encrypted<T> {
        Encrypted {
            nonce,
            ciphertext,
            _plaintext_tag: PhantomData,
        }
    }
}

// FIXME consider Vec<(Pk, Nonce, Ciphertext)> instead due to fewer possible errors
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NestedEncrypted<T> {
    /// The nonce used to encrypt the data and
    /// the public keys the encrypter used as DH partners when doing the
    /// nested encryption.
    pub layers: NonEmpty<(ShareKey, Siv)>,

    /// The outermost layer (most encrypted) of the nested encrypted data.
    pub ciphertext: Vec<u8>,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T> NestedEncrypted<T> {
    /// Associate a nonce with a ciphertext and assert the plaintext type.
    pub fn new(layers: NonEmpty<(ShareKey, Siv)>, ciphertext: Vec<u8>) -> Self {
        Self {
            layers,
            ciphertext,
            _plaintext_tag: PhantomData,
        }
    }

    pub fn try_encrypt<U>(
        doc_id: DocumentId,
        secret: U,
        encrypt_keys: &NonEmpty<(ShareKey, ShareSecretKey)>,
    ) -> Result<Self, chacha20poly1305::Error>
    where
        Vec<u8>: From<U>,
    {
        let mut ciphertext: Vec<u8> = secret.into();
        let mut layer_vec: Vec<(ShareKey, Siv)> = vec![];

        for (pk, sk) in encrypt_keys.iter() {
            // FIXME lift the errors into one type
            let nonce =
                Siv::new(&SymmetricKey::from(sk.to_bytes()), &ciphertext, doc_id).expect("FIXME");

            layer_vec.push((*pk, nonce.clone()));

            sk.derive_symmetric_key(&pk)
                .try_encrypt(nonce, &mut ciphertext)?
        }

        Ok(NestedEncrypted {
            layers: NonEmpty::from_vec(layer_vec)
                .expect("must be nonempty since we iterated over a nonempty argument"),
            ciphertext,
            _plaintext_tag: PhantomData,
        })
    }

    // TODO validate nonce & AEAD
    pub fn try_decrypt(
        &self,
        decrypt_keys: &[ShareSecretKey],
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        for (idx, (pk, nonce)) in self.layers.iter().enumerate().rev() {
            let sk = &decrypt_keys[idx];
            let key = sk.derive_symmetric_key(pk);
            key.try_decrypt(*nonce, &mut buf)?;
        }
        Ok(buf)
    }
}

impl<T: Serialize> Serialize for NestedEncrypted<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut ser = serializer.serialize_struct("NestedEncrypted", 3)?;
        ser.serialize_field("layers", &Vec::<_>::from(self.layers.clone()))?;
        ser.serialize_field("ciphertext", &self.ciphertext)?;
        ser.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NestedEncrypted<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct NestedEncryptedHelper {
            layers: Vec<(ShareKey, Siv)>,
            ciphertext: Vec<u8>,
        }

        let helper = NestedEncryptedHelper::deserialize(deserializer)?;
        Ok(NestedEncrypted::new(
            NonEmpty::from_slice(&helper.layers).ok_or_else(|| {
                serde::de::Error::custom("nested encrypted data must have at least one layer")
            })?,
            helper.ciphertext,
        ))
    }
}
