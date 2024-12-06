//! Ciphertext with public metadata.

use super::{
    application_secret::PcsKey,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use crate::{cgka::operation::CgkaOperation, content::reference::ContentRef, principal::document::id::DocumentId};
use nonempty::NonEmpty;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use std::marker::PhantomData;

/// The public information for a ciphertext.
///
/// This wraps a ciphertext that includes the [`Siv`] and the type of the data
/// that was encrypted (or that the plaintext is _expected_ to be).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Encrypted<T, Cr: ContentRef> {
    /// The nonce used to encrypt the data.
    pub nonce: Siv,

    /// The encrypted data.
    pub ciphertext: Vec<u8>,

    /// Hash of the PCS key used to derive the application secret for encrypting.
    pub pcs_key_hash: Digest<PcsKey>,
    /// Hash of the PCS update operation corresponding to the PCS key
    pub pcs_update_op_hash: Digest<CgkaOperation>,
    /// The content ref hash used to derive the application secret for encrypting.
    pub content_ref: Digest<Cr>,
    /// The predecessor content ref hashes used to derive the application secret
    /// for encrypting.
    pub pred_refs: Digest<Vec<Cr>>,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T, Cr: ContentRef> Encrypted<T, Cr> {
    /// Associate a nonce with a ciphertext and assert the plaintext type.
    pub fn new(
        nonce: Siv,
        ciphertext: Vec<u8>,
        pcs_key_hash: Digest<PcsKey>,
        pcs_update_op_hash: Digest<CgkaOperation>,
        content_ref: Digest<Cr>,
        pred_refs: Digest<Vec<Cr>>,
    ) -> Encrypted<T, Cr> {
        Encrypted {
            nonce,
            ciphertext,
            pcs_key_hash,
            pcs_update_op_hash,
            content_ref,
            pred_refs,
            _plaintext_tag: PhantomData,
        }
    }
}

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
        encrypter_sk: &ShareSecretKey,
        paired_share_keys: &NonEmpty<ShareKey>,
    ) -> Result<Self, chacha20poly1305::Error>
    where
        Vec<u8>: From<U>,
    {
        let mut ciphertext: Vec<u8> = secret.into();
        let mut layer_vec: Vec<(ShareKey, Siv)> = vec![];

        for pk in paired_share_keys.iter() {
            let key = encrypter_sk.derive_symmetric_key(pk);
            let nonce = Siv::new(&key, &ciphertext, doc_id).expect("FIXME");
            layer_vec.push((*pk, nonce));
            // FIXME lift the errors into one type
            key.try_encrypt(nonce, &mut ciphertext)?
        }

        Ok(NestedEncrypted {
            layers: NonEmpty::from_vec(layer_vec)
                .expect("must be nonempty since we iterated over a nonempty argument"),
            ciphertext,
            _plaintext_tag: PhantomData,
        })
    }

    // TODO validate nonce & AEAD
    pub fn try_encrypter_decrypt(
        &self,
        encrypter_secret_key: &ShareSecretKey,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        for (pk, nonce) in self.layers.iter().rev() {
            let key = encrypter_secret_key.derive_symmetric_key(pk);
            key.try_decrypt(*nonce, &mut buf)?;
        }
        Ok(buf)
    }

    // TODO validate nonce & AEAD
    pub fn try_sibling_decrypt(
        &self,
        decrypt_keys: &[SymmetricKey],
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        for (idx, (_pk, nonce)) in self.layers.iter().enumerate().rev() {
            let key = &decrypt_keys[idx];
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

#[cfg(test)]
mod tests {
    use nonempty::nonempty;

    use super::super::share_key::ShareSecretKey;
    use super::NestedEncrypted;
    use crate::crypto::symmetric_key::SymmetricKey;
    use crate::principal::document::id::DocumentId;
    use crate::principal::identifier::Identifier;

    #[test]
    pub(crate) fn test_encrypt_and_decrypt() -> Result<(), chacha20poly1305::Error> {
        let csprng = &mut rand::thread_rng();
        let secret = ShareSecretKey::generate(csprng);
        let id = Identifier(
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key(),
        );
        let doc_id = DocumentId(id);

        let encrypter_share_secret_key = ShareSecretKey::generate(csprng);
        let encrypter_share_key = encrypter_share_secret_key.share_key();

        let share_secret_key = ShareSecretKey::generate(csprng);
        let share_key = share_secret_key.share_key();
        let mut encrypt_paired_pks = nonempty![share_key];
        let mut encrypt_paired_sks = nonempty![share_secret_key];
        for _ in 0..5 {
            let share_secret_key = ShareSecretKey::generate(csprng);
            let share_key = share_secret_key.share_key();
            encrypt_paired_pks.push(share_key);
            encrypt_paired_sks.push(share_secret_key);
        }

        let nested_encrypted = NestedEncrypted::<ShareSecretKey>::try_encrypt(
            doc_id,
            secret.to_bytes(),
            &encrypter_share_secret_key,
            &encrypt_paired_pks,
        )?;

        let decrypt_keys: Vec<SymmetricKey> = encrypt_paired_sks
            .iter()
            .map(|sk| sk.derive_symmetric_key(&encrypter_share_key))
            .collect();

        let decrypted = nested_encrypted.try_sibling_decrypt(&decrypt_keys)?;

        assert_eq!(secret.to_bytes(), decrypted.as_slice());

        let encrypters_decrypted =
            nested_encrypted.try_encrypter_decrypt(&encrypter_share_secret_key)?;
        assert_eq!(secret.to_bytes(), encrypters_decrypted.as_slice());
        Ok(())
    }
}
