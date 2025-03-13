//! Ciphertext with public metadata.

use super::{
    application_secret::PcsKey,
    digest::Digest,
    envelope::Envelope,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use crate::{cgka::operation::CgkaOperation, content::reference::ContentRef};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

/// The public information for an encrypted content ciphertext.
///
/// This wraps a ciphertext that includes the [`Siv`] and the type of the data
/// that was encrypted (or that the plaintext is _expected_ to be).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EncryptedContent<T, Cr: ContentRef> {
    /// The nonce used to encrypt the data.
    pub nonce: Siv,
    /// The encrypted data.
    pub ciphertext: Vec<u8>,
    /// Hash of the PCS key used to derive the application secret for encrypting.
    pub pcs_key_hash: Digest<PcsKey>,
    /// Hash of the PCS update operation corresponding to the PCS key
    pub pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
    /// The content ref hash used to derive the application secret for encrypting.
    pub content_ref: Digest<Cr>,
    /// The predecessor content ref hashes used to derive the application secret
    /// for encrypting.
    pub pred_refs: Digest<Vec<Cr>>,
    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T, Cr: ContentRef> EncryptedContent<T, Cr> {
    /// Associate a nonce with a ciphertext and assert the plaintext type.
    pub fn new(
        nonce: Siv,
        ciphertext: Vec<u8>,
        pcs_key_hash: Digest<PcsKey>,
        pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
        content_ref: Digest<Cr>,
        pred_refs: Digest<Vec<Cr>>,
    ) -> EncryptedContent<T, Cr> {
        EncryptedContent {
            nonce,
            ciphertext,
            pcs_key_hash,
            pcs_update_op_hash,
            content_ref,
            pred_refs,
            _plaintext_tag: PhantomData,
        }
    }

    pub fn try_decrypt(&self, key: SymmetricKey) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        key.try_decrypt(self.nonce, &mut buf)?;
        Ok(buf)
    }

    pub fn try_causal_decrypt<'de>(
        &self,
        key: SymmetricKey,
        store: HashMap<Digest<Cr>, Self>, // FIXME make a storgae trait
    ) -> Result<(), chacha20poly1305::Error>
    where
        T: Serialize + Deserialize<'de>,
        Cr: Deserialize<'de>,
    {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        key.try_decrypt(self.nonce, &mut buf)?;
        let envelope: Envelope<Cr, T> = bincode::deserialize(buf.as_slice())?;

        fn inner_fn() {}

        for (ancestor_id, ancestor_key) in envelope.ancestors {
            if let Some(ciphertext) = store.get(&ancestor_id) {
                ciphertext.try_causal_decrypt(ancestor_key, store.clone())?;
            }
        }

        Ok(())
    }
}

/// The public information for an encrypted secret ciphertext.
///
/// This wraps a ciphertext that includes the [`Siv`] and the type of the data
/// that was encrypted (or that the plaintext is _expected_ to be).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct EncryptedSecret<T> {
    /// The nonce used to encrypt the data.
    pub nonce: Siv,

    /// The encrypted data.
    pub ciphertext: Vec<u8>,

    /// The [`ShareKey`] used as a Diffie Hellman partner when encrypting.
    pub paired_pk: ShareKey,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T> EncryptedSecret<T> {
    /// Associate a nonce with a ciphertext and assert the plaintext type.
    pub fn new(nonce: Siv, ciphertext: Vec<u8>, paired_pk: ShareKey) -> EncryptedSecret<T> {
        EncryptedSecret {
            nonce,
            ciphertext,
            paired_pk,
            _plaintext_tag: PhantomData,
        }
    }

    pub fn try_encrypter_decrypt(
        &self,
        encrypter_secret_key: &ShareSecretKey,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        let key = encrypter_secret_key.derive_symmetric_key(&self.paired_pk);
        key.try_decrypt(self.nonce, &mut buf)?;
        Ok(buf)
    }
}
