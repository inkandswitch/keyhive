//! Ciphertext with public metadata.

use crate::{error::CgkaError, operation::CgkaOperation, pcs_key::PcsKey};
use alloc::vec::Vec;
use core::marker::PhantomData;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// A predecessor PCS key entry. Includes the op hash that produced the key
/// plus the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredecessorPcsKey {
    /// The hash of the CGKA operation that produced [`Self::pcs_key`].
    pub op_hash: Digest<Signed<CgkaOperation>>,
    /// The predecessor epoch's PCS key.
    pub pcs_key: PcsKey,
}

/// Predecessor PCS keys encrypted under the current PCS key.
/// Enables key chaining.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct EncryptedPredecessorKeys {
    /// The synthetic IV used to encrypt the predecessor entries.
    pub nonce: Siv,
    /// The encrypted, concatenated predecessor entries.
    pub ciphertext: Vec<u8>,
}

impl EncryptedPredecessorKeys {
    /// Each entry is 64 bytes: 32 for op_hash and 32 for PcsKey (ShareSecretKey).
    const ENTRY_SIZE: usize = 32 + 32;

    /// Serialize and encrypt the `predecessors` under `key` (the current PCS
    /// key as a [`SymmetricKey`]), binding the ciphertext to `doc_id`.
    pub fn encrypt(
        predecessors: &[PredecessorPcsKey],
        key: SymmetricKey,
        doc_id: &[u8],
    ) -> Result<Self, chacha20poly1305::Error> {
        let mut plaintext = Vec::with_capacity(predecessors.len() * Self::ENTRY_SIZE);
        for pred in predecessors {
            plaintext.extend_from_slice(pred.op_hash.as_slice());
            plaintext.extend_from_slice(pred.pcs_key.0.as_slice());
        }
        let nonce = Siv::new(&key, &plaintext, doc_id);
        key.try_encrypt(nonce, &mut plaintext)?;
        Ok(Self {
            nonce,
            ciphertext: plaintext,
        })
    }

    /// Decrypt and deserialize the predecessor entries using `key` (the
    /// current PCS key as a [`SymmetricKey`]).
    pub fn decrypt(&self, key: SymmetricKey) -> Result<Vec<PredecessorPcsKey>, CgkaError> {
        use alloc::format;
        let mut buf = self.ciphertext.clone();
        key.try_decrypt(self.nonce, &mut buf)
            .map_err(|e| CgkaError::Decryption(format!("predecessor keys: {}", e)))?;
        if !buf.len().is_multiple_of(Self::ENTRY_SIZE) {
            return Err(CgkaError::Decryption(format!(
                "predecessor keys: invalid size {}",
                buf.len()
            )));
        }
        let mut result = Vec::with_capacity(buf.len() / Self::ENTRY_SIZE);
        for chunk in buf.chunks_exact(Self::ENTRY_SIZE) {
            let op_hash_bytes: [u8; 32] = chunk[..32]
                .try_into()
                .expect("chunks_exact guarantees 64-byte chunks");
            let pcs_key_bytes: [u8; 32] = chunk[32..]
                .try_into()
                .expect("chunks_exact guarantees 64-byte chunks");
            let op_hash: Digest<Signed<CgkaOperation>> = op_hash_bytes.into();
            let pcs_key = PcsKey::new(ShareSecretKey::force_from_bytes(pcs_key_bytes));
            result.push(PredecessorPcsKey { op_hash, pcs_key });
        }
        Ok(result)
    }
}

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
    /// Hash of the PCS update operation corresponding to the PCS key.
    pub pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
    /// The content ref hash used to derive the application secret for encrypting.
    pub content_ref: Cr,
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
        content_ref: Cr,
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

    /// Decrypt the ciphertext using the provided symmetric key.
    pub fn try_decrypt(&self, key: SymmetricKey) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let mut buf: Vec<u8> = self.ciphertext.clone();
        key.try_decrypt(self.nonce, &mut buf)?;
        Ok(buf)
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

    /// Decrypt the secret using the encrypter's secret key.
    #[instrument(skip(self))]
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

impl<T: core::hash::Hash, Cr: ContentRef> core::hash::Hash for EncryptedContent<T, Cr> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let EncryptedContent {
            nonce,
            ciphertext,
            pcs_key_hash,
            pcs_update_op_hash,
            content_ref,
            pred_refs,
            _plaintext_tag,
        } = self;

        nonce.hash(state);
        ciphertext.hash(state);
        pcs_key_hash.hash(state);
        pcs_update_op_hash.hash(state);
        content_ref.hash(state);
        pred_refs.hash(state);
    }
}

/// Encrypt a secret key for a tree node, paired with the given public key.
pub fn encrypt_secret(
    doc_id: &[u8],
    secret: ShareSecretKey,
    sk: &ShareSecretKey,
    paired_pk: &ShareKey,
) -> Result<EncryptedSecret<ShareSecretKey>, CgkaError> {
    let key = sk.derive_symmetric_key(paired_pk);
    let mut ciphertext: Vec<u8> = (&secret).into();
    let nonce = Siv::new(&key, &ciphertext, doc_id);
    key.try_encrypt(nonce, &mut ciphertext)
        .map_err(CgkaError::Encryption)?;
    Ok(EncryptedSecret::new(nonce, ciphertext, *paired_pk))
}
