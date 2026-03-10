//! Encryption keys, key derivation, and associated metadata.

use super::signed::Signed;
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{
        digest::Digest, encrypted::EncryptedContent, separable::Separable,
        share_key::ShareSecretKey, siv::Siv, symmetric_key::SymmetricKey,
    },
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

const STATIC_CONTEXT: &str = "/keyhive/beekem/app_secret/";

/// A [`SymmetricKey`] plus metadata needed for causal encryption.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplicationSecret<Cr: ContentRef> {
    key: SymmetricKey,
    pcs_key_hash: Digest<PcsKey>,
    pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
    nonce: Siv,
    content_ref: Cr,
    pred_refs: Digest<Vec<Cr>>,
}

impl<Cr: ContentRef> ApplicationSecret<Cr> {
    /// Construct a new [`ApplicationSecret`].
    pub fn new(
        key: SymmetricKey,
        pcs_key_hash: Digest<PcsKey>,
        pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
        nonce: Siv,
        content_ref: Cr,
        pred_refs: Digest<Vec<Cr>>,
    ) -> Self {
        Self {
            key,
            pcs_key_hash,
            pcs_update_op_hash,
            nonce,
            content_ref,
            pred_refs,
        }
    }

    /// Getter for the underlying symmetric key.
    pub fn key(&self) -> SymmetricKey {
        self.key
    }

    /// Encrypt some plaintext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt.
    /// ```
    pub fn try_encrypt<T>(
        &self,
        plaintext: &[u8],
    ) -> Result<EncryptedContent<T, Cr>, chacha20poly1305::Error> {
        let mut ciphertext = plaintext.to_vec();
        self.key.try_encrypt(self.nonce, &mut ciphertext)?;
        Ok(EncryptedContent::new(
            self.nonce,
            ciphertext,
            self.pcs_key_hash,
            self.pcs_update_op_hash,
            self.content_ref.clone(),
            self.pred_refs,
        ))
    }
}

/// A key used to derive application secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PcsKey(pub ShareSecretKey);

impl PcsKey {
    /// Lift a `ShareSecretKey` into a `PcsKey`.
    pub fn new(share_secret_key: ShareSecretKey) -> Self {
        Self(share_secret_key)
    }

    #[instrument]
    pub(crate) fn derive_application_secret<Cr: ContentRef>(
        &self,
        nonce: &Siv,
        content_ref: &Cr,
        pred_refs: &Digest<Vec<Cr>>,
        pcs_update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> ApplicationSecret<Cr> {
        let pcs_hash = Digest::hash(&self.0);
        let display_ref = Digest::hash(&content_ref);
        let mut app_secret_context =
            format!("epoch:{pcs_hash}/pred:{pred_refs}/content:{display_ref}").into_bytes();
        let mut key_material = self.0.clone().as_slice().to_vec();
        key_material.append(&mut app_secret_context);
        let app_secret_bytes = blake3::derive_key(STATIC_CONTEXT, key_material.as_slice());
        let symmetric_key = SymmetricKey::derive_from_bytes(&app_secret_bytes);
        ApplicationSecret::new(
            symmetric_key,
            Digest::hash(self),
            *pcs_update_op_hash,
            *nonce,
            content_ref.clone(),
            *pred_refs,
        )
    }
}

impl From<ShareSecretKey> for PcsKey {
    fn from(share_secret_key: ShareSecretKey) -> PcsKey {
        PcsKey(share_secret_key)
    }
}

impl From<PcsKey> for SymmetricKey {
    fn from(pcs_key: PcsKey) -> SymmetricKey {
        SymmetricKey::derive_from_bytes(pcs_key.0.as_slice())
    }
}
