//! Encryption keys, key derivation, and associated metadata.

use super::{
    share_key::{AsyncSecretKey, ShareKey},
    signed::Signed,
};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{
        digest::Digest, encrypted::EncryptedContent, separable::Separable, siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::document::id::DocumentId,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

const STATIC_CONTEXT: &str = "/keyhive/beekem/app_secret/";

/// A [`SymmetricKey`] plus metadata needed for causal encryption.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplicationSecret<Cr: ContentRef> {
    key: SymmetricKey,
    pcs_pubkey: ShareKey,
    pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
    nonce: Siv,
    content_ref: Cr,
    pred_refs: Digest<Vec<Cr>>,
}

impl<Cr: ContentRef> ApplicationSecret<Cr> {
    /// Construct a new [`ApplicationSecret`].
    pub fn new(
        key: SymmetricKey,
        pcs_pubkey: ShareKey,
        pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
        nonce: Siv,
        content_ref: Cr,
        pred_refs: Digest<Vec<Cr>>,
    ) -> Self {
        Self {
            key,
            pcs_pubkey,
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
            self.pcs_pubkey,
            self.pcs_update_op_hash,
            self.content_ref.clone(),
            self.pred_refs,
        ))
    }
}

/// A key used to derive application secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PcsKey<T: AsyncSecretKey + Clone>(pub T);

impl<T: AsyncSecretKey + Clone> PcsKey<T> {
    /// Lift a `ShareSecretKey` into a `PcsKey`.
    pub fn new(share_secret_key: T) -> Self {
        Self(share_secret_key)
    }

    #[instrument(skip_all)]
    pub(crate) async fn derive_application_secret<Cr: ContentRef>(
        &self,
        doc_id: DocumentId,
        nonce: &Siv,
        content_ref: &Cr,
        pred_refs: &Digest<Vec<Cr>>,
        pcs_update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> ApplicationSecret<Cr> {
        let pcs_hash = Digest::hash(&self.0.to_share_key());
        let display_ref = Digest::hash(&content_ref);
        let mut app_secret_context =
            format!("epoch:{pcs_hash}/pred:{pred_refs}/content:{display_ref}").into_bytes();
        let local_pk: ShareKey = x25519_dalek::PublicKey::from(doc_id.to_bytes()).into();
        let mut key_material = self.0.derive_bytes(local_pk).await.expect("FIXME").to_vec();
        key_material.append(&mut app_secret_context);
        let app_secret_bytes = blake3::derive_key(STATIC_CONTEXT, key_material.as_slice());
        let symmetric_key = SymmetricKey::derive_from_bytes(&app_secret_bytes);
        ApplicationSecret::new(
            symmetric_key,
            self.0.to_share_key(),
            *pcs_update_op_hash,
            *nonce,
            content_ref.clone(),
            *pred_refs,
        )
    }

    pub(crate) async fn to_symmetric_key(
        &self,
        doc_id: DocumentId,
    ) -> Result<SymmetricKey, T::EcdhError> {
        let local_pk: ShareKey = x25519_dalek::PublicKey::from(doc_id.to_bytes()).into();
        self.0.derive_symmetric_key(local_pk).await
    }
}
