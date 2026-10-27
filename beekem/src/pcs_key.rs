//! PCS keys and application secrets for content encryption.

use crate::{
    encrypted::{EncryptedContent, PredecessorRefs},
    id::TreeId,
    keys::share_secret_key_from_decrypted_secret,
    operation::CgkaOperation,
};
use alloc::vec::Vec;
use keyhive_crypto::{
    content::reference::ContentRef,
    context::Context,
    digest::Digest,
    share_key::ShareSecretKey,
    signable::{Kind, Kinded},
    signed::SerdeSigned,
    symmetric_key::SymmetricKey,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// A block's application key, with the header fields its ciphertext carries.
///
/// The key is what a causal envelope hands to a successor's readers: holding
/// it decrypts this one block.
#[derive(Debug, Clone)]
pub struct ApplicationSecret<Cr: ContentRef> {
    key: SymmetricKey,
    pcs_key_hash: Digest<PcsKey>,
    pcs_update_op_hash: Digest<SerdeSigned<CgkaOperation>>,
    content_ref: Cr,
    pred_refs: Digest<PredecessorRefs<Cr>>,
}

impl<Cr: ContentRef> ApplicationSecret<Cr> {
    /// Construct a new [`ApplicationSecret`].
    pub fn new(
        key: SymmetricKey,
        pcs_key_hash: Digest<PcsKey>,
        pcs_update_op_hash: Digest<SerdeSigned<CgkaOperation>>,
        content_ref: Cr,
        pred_refs: Digest<PredecessorRefs<Cr>>,
    ) -> Self {
        Self {
            key,
            pcs_key_hash,
            pcs_update_op_hash,
            content_ref,
            pred_refs,
        }
    }

    /// Getter for the underlying symmetric key.
    pub fn key(&self) -> SymmetricKey {
        self.key
    }

    /// Encrypt `plaintext` for the document `doc_id`.
    pub fn try_encrypt<T>(
        &self,
        doc_id: TreeId,
        plaintext: &[u8],
    ) -> Result<EncryptedContent<T, Cr>, chacha20poly1305::Error> {
        EncryptedContent::encrypt(
            &self.key,
            doc_id,
            self.content_ref.clone(),
            self.pred_refs,
            self.pcs_key_hash,
            self.pcs_update_op_hash,
            plaintext,
        )
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

    /// A root secret decrypted from an invitation or a predecessor secret.
    /// Returns `None` unless `decrypted_secret` is 32 bytes.
    pub(crate) fn from_decrypted_secret(decrypted_secret: Vec<u8>) -> Option<Self> {
        share_secret_key_from_decrypted_secret(decrypted_secret).map(Self::new)
    }

    /// The digest that names this key in a ciphertext's header.
    pub fn digest(&self) -> Digest<PcsKey> {
        Digest::of_bytes(self.0.as_slice())
    }

    /// Derive the key for encrypting the root secrets of an update's predecessors.
    pub(crate) fn derive_predecessor_secrets_key(&self) -> SymmetricKey {
        Context::CGKA_PREDECESSOR_SECRETS_KEY
            .derive_key(self.0.as_slice())
            .into()
    }

    /// Derive a block's [`ApplicationSecret`] from this PCS key:
    /// `pcs_key ‖ pred_refs ‖ content_ref`, under its own BLAKE3 context. The
    /// content ref is self-delimiting and comes last.
    #[instrument(skip(self))]
    pub fn derive_application_secret<Cr: ContentRef>(
        &self,
        content_ref: &Cr,
        pred_refs: &Digest<PredecessorRefs<Cr>>,
        pcs_update_op_hash: &Digest<SerdeSigned<CgkaOperation>>,
    ) -> ApplicationSecret<Cr> {
        let mut hasher = Context::CONTENT_APPLICATION_KEY.hasher();
        hasher.update(self.0.as_slice());
        hasher.update(pred_refs.as_slice());
        hasher.update(content_ref.encode().as_bytes());
        ApplicationSecret::new(
            SymmetricKey::from(*hasher.finalize().as_bytes()),
            self.digest(),
            *pcs_update_op_hash,
            content_ref.clone(),
            *pred_refs,
        )
    }
}

/// Hashed to name the key a block was encrypted under; never signed or sent.
impl Kinded for PcsKey {
    const KIND: Kind = Kind::PCS_KEY;
    const VERSION: u8 = 0;
}

impl From<ShareSecretKey> for PcsKey {
    fn from(share_secret_key: ShareSecretKey) -> PcsKey {
        PcsKey(share_secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcs_key() -> PcsKey {
        PcsKey::new(ShareSecretKey::force_from_bytes([1; 32]))
    }

    /// Checked with `b3sum --derive-key` under `CONTENT_APPLICATION_KEY` over
    /// `[1; 32] ‖ Digest<PredecessorRefs>([[3; 32]]) ‖ [2; 32]`: the root secret,
    /// the predecessors' digest, then the content ref.
    #[test]
    fn the_application_key_is_derived_from_root_predecessors_and_ref() {
        let secret = pcs_key().derive_application_secret(
            &[2u8; 32],
            &PredecessorRefs::digest(&[[3; 32]]),
            &[5; 32].into(),
        );
        assert_eq!(
            secret.key(),
            SymmetricKey::from(
                *blake3::Hash::from_hex(
                    "4ca5444e220f4c0418ca1cfb49b232e0da4bd02e34ca31bd37b998f321b62165"
                )
                .expect("hex")
                .as_bytes()
            )
        );
    }

    /// Checked with `b3sum --derive-key` under `CGKA_PREDECESSOR_SECRETS_KEY`
    /// over the root secret `[1; 32]`: one derivation.
    #[test]
    fn the_predecessor_secrets_key_is_one_derivation_from_the_root() {
        assert_eq!(
            pcs_key().derive_predecessor_secrets_key(),
            SymmetricKey::from(
                *blake3::Hash::from_hex(
                    "bd12f7975b80d7ca658430f18000b51ad68e568c109306adb0ba23b4a7501665"
                )
                .expect("hex")
                .as_bytes()
            )
        );
    }
}
