//! Application secrets for content encryption, derived from a CGKA group
//! secret.

use crate::encrypted::{EncryptedContent, PredecessorRefs};
use keyhive_crypto::{
    content::reference::ContentRef,
    context::Context,
    digest::Digest,
    identifier::Identifier,
    share_key::ShareSecretKey,
    signable::{Kind, Kinded},
    symmetric_key::SymmetricKey,
};
use tracing::instrument;

/// A block's application key, with its ciphertext's header fields.
///
/// Each later block's envelope stores this key for the block so anyone who
/// can read a later block can read this one too. The key opens this block only.
#[derive(Debug, Clone)]
pub struct ApplicationSecret<Cr: ContentRef> {
    key: SymmetricKey,
    group_secret_hash: Digest<GroupSecret>,
    group_secret_origin_hash: Digest<GroupSecretOrigin>,
    content_ref: Cr,
    pred_refs: Digest<PredecessorRefs<Cr>>,
}

impl<Cr: ContentRef> ApplicationSecret<Cr> {
    /// Construct a new [`ApplicationSecret`].
    pub fn new(
        key: SymmetricKey,
        group_secret_hash: Digest<GroupSecret>,
        group_secret_origin_hash: Digest<GroupSecretOrigin>,
        content_ref: Cr,
        pred_refs: Digest<PredecessorRefs<Cr>>,
    ) -> Self {
        Self {
            key,
            group_secret_hash,
            group_secret_origin_hash,
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
        doc_id: Identifier,
        plaintext: &[u8],
    ) -> Result<EncryptedContent<T, Cr>, chacha20poly1305::Error> {
        EncryptedContent::encrypt(
            &self.key,
            doc_id,
            self.content_ref.clone(),
            self.pred_refs,
            self.group_secret_hash,
            self.group_secret_origin_hash,
            plaintext,
        )
    }
}

/// A CGKA group secret, which application secrets are derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupSecret(pub ShareSecretKey);

impl GroupSecret {
    /// The digest of this key.
    pub fn digest(&self) -> Digest<GroupSecret> {
        Digest::of_bytes(self.0.as_slice())
    }

    /// Derive a block's [`ApplicationSecret`] from this group secret:
    /// `group_secret ‖ pred_refs ‖ content_ref`, under its own BLAKE3 context.
    /// The content ref is self-delimiting and comes last.
    #[instrument(skip(self))]
    pub fn derive_application_secret<Cr: ContentRef>(
        &self,
        content_ref: &Cr,
        pred_refs: &Digest<PredecessorRefs<Cr>>,
        group_secret_origin_hash: &Digest<GroupSecretOrigin>,
    ) -> ApplicationSecret<Cr> {
        let mut hasher = Context::CONTENT_APPLICATION_KEY.hasher();
        hasher.update(self.0.as_slice());
        hasher.update(pred_refs.as_slice());
        hasher.update(content_ref.encode().as_bytes());
        ApplicationSecret::new(
            SymmetricKey::from(*hasher.finalize().as_bytes()),
            self.digest(),
            *group_secret_origin_hash,
            content_ref.clone(),
            *pred_refs,
        )
    }
}

/// The secret is never signed or sent. Its digest is included in each ciphertext's
/// header so a reader can tell which group secret a block's key came from.
impl Kinded for GroupSecret {
    const KIND: Kind = Kind::PCS_KEY;
    const VERSION: u8 = 0;
}

impl From<ShareSecretKey> for GroupSecret {
    fn from(share_secret_key: ShareSecretKey) -> GroupSecret {
        GroupSecret(share_secret_key)
    }
}

/// The CGKA operation that generated a group secret. A block's header contains its
/// hash, which identifies the secret the block's key was derived from. Only
/// `Digest<GroupSecretOrigin>` is used, as bytes the key agreement supplies.
/// No value of this type exists.
#[derive(Debug)]
pub enum GroupSecretOrigin {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checked with `b3sum --derive-key` under `CONTENT_APPLICATION_KEY` over
    /// `[1; 32] ‖ Digest<PredecessorRefs>([[3; 32]]) ‖ [2; 32]`: the group secret,
    /// the predecessors' digest, then the content ref.
    #[test]
    fn the_application_key_is_derived_from_group_secret_predecessors_and_ref() {
        let secret = GroupSecret(ShareSecretKey::force_from_bytes([1; 32]))
            .derive_application_secret(
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
}
