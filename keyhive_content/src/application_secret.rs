//! Application secrets for content encryption, derived from a CGKA group
//! secret.

use crate::{
    ancestor_key::AncestorKey,
    encrypted::{encode_ancestors, EncryptedContent, PredecessorRefs},
    reference::ContentRef,
};
use alloc::vec::Vec;
use keyhive_crypto::{
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

    /// Encrypt `payload` for the document `doc_id`, with the keys of its
    /// `ancestors` before it in the body (see the [`encrypted`] module docs).
    /// Returns the block with its own [`AncestorKey`], for a later write.
    ///
    /// The ancestors must be in `doc_id` and must be exactly the predecessors
    /// this secret was derived for. Where a content ref is listed more than
    /// once, its last key is kept.
    ///
    /// [`encrypted`]: crate::encrypted
    pub fn try_encrypt<T>(
        &self,
        doc_id: Identifier,
        ancestors: &[AncestorKey<Cr>],
        payload: &[u8],
    ) -> Result<(EncryptedContent<T, Cr>, AncestorKey<Cr>), TryEncryptError> {
        if ancestors.iter().any(|a| a.doc_id() != doc_id) {
            return Err(TryEncryptError::AncestorInAnotherDocument);
        }
        let refs: Vec<Cr> = ancestors.iter().map(|a| a.content_ref().clone()).collect();
        if PredecessorRefs::digest(&refs) != self.pred_refs {
            return Err(TryEncryptError::AncestorsAreNotPredecessors);
        }
        let mut body = Vec::new();
        encode_ancestors(
            ancestors.iter().map(|a| (a.content_ref(), a.key_ref())),
            &mut body,
        );
        body.reserve_exact(payload.len());
        body.extend_from_slice(payload);
        let encrypted = EncryptedContent::encrypt(
            &self.key,
            doc_id,
            self.content_ref.clone(),
            self.pred_refs,
            self.group_secret_hash,
            self.group_secret_origin_hash,
            &body,
        )
        .map_err(|_| TryEncryptError::Encryption)?;
        Ok((
            encrypted,
            AncestorKey::new(self.content_ref.clone(), doc_id, self.key),
        ))
    }
}

/// Why [`ApplicationSecret::try_encrypt`] did not encrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TryEncryptError {
    /// An ancestor's key is for a block in another document.
    #[error("an ancestor is in another document")]
    AncestorInAnotherDocument,

    /// The ancestors are not the predecessors the secret was derived for.
    #[error("the ancestors are not the block's predecessors")]
    AncestorsAreNotPredecessors,

    /// The cipher refused the plaintext.
    #[error("encryption failed")]
    Encryption,
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

    fn secret(pred_refs: &[[u8; 32]]) -> ApplicationSecret<[u8; 32]> {
        GroupSecret(ShareSecretKey::force_from_bytes([1; 32])).derive_application_secret(
            &[2; 32],
            &PredecessorRefs::digest(pred_refs),
            &[5; 32].into(),
        )
    }

    fn doc(n: u8) -> Identifier {
        Identifier::from(&ed25519_dalek::SigningKey::from_bytes(&[n; 32]))
    }

    fn ancestor(content_ref: u8, doc_id: Identifier) -> AncestorKey<[u8; 32]> {
        AncestorKey::new(
            [content_ref; 32],
            doc_id,
            SymmetricKey::from([content_ref; 32]),
        )
    }

    #[test]
    fn a_write_refuses_an_ancestor_from_another_document() {
        assert_eq!(
            secret(&[[3; 32]])
                .try_encrypt::<Vec<u8>>(doc(1), &[ancestor(3, doc(2))], b"")
                .map(|_| ()),
            Err(TryEncryptError::AncestorInAnotherDocument)
        );
    }

    #[test]
    fn a_write_refuses_ancestors_that_are_not_its_predecessors() {
        assert_eq!(
            secret(&[[3; 32], [4; 32]])
                .try_encrypt::<Vec<u8>>(doc(1), &[ancestor(3, doc(1))], b"")
                .map(|_| ()),
            Err(TryEncryptError::AncestorsAreNotPredecessors)
        );
    }

    #[test]
    fn a_write_returns_the_key_that_decrypts_it() {
        let (encrypted, own) = secret(&[[3; 32]])
            .try_encrypt::<Vec<u8>>(doc(1), &[ancestor(3, doc(1))], b"payload")
            .expect("the ancestors are the predecessors");
        assert!(encrypted.try_decrypt(own.key(), own.doc_id()).is_ok());
        assert_eq!(own.content_ref(), &encrypted.content_ref);
    }
}
