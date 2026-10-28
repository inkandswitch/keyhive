//! Keys that encrypted or decrypted the block they are for.

use crate::reference::ContentRef;
use keyhive_crypto::{identifier::Identifier, symmetric_key::SymmetricKey};

/// The key for the block a content ref refers to in a document. Should be
/// created only when that key encrypted the block, when that block
/// successfully decrypted under it, or when such a key is restored from
/// this replica's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorKey<Cr: ContentRef> {
    content_ref: Cr,
    doc_id: Identifier,
    key: SymmetricKey,
}

impl<Cr: ContentRef> AncestorKey<Cr> {
    /// Construct an `AncestorKey`. This is only called in this crate where
    /// we have demonstrated `key` can actually decrypt the content for
    /// `content_ref` for `doc_id`.
    pub(crate) fn new(content_ref: Cr, doc_id: Identifier, key: SymmetricKey) -> Self {
        AncestorKey {
            content_ref,
            doc_id,
            key,
        }
    }

    /// A key this replica stored after it decrypted or encrypted the block,
    /// read back from that storage. Only construct one if you trust that
    /// storage.
    pub fn from_trusted_storage(content_ref: Cr, doc_id: Identifier, key: SymmetricKey) -> Self {
        Self::new(content_ref, doc_id, key)
    }

    /// The content ref the block's header claims.
    pub fn content_ref(&self) -> &Cr {
        &self.content_ref
    }

    /// The document the block is in.
    pub fn doc_id(&self) -> Identifier {
        self.doc_id
    }

    pub(crate) fn key_ref(&self) -> &SymmetricKey {
        &self.key
    }

    /// The key itself. Treat as secret.
    pub fn key(&self) -> SymmetricKey {
        self.key
    }
}
