use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{digest::Digest, encrypted::EncryptedContent, signed::Signed},
};
use dupe::Dupe;
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};
use tracing::instrument;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryCiphertextStore<Cr: ContentRef, P> {
    pub(crate) ops_to_refs: HashMap<Digest<Signed<CgkaOperation>>, HashSet<Cr>>,
    pub(crate) refs_to_digests: HashMap<Cr, HashSet<Digest<EncryptedContent<P, Cr>>>>,
    pub(crate) store:
        HashMap<Digest<EncryptedContent<P, Cr>>, (ByteSize, Rc<EncryptedContent<P, Cr>>)>,
}

impl<Cr: ContentRef, P> MemoryCiphertextStore<Cr, P> {
    #[instrument(level = "debug")]
    pub fn new() -> Self {
        Self {
            ops_to_refs: HashMap::new(),
            refs_to_digests: HashMap::new(),
            store: HashMap::new(),
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub fn get_by_content_ref(&self, content_ref: &Cr) -> Option<Rc<EncryptedContent<P, Cr>>> {
        let digests = self.refs_to_digests.get(content_ref)?;

        let xs = digests
            .iter()
            .map(|digest| self.store.get(digest))
            .collect::<Option<Vec<_>>>()?;
        let (_, largest) = xs.iter().max_by_key(|(size, _)| size)?;
        Some(largest.dupe())
    }

    #[instrument(level = "debug", skip(self))]
    pub fn get_by_pcs_update(
        &self,
        pcs_update_op: &Digest<Signed<CgkaOperation>>,
    ) -> Vec<Rc<EncryptedContent<P, Cr>>> {
        self.ops_to_refs
            .get(pcs_update_op)
            .iter()
            .fold(vec![], |mut acc, content_refs| {
                for content_ref in content_refs.iter() {
                    if let Some(digests) = self.refs_to_digests.get(content_ref) {
                        for digest in digests.iter() {
                            if let Some((_, encrypted)) = self.store.get(digest) {
                                acc.push(encrypted.dupe());
                            }
                        }
                    }
                }

                acc
            })
    }

    #[instrument(level = "debug", skip_all, fields(ecrypted.content_ref))]
    pub fn insert(&mut self, encrypted: Rc<EncryptedContent<P, Cr>>) {
        let digest = Digest::hash(encrypted.as_ref());
        let content_ref = encrypted.content_ref.clone();
        let pcs_update_op_hash = encrypted.pcs_update_op_hash;

        if self
            .store
            .insert(digest, (ByteSize(encrypted.ciphertext.len()), encrypted))
            .is_some()
        {
            return;
        }

        self.ops_to_refs
            .entry(pcs_update_op_hash)
            .or_default()
            .insert(content_ref.clone());

        self.refs_to_digests
            .entry(content_ref)
            .or_default()
            .insert(digest);
    }

    #[instrument(level = "debug", skip_all, fields(ecrypted.content_ref))]
    pub fn insert_raw(
        &mut self,
        encrypted: EncryptedContent<P, Cr>,
    ) -> Rc<EncryptedContent<P, Cr>> {
        let rc = Rc::new(encrypted);
        self.insert(rc.dupe());
        rc
    }

    #[instrument(level = "debug", skip_all, fields(digest))]
    pub fn remove(
        &mut self,
        digest: &Digest<EncryptedContent<P, Cr>>,
    ) -> Option<Rc<EncryptedContent<P, Cr>>> {
        let (_, encrypted) = self.store.remove(digest)?;

        self.ops_to_refs
            .entry(encrypted.pcs_update_op_hash)
            .and_modify(|crs| {
                crs.remove(&encrypted.content_ref);
            });

        if self
            .ops_to_refs
            .get(&encrypted.pcs_update_op_hash)?
            .is_empty()
        {
            self.ops_to_refs.remove(&encrypted.pcs_update_op_hash);
        }

        self.refs_to_digests
            .entry(encrypted.content_ref.clone())
            .and_modify(|digests| {
                digests.remove(digest);
            });

        if let Some(digests) = self.refs_to_digests.get(&encrypted.content_ref) {
            if digests.is_empty() {
                self.refs_to_digests.remove(&encrypted.content_ref);
            }
        }

        Some(encrypted)
    }

    #[instrument(level = "debug", skip(self))]
    pub fn remove_all(&mut self, content_ref: &Cr) -> bool {
        if let Some(digests) = self.refs_to_digests.remove(content_ref) {
            for digest in digests.iter() {
                self.store.remove(&digest);
            }
            true
        } else {
            false
        }
    }
}

impl<T: ContentRef, P> Default for MemoryCiphertextStore<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ByteSize(pub(crate) usize);
