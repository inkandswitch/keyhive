use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{digest::Digest, encrypted::EncryptedContent, signed::Signed},
};
use dupe::Dupe;
use futures::lock::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::instrument;

#[derive(Debug, Clone, Dupe)]
pub struct MemoryCiphertextStore<Cr: ContentRef, P>(
    pub(crate) Arc<Mutex<MemoryCiphertextStoreInner<Cr, P>>>,
);

#[derive(Debug, Clone)]
pub struct MemoryCiphertextStoreInner<Cr: ContentRef, P> {
    pub(crate) ops_to_refs: HashMap<Digest<Signed<CgkaOperation>>, HashSet<Cr>>,
    pub(crate) refs_to_digests: HashMap<Cr, HashSet<Digest<EncryptedContent<P, Cr>>>>,

    #[allow(clippy::type_complexity)]
    pub(crate) store:
        HashMap<Digest<EncryptedContent<P, Cr>>, (ByteSize, Arc<EncryptedContent<P, Cr>>)>,
}

impl<Cr: ContentRef, P> MemoryCiphertextStore<Cr, P> {
    #[instrument(level = "debug")]
    pub fn new() -> Self {
        MemoryCiphertextStore(Arc::new(Mutex::new(MemoryCiphertextStoreInner {
            ops_to_refs: HashMap::new(),
            refs_to_digests: HashMap::new(),
            store: HashMap::new(),
        })))
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_by_content_ref(
        &self,
        content_ref: &Cr,
    ) -> Option<Arc<EncryptedContent<P, Cr>>> {
        let locked = self.0.lock().await;

        let xs = locked
            .refs_to_digests
            .get(content_ref)?
            .iter()
            .map(|digest| locked.store.get(digest))
            .collect::<Option<Vec<_>>>()?;
        let (_, largest) = xs.iter().max_by_key(|(size, _)| size)?;
        Some(largest.dupe())
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_by_pcs_update(
        &self,
        pcs_update_op: &Digest<Signed<CgkaOperation>>,
    ) -> Vec<Arc<EncryptedContent<P, Cr>>> {
        let locked = self.0.lock().await;

        locked
            .ops_to_refs
            .get(pcs_update_op)
            .iter()
            .fold(vec![], |mut acc, content_refs| {
                for content_ref in content_refs.iter() {
                    if let Some(digests) = locked.refs_to_digests.get(content_ref) {
                        for digest in digests.iter() {
                            if let Some((_, encrypted)) = locked.store.get(digest) {
                                acc.push(encrypted.dupe());
                            }
                        }
                    }
                }

                acc
            })
    }

    #[instrument(level = "debug", skip_all, fields(ecrypted.content_ref))]
    pub async fn insert(&self, encrypted: Arc<EncryptedContent<P, Cr>>) {
        let digest = Digest::hash(encrypted.as_ref());
        let content_ref = encrypted.content_ref.clone();
        let pcs_update_op_hash = encrypted.pcs_update_op_hash;

        let mut locked = self.0.lock().await;

        if locked
            .store
            .insert(digest, (ByteSize(encrypted.ciphertext.len()), encrypted))
            .is_some()
        {
            return;
        }

        locked
            .ops_to_refs
            .entry(pcs_update_op_hash)
            .or_default()
            .insert(content_ref.clone());

        locked
            .refs_to_digests
            .entry(content_ref)
            .or_default()
            .insert(digest);
    }

    #[instrument(level = "debug", skip_all, fields(ecrypted.content_ref))]
    pub async fn insert_raw(
        &self,
        encrypted: EncryptedContent<P, Cr>,
    ) -> Arc<EncryptedContent<P, Cr>> {
        let rc = Arc::new(encrypted);
        self.insert(rc.dupe()).await;
        rc
    }

    #[instrument(level = "debug", skip_all, fields(digest))]
    pub async fn remove(
        &self,
        digest: &Digest<EncryptedContent<P, Cr>>,
    ) -> Option<Arc<EncryptedContent<P, Cr>>> {
        let mut locked = self.0.lock().await;
        let (_, encrypted) = locked.store.remove(digest)?;

        locked
            .ops_to_refs
            .entry(encrypted.pcs_update_op_hash)
            .and_modify(|crs| {
                crs.remove(&encrypted.content_ref);
            });

        if locked
            .ops_to_refs
            .get(&encrypted.pcs_update_op_hash)?
            .is_empty()
        {
            locked.ops_to_refs.remove(&encrypted.pcs_update_op_hash);
        }

        locked
            .refs_to_digests
            .entry(encrypted.content_ref.clone())
            .and_modify(|digests| {
                digests.remove(digest);
            });

        if let Some(digests) = locked.refs_to_digests.get(&encrypted.content_ref) {
            if digests.is_empty() {
                locked.refs_to_digests.remove(&encrypted.content_ref);
            }
        }

        Some(encrypted)
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn remove_all(&self, content_ref: &Cr) -> bool {
        let mut locked = self.0.lock().await;
        if let Some(digests) = locked.refs_to_digests.remove(content_ref) {
            for digest in digests.iter() {
                locked.store.remove(digest);
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
