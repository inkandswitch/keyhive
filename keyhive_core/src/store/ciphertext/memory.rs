use dupe::Dupe;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{digest::Digest, encrypted::EncryptedContent, signed::Signed},
};

#[derive(Debug, Clone, Dupe, PartialEq, Eq)]
pub struct MemoryCiphertextStore<T: ContentRef, P>(pub(crate) Rc<RefCell<Inner<T, P>>>);

impl<T: ContentRef, P> MemoryCiphertextStore<T, P> {
    pub fn new() -> Self {
        MemoryCiphertextStore(Rc::new(RefCell::new(Inner::new())))
    }

    pub fn get(&self, content_ref: &T) -> Option<EncryptedContent<P, T>>
    where
        P: Clone,
    {
        let inner = self.0.borrow();
        inner.get(content_ref).cloned()
    }

    pub fn get_by_pcs_update(
        &self,
        pcs_update_op: &Digest<Signed<CgkaOperation>>,
    ) -> Vec<EncryptedContent<P, T>>
    where
        P: Clone,
    {
        let inner = self.0.borrow();
        inner
            .get_by_pcs_update(pcs_update_op)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn insert(&mut self, encrypted: EncryptedContent<P, T>) {
        self.0.borrow_mut().insert(encrypted);
    }

    pub fn remove(
        &mut self,
        content_ref: &T,
        digest: &Digest<EncryptedContent<P, T>>,
    ) -> Option<EncryptedContent<P, T>> {
        self.0.borrow_mut().remove(content_ref, digest)
    }

    pub fn remove_all(&mut self, content_ref: &T) -> bool {
        self.0.borrow_mut().remove_all(content_ref)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Inner<T: ContentRef, P> {
    pub(crate) index: HashMap<Digest<Signed<CgkaOperation>>, Vec<T>>,
    pub(crate) store:
        HashMap<T, HashMap<Digest<EncryptedContent<P, T>>, (ByteSize, EncryptedContent<P, T>)>>,
}

impl<T: ContentRef, P> Inner<T, P> {
    pub fn new() -> Self {
        Inner {
            store: HashMap::new(),
            index: HashMap::new(),
        }
    }

    pub fn get(&self, content_ref: &T) -> Option<&EncryptedContent<P, T>> {
        self.store.get(content_ref).and_then(|xs| {
            let (_, largest) = xs.values().max_by_key(|(size, _)| size)?;
            Some(largest)
        })
    }

    fn get_by_pcs_update(
        &self,
        pcs_update_op: &Digest<Signed<CgkaOperation>>,
    ) -> Vec<&EncryptedContent<P, T>> {
        self.index
            .get(pcs_update_op)
            .iter()
            .fold(vec![], |mut acc, hashes| {
                for hash in hashes.iter() {
                    if let Some(entry) = self.store.get(hash) {
                        for (_, encrypted) in entry.values() {
                            acc.push(encrypted);
                        }
                    }
                }

                acc
            })
    }

    pub fn insert(&mut self, encrypted: EncryptedContent<P, T>) {
        let content_ref = encrypted.content_ref.clone();
        let pcs_update_op_hash = encrypted.pcs_update_op_hash;

        self.store
            .entry(content_ref.clone())
            .or_insert_with(HashMap::new)
            .insert(
                Digest::hash(&encrypted),
                (ByteSize(encrypted.ciphertext.len()), encrypted),
            );

        self.index
            .entry(pcs_update_op_hash)
            .or_insert_with(Vec::new)
            .push(content_ref);
    }

    pub fn remove(
        &mut self,
        content_ref: &T,
        digest: &Digest<EncryptedContent<P, T>>,
    ) -> Option<EncryptedContent<P, T>> {
        let entry = self.store.get_mut(content_ref)?;
        let encrypted = entry.remove(digest).map(|(_, ciphertext)| ciphertext)?;

        if entry.is_empty() {
            self.store.remove(content_ref);
            self.index.remove(&encrypted.pcs_update_op_hash);
        }

        Some(encrypted)
    }

    pub fn remove_all(&mut self, content_ref: &T) -> bool {
        self.store.remove(content_ref).is_some()
    }
}

// FIXME move to util
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ByteSize(pub(crate) usize);
