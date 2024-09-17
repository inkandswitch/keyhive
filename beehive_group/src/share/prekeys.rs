use super::op::Update; // FIXME split
use crate::crypto::hash::{CAStore, Hash};
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::principal::individual::Individual;
use crate::util::non_empty_set::NonEmptySet;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prekeys {
    pub id: Individual,
    pub sharing_prekeys: NonEmptySet<ShareKey>,
}

impl Prekeys {
    pub fn from_ops(id: Individual, updates: NonEmptySet<Signed<Update>>) -> Self {
        let mut indexed: CAStore<Signed<Update>> = CAStore::new();
        let mut tombstones: BTreeSet<&Hash<Signed<Update>>> = BTreeSet::new();

        indexed.insert(updates.head);

        for update in updates.rest.iter() {
            for replacement in update.payload.replaces.iter() {
                tombstones.insert(&replacement);
            }

            indexed.insert(update.clone());
        }

        for tombstone in tombstones.iter() {
            indexed.remove(tombstone);
        }

        let mut sharing_prekeys_iter = indexed.into_values().map(|update| update.payload.add);
        let head = sharing_prekeys_iter.next().expect("at least one prekey"); // FIXME not thrilled about this expect

        Self {
            id,
            sharing_prekeys: NonEmptySet {
                head,
                rest: sharing_prekeys_iter.collect(),
            },
        }
    }

    pub fn prekey_for(&self, requestor: VerifyingKey) -> Option<ShareKey> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_slice());
        hasher.update(requestor.as_bytes());
        let hash = hasher.finalize();

        let pre_index = u64::from_be_bytes(hash.as_bytes()[0..8].try_into().expect("FIXME"));
        let index = pre_index % self.sharing_prekeys.len() as u64;

        self.sharing_prekeys.clone().into_iter().nth(index as usize)
    }
}
