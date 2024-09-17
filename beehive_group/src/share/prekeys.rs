use super::op::{Add, Replace}; // FIXME split
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::principal::stateless::Stateless;
use crate::util::non_empty_set::NonEmptySet;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prekeys {
    pub verifier: Stateless,
    pub sharing_prekeys: NonEmptySet<ShareKey>,
}

impl Prekeys {
    pub fn from_ops(
        verifier: Stateless,
        adds: NonEmptySet<Signed<Add>>,
        replacements: BTreeSet<Signed<Replace>>,
    ) -> Self {
        // FIXME validate ops at some stage... maybe earlier in the pipeline than this func
        let mut sharing_prekeys = NonEmptySet {
            head: adds.head.payload.sharing_pubkey,
            rest: adds
                .rest
                .iter()
                .map(|add| add.payload.sharing_pubkey)
                .collect(),
        };

        for replacement in replacements.iter() {
            if sharing_prekeys.head == replacement.payload.prev {
                sharing_prekeys.head = replacement.payload.next;
            } else {
                sharing_prekeys.rest.remove(&replacement.payload.prev);
                sharing_prekeys.rest.insert(replacement.payload.next);
            }
        }

        Self {
            verifier,
            sharing_prekeys,
        }
    }

    pub fn prekey_for(&self, requestor: VerifyingKey) -> Option<ShareKey> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.verifier.as_slice());
        hasher.update(requestor.as_bytes());
        let hash = hasher.finalize();

        let pre_index = u64::from_be_bytes(hash.as_bytes()[0..8].try_into().expect("FIXME"));
        let index = pre_index % self.sharing_prekeys.len() as u64;

        self.sharing_prekeys.clone().into_iter().nth(index as usize)
    }
}
