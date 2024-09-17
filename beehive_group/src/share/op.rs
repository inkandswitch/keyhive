use crate::crypto::hash::Hash;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::principal::individual::Individual;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Update {
    pub id: Individual,
    pub add: ShareKey,
    pub replaces: BTreeSet<Hash<Signed<Update>>>, // NOTE: This way avoids cycles
}

// FIXME replace with Serde
impl From<Update> for Vec<u8> {
    fn from(update: Update) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&update.id.as_bytes());
        bytes.extend_from_slice(&update.add.0.to_bytes());

        for replace in update.replaces {
            bytes.extend_from_slice(&replace.as_bytes());
        }

        bytes
    }
}
