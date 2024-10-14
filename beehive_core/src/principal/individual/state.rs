use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::util::content_addressed_map::CaMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyState {
    pub ops: CaMap<Signed<KeyOp>>,
}

impl PrekeyState {
    pub fn new() -> Self {
        Self { ops: CaMap::new() }
    }

    pub fn materialize(&self) -> BTreeSet<ShareKey> {
        let mut keys = BTreeSet::new();
        let mut to_drop = vec![];

        for Signed { payload, .. } in self.ops.clone().into_values() {
            match payload {
                KeyOp::Add(AddKeyOp { key }) => {
                    keys.insert(key.clone());
                }
                KeyOp::Update(ShareKeyOp { old, new }) => {
                    to_drop.push(old.clone());
                    keys.insert(new.clone());
                }
            }
        }

        for tombstone in to_drop {
            keys.remove(&tombstone);
        }

        keys
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyOp {
    Add(AddKeyOp),
    Update(ShareKeyOp),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddKeyOp {
    pub key: ShareKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareKeyOp {
    pub old: ShareKey,
    pub new: ShareKey,
}
