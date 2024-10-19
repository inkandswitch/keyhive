use crate::crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
};
use crate::util::content_addressed_map::CaMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyState {
    pub ops: CaMap<Signed<KeyOp>>,
    pub keypairs: HashMap<ShareKey, ShareSecretKey>,
}

impl PrekeyState {
    pub fn new() -> Self {
        Self {
            ops: CaMap::new(),
            keypairs: HashMap::new(),
        }
    }

    pub fn generate(signing_key: &ed25519_dalek::SigningKey, size: usize) -> Self {
        let mut keypairs = HashMap::new();
        let mut ops = CaMap::new();

        for _ in 0..size {
            let secret_key = ShareSecretKey::generate();
            let share_key = secret_key.share_key();

            let op = Signed::sign(KeyOp::Add(AddKeyOp { share_key }), &signing_key);
            ops.insert(op);
            keypairs.insert(share_key, secret_key);
        }

        Self { ops, keypairs }
    }

    pub fn materialize(&self) -> HashSet<ShareKey> {
        let mut keys = HashSet::new();
        let mut to_drop = vec![];

        for signed in self.ops.values() {
            match signed.payload() {
                KeyOp::Add(AddKeyOp { share_key, .. }) => {
                    keys.insert(*share_key);
                }
                KeyOp::Update(ShareKeyOp { old, new }) => {
                    to_drop.push(old);
                    keys.insert(*new);
                }
            }
        }

        for tombstone in to_drop {
            keys.remove(&tombstone);
        }

        keys
    }
}

impl std::hash::Hash for PrekeyState {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ops.hash(state);
        BTreeSet::from_iter(self.keypairs.iter()).hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyOp {
    Add(AddKeyOp),
    Update(ShareKeyOp),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddKeyOp {
    pub share_key: ShareKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareKeyOp {
    pub old: ShareKey,
    pub new: ShareKey,
}
