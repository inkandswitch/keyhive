//! Operations for updating prekeys.

pub mod add_key;
pub mod rotate_key;

use self::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
use crate::util::content_addressed_map::CaMap;
use derive_more::{From, TryInto};
use dupe::Dupe;
use ed25519_dalek::{Signature, VerifyingKey};
use keyhive_crypto::{
    id::Id,
    share_key::ShareKey,
    signed::{Signed, VerificationError},
    verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Operations for updating prekeys.
///
/// Note that the number of keys only ever increases.
/// This prevents the case where all keys are removed and the user is unable to be
/// added to a [`Cgka`][crate::cgka::Cgka].
#[derive(Debug, Clone, Dupe, PartialEq, Eq, Hash, Serialize, Deserialize, From, TryInto)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum KeyOp {
    /// Add a new key.
    Add(Arc<Signed<AddKeyOp>>),

    /// Retire and replace an existing key.
    Rotate(Arc<Signed<RotateKeyOp>>),
}

impl KeyOp {
    pub fn new_key(&self) -> &ShareKey {
        match self {
            KeyOp::Add(add) => &add.payload.share_key,
            KeyOp::Rotate(rot) => &rot.payload.new,
        }
    }

    pub fn try_verify(&self) -> Result<(), VerificationError> {
        match self {
            KeyOp::Add(add) => add.try_verify(),
            KeyOp::Rotate(rot) => rot.try_verify(),
        }
    }

    pub fn issuer(&self) -> &Id {
        match self {
            KeyOp::Add(add) => &add.issuer,
            KeyOp::Rotate(rot) => &rot.issuer,
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            KeyOp::Add(add) => &add.signature,
            KeyOp::Rotate(rot) => &rot.signature,
        }
    }
}

impl Verifiable for KeyOp {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            KeyOp::Add(add) => add.verifying_key(),
            KeyOp::Rotate(rot) => rot.verifying_key(),
        }
    }
}

/// Key ops grouped by the identifier they belong to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOps(HashMap<Id, Vec<Arc<KeyOp>>>);

impl KeyOps {
    /// The ops belonging to `id`.
    pub fn get(&self, id: &Id) -> Option<&[Arc<KeyOp>]> {
        self.0.get(id).map(Vec::as_slice)
    }

    /// The identifiers that have ops.
    pub fn keys(&self) -> impl Iterator<Item = &Id> {
        self.0.keys()
    }

    /// The ops for each identifier.
    pub fn values(&self) -> impl Iterator<Item = &[Arc<KeyOp>]> {
        self.0.values().map(Vec::as_slice)
    }
}

impl From<HashMap<Id, CaMap<KeyOp>>> for KeyOps {
    fn from(by_id: HashMap<Id, CaMap<KeyOp>>) -> Self {
        KeyOps(
            by_id
                .into_iter()
                .map(|(id, ops)| (id, ops.into_values().collect()))
                .collect(),
        )
    }
}

impl IntoIterator for KeyOps {
    type Item = (Id, Vec<Arc<KeyOp>>);
    type IntoIter = std::collections::hash_map::IntoIter<Id, Vec<Arc<KeyOp>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Reachable prekey ops for all principals, with shared storage.
///
/// Instead of duplicating key ops across principals, the ops are stored
/// once in `ops` and each principal has an index into that shared map.
#[derive(Debug)]
pub struct AllReachablePrekeyOps {
    /// Key ops per identifier, computed once.
    pub ops: KeyOps,

    /// For each principal: the set of identifiers whose ops in `ops` are reachable, plus
    /// members it can no longer reach whose keys still help verify the history it is
    /// sent.
    pub index: HashMap<Id, HashSet<Id>>,
}

impl AllReachablePrekeyOps {
    /// Returns the set of principal identifiers that have reachable ops.
    pub fn agents(&self) -> impl Iterator<Item = &Id> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable [`KeyOp`]s for the given principal
    /// (flattened across all source identifiers), or `None` if the principal is not
    /// in the index.
    pub fn ops_for_agent(&self, agent_id: &Id) -> Option<impl Iterator<Item = &Arc<KeyOp>>> {
        self.index
            .get(agent_id)
            .map(|ids| ids.iter().filter_map(|id| self.ops.get(id)).flatten())
    }
}
