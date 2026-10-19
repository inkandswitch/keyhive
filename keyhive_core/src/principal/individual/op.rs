//! Operations for updating prekeys.

pub mod add_key;
pub mod rotate_key;

use self::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
use crate::util::content_addressed_map::CaMap;
use derive_more::{From, TryInto};
use dupe::Dupe;
use keyhive_crypto::{
    identifier::Identifier,
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

    pub fn issuer(&self) -> Identifier {
        match self {
            KeyOp::Add(add) => add.issuer,
            KeyOp::Rotate(rot) => rot.issuer,
        }
    }

    pub fn signature(&self) -> &ed25519_dalek::Signature {
        match self {
            KeyOp::Add(add) => &add.signature,
            KeyOp::Rotate(rot) => &rot.signature,
        }
    }
}

impl Verifiable for KeyOp {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            KeyOp::Add(add) => add.verifying_key(),
            KeyOp::Rotate(rot) => rot.verifying_key(),
        }
    }
}

/// Key ops grouped by the identifier they belong to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOps(HashMap<Identifier, Vec<Arc<KeyOp>>>);

impl KeyOps {
    /// The ops belonging to `id`.
    pub fn get(&self, id: &Identifier) -> Option<&[Arc<KeyOp>]> {
        self.0.get(id).map(Vec::as_slice)
    }

    /// The identifiers that have ops.
    pub fn keys(&self) -> impl Iterator<Item = &Identifier> {
        self.0.keys()
    }

    /// The ops for each identifier.
    pub fn values(&self) -> impl Iterator<Item = &[Arc<KeyOp>]> {
        self.0.values().map(Vec::as_slice)
    }
}

impl From<HashMap<Identifier, CaMap<KeyOp>>> for KeyOps {
    fn from(by_id: HashMap<Identifier, CaMap<KeyOp>>) -> Self {
        KeyOps(
            by_id
                .into_iter()
                .map(|(id, ops)| (id, ops.into_values().collect()))
                .collect(),
        )
    }
}

impl IntoIterator for KeyOps {
    type Item = (Identifier, Vec<Arc<KeyOp>>);
    type IntoIter = std::collections::hash_map::IntoIter<Identifier, Vec<Arc<KeyOp>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Reachable prekey ops for all agents, with shared storage.
///
/// Instead of duplicating key ops across agents, the ops are stored
/// once in `ops` and each agent has an index into that shared map.
#[derive(Debug)]
pub struct AllReachablePrekeyOps {
    /// Key ops per identifier, computed once.
    pub ops: KeyOps,

    /// For each agent, the identifiers in `ops` whose prekey ops it is sent: its own
    /// plus every agent referenced by the membership and CGKA ops it is sent.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

impl AllReachablePrekeyOps {
    /// Returns the set of agent identifiers that have reachable ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable [`KeyOp`]s for the given agent
    /// (flattened across all source identifiers), or `None` if the agent is not
    /// in the index.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<impl Iterator<Item = &Arc<KeyOp>>> {
        self.index
            .get(agent_id)
            .map(|ids| ids.iter().filter_map(|id| self.ops.get(id)).flatten())
    }
}
