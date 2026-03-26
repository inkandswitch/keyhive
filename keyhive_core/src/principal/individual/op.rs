//! Operations for updating prekeys.

pub mod add_key;
pub mod rotate_key;

use self::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
use crate::{principal::identifier::Identifier, util::content_addressed_map::CaMap};
use derive_more::{From, TryInto};
use dupe::Dupe;
use keyhive_crypto::{
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
    pub fn topsort(key_ops: &CaMap<KeyOp>) -> Vec<Arc<KeyOp>> {
        let mut heads: Vec<Arc<KeyOp>> = vec![];
        let mut rotate_key_ops: HashMap<ShareKey, Vec<Arc<KeyOp>>> = HashMap::new();

        for key_op in key_ops.values() {
            match key_op.as_ref() {
                KeyOp::Add(_add) => {
                    heads.push(key_op.dupe());
                }
                KeyOp::Rotate(rot) => {
                    rotate_key_ops
                        .entry(rot.payload.old)
                        .or_default()
                        .push(key_op.dupe());
                }
            }
        }

        let mut topsorted = vec![];

        while let Some(head) = heads.pop() {
            if let Some(ops) = rotate_key_ops.get(head.new_key()) {
                for op in ops.iter() {
                    heads.push(op.dupe());
                }
            }

            topsorted.push(head.dupe());
        }

        topsorted
    }

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

    pub fn issuer(&self) -> &ed25519_dalek::VerifyingKey {
        match self {
            KeyOp::Add(add) => &add.issuer,
            KeyOp::Rotate(rot) => &rot.issuer,
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

/// Reachable prekey ops for all agents, with shared storage.
///
/// Instead of duplicating topsorted key ops across agents, the ops are stored
/// once in `ops` and each agent has an index into that shared map.
#[derive(Debug)]
pub struct AllReachablePrekeyOps {
    /// Topsorted key ops per identifier (agent, group, or doc), computed once.
    pub ops: HashMap<Identifier, Vec<Arc<KeyOp>>>,

    /// For each agent: the set of identifiers whose ops in `ops` are reachable.
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
        self.index.get(agent_id).map(|ids| {
            ids.iter()
                .filter_map(|id| self.ops.get(id))
                .flat_map(|ops| ops.iter())
        })
    }
}
