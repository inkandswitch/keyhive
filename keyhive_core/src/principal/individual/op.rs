//! Operations for updating prekeys.

pub mod add_key;
pub mod rotate_key;

use self::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
use crate::crypto::{
    share_key::ShareKey,
    signed::{Signed, VerificationError},
    verifiable::Verifiable,
};
use derive_more::{From, TryInto};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Operations for updating prekeys.
///
/// Note that the number of keys only ever increases.
/// This prevents the case where all keys are remved and the user is unable to be
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
    pub fn topsort(key_ops: HashSet<KeyOp>) -> Vec<KeyOp> {
        let mut heads: Vec<KeyOp> = vec![];
        let mut rotate_key_ops: HashMap<ShareKey, HashSet<KeyOp>> = HashMap::new();

        for key_op in key_ops.iter() {
            match key_op {
                KeyOp::Add(_add) => {
                    heads.push(key_op.dupe());
                }
                KeyOp::Rotate(rot) => {
                    rotate_key_ops
                        .entry(rot.payload.old)
                        .and_modify(|set| {
                            set.insert(key_op.dupe());
                        })
                        .or_insert(HashSet::from_iter([key_op.dupe()]));
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
