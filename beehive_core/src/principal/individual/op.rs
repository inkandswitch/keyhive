//! Operations for updating prekeys.

pub mod add_key;
pub mod rotate_key;

use crate::crypto::share_key::ShareKey;
use dupe::Dupe;
use serde::{Deserialize, Serialize};

/// Operations for updating prekeys.
///
/// Note that the number of keys only ever increases.
/// This prevents the case where all keys are remved and the user is unable to be
/// added to a [`Cgka`][crate::cgka::Cgka].
#[derive(Debug, Clone, Dupe, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyOp {
    /// Add a new key.
    Add(add_key::AddKeyOp),

    /// Retire and replace an existing key.
    Rotate(rotate_key::RotateKeyOp),
}

impl KeyOp {
    pub fn add(share_key: ShareKey) -> Self {
        KeyOp::Add(add_key::AddKeyOp { share_key })
    }

    pub fn rotate(old: ShareKey, new: ShareKey) -> Self {
        KeyOp::Rotate(rotate_key::RotateKeyOp { old, new })
    }

    pub fn new_share_key(&self) -> ShareKey {
        match self {
            KeyOp::Add(op) => op.share_key,
            KeyOp::Rotate(op) => op.new,
        }
    }
}
