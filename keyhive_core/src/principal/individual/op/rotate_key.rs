use crate::crypto::share_key::ShareKey;
use dupe::Dupe;
use serde::{Deserialize, Serialize};

/// Retire a prekey and replace it with a new one.
#[derive(Debug, Clone, Dupe, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct RotateKeyOp {
    /// The prekey to remove.
    pub old: ShareKey,

    /// The prekey that repalces the old one.
    pub new: ShareKey,
}
