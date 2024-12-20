use crate::crypto::share_key::ShareKey;
use serde::{Deserialize, Serialize};

/// Retire a prekey and replace it with a new one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RotateKeyOp {
    /// The prekey to remove.
    pub old: ShareKey,

    /// The prekey that repalces the old one.
    pub new: ShareKey,
}
