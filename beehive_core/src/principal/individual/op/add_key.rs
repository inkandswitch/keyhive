use crate::crypto::share_key::ShareKey;
use dupe::Dupe;
use serde::{Deserialize, Serialize};

/// Add a new key to the prekeys.
#[derive(Debug, Clone, Dupe, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddKeyOp {
    /// The key to add.
    pub share_key: ShareKey,
}
