use std::collections::HashMap;

use crate::{commands::keyhive::MemberAccess, CommitHash, CommitOrBundle, PeerId};

/// The state of a one document
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocStatus {
    pub local_heads: Option<Vec<CommitHash>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocEvent {
    Data {
        data: CommitOrBundle,
    },
    Discovered,
    AccessChanged {
        new_access: HashMap<PeerId, MemberAccess>,
    },
}
