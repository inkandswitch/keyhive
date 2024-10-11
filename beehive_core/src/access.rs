//! Access levels.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Access levels for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Access {
    /// The ability to retrieve bytes over the network.
    Pull,

    /// The ability to read (decrypt) the content of a document.
    Read,

    /// The ability to write (append ops to) the content of a document.
    Write,

    /// The ability to revoke any members of a group, not just those that they have causal senority over.
    Admin,
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Access::Pull => write!(f, "Pull"),
            Access::Read => write!(f, "Read"),
            Access::Write => write!(f, "Write"),
            Access::Admin => write!(f, "Admin"),
        }
    }
}
