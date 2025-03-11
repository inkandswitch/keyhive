//! Access levels.

use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "test_utils")]
use proptest_derive::Arbitrary;

/// Access levels for a capability.
///
/// The access levels are ordered from least to most permissive.
/// Later levels imply all earlier levels. For example, `Write` implies the ability to `Read`.
#[cfg_attr(feature = "test_utils", derive(Arbitrary))]
#[derive(
    Debug, Clone, Dupe, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum Access {
    /// The ability to retrieve bytes over the network.
    ///
    /// This is important for the defence-in-depth strategy,
    /// keeping all Keyhive data out of the hands of unauthorized actors.
    ///
    /// All encryption is fallable. For example, a key may be leaked, or a cipher may be broken.
    ///
    /// While a Byzantine node may fail to enforce this rule,
    /// a node with only `Pull` access does not have decryption (`Read`) access
    /// to the underlying data.
    Pull,

    /// The ability to read (decrypt) the content of a document.
    Read,

    /// The ability to write (append ops to) the content of a document.
    Write,

    /// The ability to revoke any members of a group, not just those that they have causal senority over.
    Admin,
}

impl Access {
    pub fn is_reader(self) -> bool {
        self >= Access::Read
    }

    pub fn is_writer(self) -> bool {
        self >= Access::Write
    }
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
