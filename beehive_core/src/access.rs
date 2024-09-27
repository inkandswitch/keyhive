// #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct Admin;
//
// #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct Append {}
//
// #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct Read;
//
// #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct Pull;

use serde::{Deserialize, Serialize};
use std::fmt;

// FIXME to and froms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Access {
    Pull,
    Read,
    Write,
    Admin, // FIXME revoker? also: remember that agents MUSY be able to revoke themselevs to do things like key rotation
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

// FIXME consider
//
// pull < read < write  < admin
//        read < revoke < admin
//
// auth graph:    pull, revoke/admin
// content graph: pull, read, write, admin

// pub enum DocAccess {
//     Read,
//     Write,
// }
//
// pub enum AuthAccess {
//     Delegate, // FIXME remove Delagete, because you should always be able to do this
//     Revoke,
// }
