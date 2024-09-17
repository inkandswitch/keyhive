#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Admin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Append {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pull;

// FIXME to and froms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Access {
    Pull,
    Read,
    Write,
    Admin, // FIXME revoker? also: remember that agents MUSY be able to revoke themselevs to do things like key rotation
}

// FIXME consider
//
// pull < read < write  < admin
//        read < revoke < admin
//
// auth graph:    pull, revoke/admin
// content graph: pull, read, write, admin

pub enum DocAccess {
    Read,
    Write,
}

pub enum AuthAccess {
    Delegate, // FIXME remove Delagete, because you should always be able to do this
    Revoke,
}

pub enum OtherAccess {
    Doc {
        doc: crate::principal::document::Document,
        access: DocAccess,
    },
    Auth {
        group: crate::principal::group::Group,
        access: AuthAccess,
    },
    Pull {
        group: crate::principal::group::Group,
    },
}
