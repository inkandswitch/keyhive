use blake3::Hash;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stateless {
    verifier: VerifingKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CurrentAgent {
    verifier: VerifyingKey,
    signer: SigningKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stateful {
    verifier: Verifier,
    state: BTreeMap<Hash, Op>,
}

pub trait Agent {
    fn public_key(&self) -> [u8; 32];
}

impl Agent for Stateless {
    fn public_key(&self) -> [u8; 32] {
        self.public_key()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Admin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Append {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pull;

// FIXME to and froms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    Pull,
    Read,
    Write(Append),
    Admin, // FIXME revoker?
}

pub struct Capability<'a> {
    // delegate: &Agent,
    subject: &'a Group,
    can: Access,
}

pub struct Store(pub BTreeMap<Agent, Capability>);

pub enum BeehiveOp<'a> {
    Delegate {
        who: PublicKey,
        what: Capability<'a>,
    },

    RevokeAgent {
        // FIXME should be the specific cap, not user?
        who: PublicKey,
    },
}

/// Materialized gorup
pub struct Group {
    pub id: PublicKey,
    pub delegates: BTreeMap<PublicKey, Delegate>,
}

// FIXME switch to a trait
impl Agent {
    fn get_caps(&self) -> BTreeMap<Agent, Capability> {
        todo!()
    }
}

pub struct Document {
    pub group: Group,
    pub content: Vec<u8>, // FIXME automerge content
}
