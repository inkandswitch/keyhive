use blake3::Hash;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stateless {
    verifier: VerifyingKey,
}

// FIXME needed?
impl PartialOrd for Stateless {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

impl Ord for Stateless {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentAgent {
    verifier: VerifyingKey,
    signer: SigningKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Op();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stateful {
    verifier: VerifyingKey,
    state: BTreeMap<Hash, Op>,
}

impl PartialOrd for Stateful {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

pub trait Agent {
    fn public_key(&self) -> [u8; 32];
}

impl Agent for Stateless {
    fn public_key(&self) -> [u8; 32] {
        self.verifier.to_bytes()
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capability {
    // delegate: &Agent,
    subject: Stateless, // FIXME rename to ID
    can: Access,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum Agentic {
    Stateless(Stateless),
    Stateful(Stateful),
    Document(Document),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Store(pub BTreeMap<Agentic, Capability>);

pub enum BeehiveOp {
    Delegate {
        who: VerifyingKey,
        what: Capability,
    },

    RevokeAgent {
        // FIXME should be the specific cap, not user?
        who: VerifyingKey,
    },
}

/// Materialized gorup
pub struct Group {
    pub id: VerifyingKey,
    pub delegates: BTreeMap<VerifyingKey, Access>,
}

// FIXME switch to a trait
// impl Agent {
//     fn get_caps(&self) -> BTreeMap<Agentic, Capability> {
//         todo!()
//     }
// }

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Document {
    pub auth: Stateful,
    pub content: Vec<u8>, // FIXME automerge content
}
