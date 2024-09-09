use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::BTreeMap;

pub mod access;
pub mod agent;

use crate::{
    access::{Access, Admin, Append, Pull, Read},
    agent::{document::Document, stateful::Stateful, stateless::Stateless, Agent},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentAgent {
    verifier: VerifyingKey,
    signer: SigningKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Op();

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Store(pub BTreeMap<Agent, Capability>);

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
