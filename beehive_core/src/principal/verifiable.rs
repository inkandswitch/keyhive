// FIXME rename module?

use super::agent::AgentId;
use serde::Serialize;

pub trait Verifiable {
    // fn id<'a, T: Clone + Ord + Serialize>(&self) -> AgentId<'a, T>;
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}
