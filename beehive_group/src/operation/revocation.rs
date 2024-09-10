use crate::agent::stateless::Stateless;
use crate::agent::Agentic;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Revocation {
    // FIXME should be the specific cap, not user?
    pub kicker: Stateless,
    pub kickee: Agentic,
}
