use crate::principal::agent::Agent;
use crate::principal::stateless::Stateless;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Revocation {
    // FIXME should be the specific cap, not user?
    pub kicker: Stateless,
    pub kickee: Agent,
}
