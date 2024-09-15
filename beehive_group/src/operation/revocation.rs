use crate::hash::Hash;
use crate::principal::agent::Agent;
use crate::principal::stateful::Stateful;
use crate::principal::stateless::Stateless;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revocation {
    // FIXME should be the specific cap, not user?
    pub subject: Stateful,
    pub revoker: Stateless,
    pub revoke: Hash<super::delegation::Delegation>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: Hash<super::delegation::Delegation>,
}
