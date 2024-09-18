use crate::access::Access;
use crate::crypto::signed::Signed;
use crate::operation::delegation::Delegation;
use crate::principal::agent::Agent;
use crate::principal::membered::Membered;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    pub subject: Membered,
    pub can: Access,

    pub delegator: Agent,
    pub delegate: Agent,

    pub proof: Signed<Delegation>,
}
