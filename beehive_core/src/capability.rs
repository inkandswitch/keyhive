use crate::access::Access;
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::group::operation::delegation::Delegation;
use crate::principal::membered::Membered;

// FIXME needed?
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    pub subject: Membered,
    pub can: Access,

    pub delegator: Agent,
    pub delegate: Agent,

    pub proof: Signed<Delegation>,
}
