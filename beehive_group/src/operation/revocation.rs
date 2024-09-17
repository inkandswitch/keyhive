// FIXME move to Group

use crate::crypto::hash::Hash;
use crate::principal::membered::MemberedId;
use crate::principal::stateless::Stateless;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revocation {
    // FIXME should be the specific cap, not user?
    pub subject: MemberedId,
    pub revoker: Stateless,
    pub revoke: Hash<super::delegation::Delegation>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: Hash<super::delegation::Delegation>,
}
