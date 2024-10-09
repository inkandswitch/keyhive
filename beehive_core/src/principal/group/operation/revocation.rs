// FIXME move to Group

use super::delegation::Delegation;
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::individual::Individual;
use crate::principal::membered::MemberedId;
use crate::principal::traits::Verifiable;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revocation {
    // FIXME should be the specific cap, not user?
    pub subject: MemberedId,
    pub revoker: Individual,
    pub revoke: Signed<Delegation>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: Signed<Delegation>,
}

impl Revocation {
    pub fn revoked_agent(&self) -> &Agent {
        &self.revoke.payload.delegate
    }
}

impl From<Revocation> for Vec<u8> {
    fn from(revocation: Revocation) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&revocation.subject.verifying_key().to_bytes());
        bytes.extend_from_slice(&revocation.revoker.verifying_key().to_bytes());
        bytes.extend_from_slice(Vec::<u8>::from(revocation.revoke).as_slice());
        bytes.extend_from_slice(Vec::<u8>::from(revocation.proof).as_slice());
        bytes
    }
}
