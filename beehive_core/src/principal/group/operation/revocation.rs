// FIXME move to Group

use super::delegation::Delegation;
use crate::{
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::AgentId, identifier::Identifier},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct Revocation<T: Serialize> {
    pub revoke: Digest<Signed<Delegation<T>>>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: Digest<Signed<Delegation<T>>>,

    pub after_content: Vec<(Identifier, Digest<T>)>,
}

impl<T: Serialize> Revocation<T> {
    pub fn subject(&self) -> AgentId {
        todo!()
    }

    pub fn after(
        &self,
    ) -> (
        &[Digest<Signed<Delegation<T>>>],
        &[Digest<Signed<Revocation<T>>>],
        &[(Identifier, Digest<T>)],
    ) {
        (
            vec![self.revoke].as_slice(),
            &[],
            self.after_content.as_slice(),
        )
    }
}

impl<T: Serialize> PartialEq for Revocation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.revoke == other.revoke
            && self.proof == other.proof
            && self.after_content == other.after_content
    }
}

impl<T: Serialize> Eq for Revocation<T> {}

impl<T: Serialize> PartialOrd for Revocation<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.revoke.partial_cmp(&other.revoke) {
            Some(std::cmp::Ordering::Equal) => match self.proof.partial_cmp(&other.proof) {
                Some(std::cmp::Ordering::Equal) => {
                    self.after_content.partial_cmp(&other.after_content)
                }
                x => x,
            },
            x => x,
        }
    }
}
