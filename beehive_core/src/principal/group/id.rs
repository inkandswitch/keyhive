use crate::principal::{identifier::Identifier, verifiable::Verifiable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupId(pub(crate) Identifier);

impl From<GroupId> for Identifier {
    fn from(group_id: GroupId) -> Identifier {
        group_id.0
    }
}

impl Verifiable for GroupId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.into()
    }
}
