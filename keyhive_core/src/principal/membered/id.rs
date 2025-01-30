use crate::{
    crypto::verifiable::Verifiable,
    principal::{document::id::DocumentId, group::id::GroupId, identifier::Identifier},
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemberedId {
    GroupId(GroupId),
    DocumentId(DocumentId),
}

impl MemberedId {
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            MemberedId::GroupId(group_id) => group_id.to_bytes(),
            MemberedId::DocumentId(document_id) => document_id.to_bytes(),
        }
    }
}

impl fmt::Display for MemberedId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemberedId::GroupId(group_id) => group_id.fmt(f),
            MemberedId::DocumentId(document_id) => document_id.fmt(f),
        }
    }
}

impl Verifiable for MemberedId {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MemberedId::GroupId(group_id) => group_id.verifying_key(),
            MemberedId::DocumentId(document_id) => document_id.verifying_key(),
        }
    }
}

impl From<MemberedId> for Identifier {
    fn from(membered_id: MemberedId) -> Self {
        match membered_id {
            MemberedId::GroupId(group_id) => group_id.into(),
            MemberedId::DocumentId(document_id) => document_id.into(),
        }
    }
}

impl From<GroupId> for MemberedId {
    fn from(group_id: GroupId) -> Self {
        MemberedId::GroupId(group_id)
    }
}
