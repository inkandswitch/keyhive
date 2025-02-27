use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::group::{delegation::StaticDelegation, id::GroupId, revocation::StaticRevocation},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStateArchive<T: ContentRef> {
    pub id: GroupId,
    pub delegation_heads: HashSet<Digest<Signed<StaticDelegation<T>>>>,
    pub revocation_heads: HashSet<Digest<Signed<StaticRevocation<T>>>>,
}
