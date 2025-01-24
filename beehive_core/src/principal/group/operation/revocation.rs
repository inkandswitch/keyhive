// FIXME move to Group

use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{agent::id::AgentId, document::id::DocumentId, identifier::Identifier},
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation<T: ContentRef> {
    pub(crate) revoke: Rc<Signed<Delegation<T>>>,
    pub(crate) proof: Option<Rc<Signed<Delegation<T>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<T: ContentRef> Revocation<T> {
    pub fn subject_id(&self) -> Identifier {
        self.revoke.subject_id()
    }

    pub fn revoked(&self) -> &Rc<Signed<Delegation<T>>> {
        &self.revoke
    }

    pub fn revoked_id(&self) -> AgentId {
        self.revoke.payload().delegate.agent_id()
    }

    pub fn proof(&self) -> Option<Rc<Signed<Delegation<T>>>> {
        self.proof.dupe()
    }

    pub fn after(&self) -> Dependencies<T> {
        let mut delegations = vec![self.revoke.dupe()];
        if let Some(dlg) = &self.proof {
            delegations.push(dlg.clone());
        }

        Dependencies {
            delegations,
            revocations: vec![],
            content: &self.after_content,
        }
    }
}

impl<T: ContentRef> Signed<Revocation<T>> {
    pub fn subject_id(&self) -> Identifier {
        self.payload.subject_id()
    }
}

impl<T: ContentRef> std::hash::Hash for Revocation<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revoke.hash(state);
        self.proof.hash(state);

        let mut vec = self.after_content.iter().collect::<Vec<_>>();
        vec.sort_by_key(|(doc_id, _)| *doc_id);
        vec.hash(state);
    }
}

impl<T: ContentRef> Serialize for Revocation<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StaticRevocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct StaticRevocation<T: ContentRef> {
    /// The [`Delegation`] being revoked.
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    /// Proof that the revoker is allowed to perform this revocation.
    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,

    /// The heads of relevant [`Document`] content at time of revocation.
    pub after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<T: ContentRef> From<Revocation<T>> for StaticRevocation<T> {
    fn from(revocation: Revocation<T>) -> Self {
        Self {
            revoke: Digest::hash(revocation.revoke.as_ref()).into(),
            proof: revocation.proof.map(|p| Digest::hash(p.as_ref()).into()),
            after_content: revocation.after_content,
        }
    }
}
