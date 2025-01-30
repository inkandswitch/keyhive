use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{agent::id::AgentId, document::id::DocumentId, identifier::Identifier},
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) revoke: Rc<Signed<Delegation<T, L>>>,
    pub(crate) proof: Option<Rc<Signed<Delegation<T, L>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<T: ContentRef, L: MembershipListener<T>> Revocation<T, L> {
    pub fn subject_id(&self) -> Identifier {
        self.revoke.subject_id()
    }

    pub fn revoked(&self) -> &Rc<Signed<Delegation<T, L>>> {
        &self.revoke
    }

    pub fn revoked_id(&self) -> AgentId {
        self.revoke.payload().delegate.agent_id()
    }

    pub fn proof(&self) -> Option<Rc<Signed<Delegation<T, L>>>> {
        self.proof.dupe()
    }

    pub fn after(&self) -> Dependencies<T, L> {
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

impl<T: ContentRef, L: MembershipListener<T>> Signed<Revocation<T, L>> {
    pub fn subject_id(&self) -> Identifier {
        self.payload.subject_id()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> std::hash::Hash for Revocation<T, L> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revoke.hash(state);
        self.proof.hash(state);

        let mut vec = self.after_content.iter().collect::<Vec<_>>();
        vec.sort_by_key(|(doc_id, _)| *doc_id);
        vec.hash(state);
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Serialize for Revocation<T, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StaticRevocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct StaticRevocation<T: ContentRef = [u8; 32]> {
    /// The [`Delegation`] being revoked.
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    /// Proof that the revoker is allowed to perform this revocation.
    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,

    /// The heads of relevant [`Document`] content at time of revocation.
    pub after_content: BTreeMap<DocumentId, Vec<T>>,
}

impl<T: ContentRef, L: MembershipListener<T>> From<Revocation<T, L>> for StaticRevocation<T> {
    fn from(revocation: Revocation<T, L>) -> Self {
        Self {
            revoke: Digest::hash(revocation.revoke.as_ref()).into(),
            proof: revocation.proof.map(|p| Digest::hash(p.as_ref()).into()),
            after_content: revocation.after_content,
        }
    }
}
