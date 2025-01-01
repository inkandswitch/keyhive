// FIXME move to Group

use super::delegation::{Delegation, StaticDelegation};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::ed_signer::EdSigner},
    principal::{
        agent::AgentId,
        document::{id::DocumentId, Document},
        identifier::Identifier,
    },
};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation<T: ContentRef, S: EdSigner> {
    pub(crate) revoke: Rc<Signed<Delegation<T, S>>>,
    pub(crate) proof: Option<Rc<Signed<Delegation<T, S>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, (Rc<RefCell<Document<T, S>>>, Vec<T>)>,
}

impl<T: ContentRef, S: EdSigner> Revocation<T, S> {
    // FIXME MemberedId
    pub fn subject(&self) -> Identifier {
        self.revoke.subject()
    }

    pub fn revoked(&self) -> &Rc<Signed<Delegation<T, S>>> {
        &self.revoke
    }

    pub fn revoked_id(&self) -> AgentId {
        self.revoke.payload().delegate.agent_id()
    }

    pub fn proof(&self) -> Option<Rc<Signed<Delegation<T, S>>>> {
        self.proof.dupe()
    }

    pub fn after(
        &self,
    ) -> (
        Vec<Rc<Signed<Delegation<T, S>>>>,
        Vec<Rc<Signed<Revocation<T, S>>>>,
        &BTreeMap<DocumentId, (Rc<RefCell<Document<T, S>>>, Vec<T>)>,
    ) {
        let mut dlgs = vec![self.revoke.dupe()];
        if let Some(dlg) = &self.proof {
            dlgs.push(dlg.clone());
        }

        (dlgs, vec![], &self.after_content)
    }
}

impl<T: ContentRef, S: EdSigner> Signed<Revocation<T, S>> {
    pub fn subject(&self) -> Identifier {
        self.payload().subject()
    }
}

impl<T: ContentRef, S: EdSigner> std::hash::Hash for Revocation<T, S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revoke.hash(state);
        self.proof.hash(state);

        let mut vec = self.after_content.iter().collect::<Vec<_>>();
        vec.sort_by_key(|(doc_id, _)| *doc_id);

        for (doc_id, (_, cs)) in vec.iter() {
            (doc_id, cs).hash(state);
        }
    }
}

impl<T: ContentRef, S: EdSigner> Serialize for Revocation<T, S> {
    fn serialize<Ser: serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
        StaticRevocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticRevocation<T: ContentRef> {
    /// The [`Delegation`] being revoked.
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    /// Proof that the revoker is allowed to perform this revocation.
    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,

    /// The heads of relevant [`Document`] content at time of revocation.
    pub after_content: BTreeMap<Identifier, Vec<T>>,
}

impl<T: ContentRef, S: EdSigner> From<Revocation<T, S>> for StaticRevocation<T> {
    fn from(revocation: Revocation<T, S>) -> Self {
        Self {
            revoke: Digest::hash(revocation.revoke.as_ref()).coerce(),
            proof: revocation.proof.map(|p| Digest::hash(p.as_ref()).coerce()),
            after_content: BTreeMap::from_iter(
                revocation
                    .after_content
                    .into_iter()
                    .map(|(doc_id, (_, content))| (Identifier::from(doc_id), content)),
            ),
        }
    }
}
