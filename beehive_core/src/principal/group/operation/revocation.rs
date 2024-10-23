// FIXME move to Group

use super::delegation::{Delegation, StaticDelegation};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{
        agent::AgentId,
        document::{id::DocumentId, Document},
        identifier::Identifier,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation<T: ContentRef> {
    pub(crate) revoke: Rc<Signed<Delegation<T>>>,
    pub(crate) proof: Option<Rc<Signed<Delegation<T>>>>,
    pub(crate) after_content: BTreeMap<DocumentId, (Rc<Document<T>>, Vec<T>)>,
}

impl<T: ContentRef> Revocation<T> {
    // FIXME MemberedId
    pub fn subject(&self) -> Identifier {
        self.revoke.subject()
    }

    pub fn revoked_id(&self) -> AgentId {
        self.revoke.payload().delegate.agent_id()
    }

    pub fn after(
        &self,
    ) -> (
        Vec<Rc<Signed<Delegation<T>>>>,
        Vec<Rc<Signed<Revocation<T>>>>,
        &BTreeMap<DocumentId, (Rc<Document<T>>, Vec<T>)>,
    ) {
        (vec![self.revoke.clone()], vec![], &self.after_content)
    }
}

impl<T: ContentRef> Signed<Revocation<T>> {
    pub fn subject(&self) -> Identifier {
        self.payload().subject()
    }
}

// FIXME test
// impl<'a, T: ContentRef> PartialOrd for Revocation<'a, T> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         match self.revoke.partial_cmp(&other.revoke) {
//             Some(std::cmp::Ordering::Equal) => match self.proof.partial_cmp(&other.proof) {
//                 Some(std::cmp::Ordering::Equal) => self
//                     .after_content
//                     .iter()
//                     .zip(other.after_content.iter())
//                     .fold(
//                         Some(std::cmp::Ordering::Equal),
//                         |acc, ((doc_id1, content1), (doc_id2, content2))| {
//                             if let Some(std::cmp::Ordering::Equal) = acc {
//                                 match doc_id1.partial_cmp(&doc_id2) {
//                                     Some(std::cmp::Ordering::Equal) => {
//                                         content1.1.iter().zip(content2.1.iter()).fold(
//                                             Some(std::cmp::Ordering::Equal),
//                                             |acc, (content1, content2)| {
//                                                 if let Some(std::cmp::Ordering::Equal) = acc {
//                                                     content1.partial_cmp(content2)
//                                                 } else {
//                                                     acc
//                                                 }
//                                             },
//                                         )
//                                     }
//                                     other => other,
//                                 }
//                             } else {
//                                 acc
//                             }
//                         },
//                     ),
//                 other => other,
//             },
//             other => other,
//         }
//     }
// }
//
// impl<'a, T: ContentRef> Ord for Revocation<'a, T> {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.partial_cmp(other).unwrap()
//     }
// }

impl<T: ContentRef> std::hash::Hash for Revocation<T> {
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

impl<T: ContentRef> Serialize for Revocation<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // FIXME could be a heavy clone since this is used to hash
        StaticRevocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticRevocation<T: ContentRef> {
    pub revoke: Digest<Signed<StaticDelegation<T>>>,

    // FIXME probably will just make this look at the ambient state,
    // but in the meantime this is just so much easier
    pub proof: Option<Digest<Signed<StaticDelegation<T>>>>,

    pub after_content: BTreeMap<Identifier, Vec<T>>,
}

impl<T: ContentRef> From<Revocation<T>> for StaticRevocation<T> {
    fn from(revocation: Revocation<T>) -> Self {
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
