use super::document::Document;
use super::group::Group;
use super::stateless::Stateless;
use super::traits::Verifiable;
use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agent {
    Stateless(Stateless),
    Stateful(Group),
    Document(Document),
}

impl From<Stateless> for Agent {
    fn from(s: Stateless) -> Self {
        Agent::Stateless(s)
    }
}

impl From<Group> for Agent {
    fn from(g: Group) -> Self {
        Agent::Stateful(g)
    }
}

impl From<Document> for Agent {
    fn from(d: Document) -> Self {
        Agent::Document(d)
    }
}

impl Verifiable for Agent {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Stateless(s) => s.verifying_key(),
            Agent::Stateful(s) => s.verifying_key(),
            Agent::Document(d) => d.verifying_key(),
        }
    }
}
