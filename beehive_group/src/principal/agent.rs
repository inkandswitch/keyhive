use super::document::Document;
use super::group::Group;
use super::individual::Individual;
use super::traits::Verifiable;
use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agent {
    Individual(Individual),
    Group(Group),
    Document(Document),
}

impl From<Individual> for Agent {
    fn from(s: Individual) -> Self {
        Agent::Individual(s)
    }
}

impl From<Group> for Agent {
    fn from(g: Group) -> Self {
        Agent::Group(g)
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
            Agent::Individual(i) => i.verifying_key(),
            Agent::Group(g) => g.verifying_key(),
            Agent::Document(d) => d.verifying_key(),
        }
    }
}
