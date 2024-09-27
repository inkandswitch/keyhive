use super::document::Document;
use super::group::Group;
use super::identifier::Identifier;
use super::individual::Individual;
use super::traits::Verifiable;
use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agent {
    Individual(Individual),
    Group(Group),
    Document(Document),
}

impl std::fmt::Display for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Agent::Individual(i) => i.fmt(f),
            Agent::Group(g) => g.fmt(f),
            Agent::Document(d) => d.fmt(f),
        }
    }
}

impl Agent {
    pub fn id(&self) -> Identifier {
        match self {
            Agent::Individual(i) => i.id,
            Agent::Group(g) => g.id(),
            Agent::Document(d) => d.id(),
        }
    }
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
