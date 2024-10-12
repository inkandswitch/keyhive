use super::{
    document::Document, group::Group, identifier::Identifier, individual::Individual,
    traits::Verifiable,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Agent<'a, T: std::hash::Hash + Clone> {
    Individual(Individual),
    Group(Group<'a, T>),
    Document(Document<'a, T>),
}

impl<'a, T: std::hash::Hash + Clone> std::fmt::Display for Agent<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Agent::Individual(i) => i.fmt(f),
            Agent::Group(g) => g.fmt(f),
            Agent::Document(d) => d.fmt(f),
        }
    }
}

impl<'a, T: std::hash::Hash + Clone> Agent<'a, T> {
    pub fn id(&self) -> Identifier {
        match self {
            Agent::Individual(i) => i.id,
            Agent::Group(g) => g.id(),
            Agent::Document(d) => d.id(),
        }
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Individual> for Agent<'a, T> {
    fn from(s: Individual) -> Self {
        Agent::Individual(s)
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Group<'a, T>> for Agent<'a, T> {
    fn from(g: Group<'a, T>) -> Self {
        Agent::Group(g)
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Document<'a, T>> for Agent<'a, T> {
    fn from(d: Document<'a, T>) -> Self {
        Agent::Document(d)
    }
}

impl<'a, T: std::hash::Hash + Clone> Verifiable for Agent<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Individual(i) => i.verifying_key(),
            Agent::Group(g) => g.verifying_key(),
            Agent::Document(d) => d.verifying_key(),
        }
    }
}
