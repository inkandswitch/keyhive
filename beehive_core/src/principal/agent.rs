use super::{
    document::Document, group::Group, identifier::Identifier, individual::Individual,
    traits::Verifiable,
};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Agent<'a, T: Clone + Ord + Serialize> {
    Individual(Individual),
    Group(Group<'a, T>),
    Document(Document<'a, T>),
}

impl<'a, T: Clone + Ord + Serialize> Agent<'a, T> {
    pub fn id(&self) -> Identifier {
        match self {
            Agent::Individual(i) => i.id,
            Agent::Group(g) => g.id(),
            Agent::Document(d) => d.id(),
        }
    }
}

impl<'a, T: Clone + Ord + Serialize> From<Individual> for Agent<'a, T> {
    fn from(s: Individual) -> Self {
        Agent::Individual(s)
    }
}

impl<'a, T: Clone + Ord + Serialize> From<Group<'a, T>> for Agent<'a, T> {
    fn from(g: Group<'a, T>) -> Self {
        Agent::Group(g)
    }
}

impl<'a, T: Clone + Ord + Serialize> From<Document<'a, T>> for Agent<'a, T> {
    fn from(d: Document<'a, T>) -> Self {
        Agent::Document(d)
    }
}

impl<'a, T: Clone + Ord + Serialize> Verifiable for Agent<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Individual(i) => i.verifying_key(),
            Agent::Group(g) => g.verifying_key(),
            Agent::Document(d) => d.verifying_key(),
        }
    }
}
