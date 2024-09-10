use super::document::Document;
use super::stateful::Stateful;
use super::stateless::Stateless;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agent {
    Stateless, // FIXME
    Stateful,  // FIXME
    Document,  // FIXME
}

impl From<Stateless> for Agent {
    fn from(_: Stateless) -> Self {
        Agent::Stateless
    }
}

impl From<Stateful> for Agent {
    fn from(_: Stateful) -> Self {
        Agent::Stateful
    }
}

impl From<Document> for Agent {
    fn from(_: Document) -> Self {
        Agent::Document
    }
}
