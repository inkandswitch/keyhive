use ed25519_dalek::{SigningKey, VerifyingKey};

pub mod document;
pub mod stateful;
pub mod stateless;
pub mod traits;

use document::Document;
use stateful::Stateful;
use stateless::Stateless;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agentic {
    Stateless, // FIXME
    Stateful,  // FIXME
    Document,  // FIXME
}

impl From<Stateless> for Agentic {
    fn from(_: Stateless) -> Self {
        Agentic::Stateless
    }
}

impl From<Stateful> for Agentic {
    fn from(_: Stateful) -> Self {
        Agentic::Stateful
    }
}

impl From<Document> for Agentic {
    fn from(_: Document) -> Self {
        Agentic::Document
    }
}

// FIXME rename Active or Signer or something
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    verifier: VerifyingKey,
    signer: SigningKey,
}

impl PartialOrd for Current {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

impl Ord for Current {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}
