use ed25519_dalek::{SigningKey, VerifyingKey};

pub mod document;
pub mod stateful;
pub mod stateless;
pub mod traits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agentic {
    Stateless, // FIXME
    Stateful,  // FIXME
    Document,  // FIXME
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    verifier: VerifyingKey,
    signer: SigningKey,
}
