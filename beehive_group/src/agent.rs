use ed25519_dalek::{SigningKey, VerifyingKey};

pub mod document;
pub mod stateful;
pub mod stateless;
pub mod traits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Stateless, // FIXME
    Stateful,  // FIXME
    Document,  // FIXME
}

pub struct Current {
    verifier: VerifyingKey,
    signer: SigningKey,
}
