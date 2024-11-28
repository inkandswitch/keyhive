use super::{encrypted::Encrypted, secret::Secret};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Connect {
    pub client_vk: ed25519_dalek::VerifyingKey, // From signed envelope
    pub server_pk: x25519_dalek::PublicKey,
    pub encrypted_secret: Encrypted<Secret>,
}
