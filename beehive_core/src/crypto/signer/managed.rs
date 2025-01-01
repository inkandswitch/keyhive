use super::{
    super::signed::{Signed, SigningError},
    ed_signer::EdSigner,
};
use crate::principal::verifiable::Verifiable;
use dupe::Dupe;
use serde::Serialize;
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedSigner<S: EdSigner> {
    Memory(ed25519_dalek::SigningKey),
    External(S),
}

impl<S: EdSigner> Hash for ManagedSigner<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Memory(m) => m.verifying_key().hash(state),
            Self::External(s) => s.hash(state),
        }
    }
}

impl<S: EdSigner> From<ed25519_dalek::SigningKey> for ManagedSigner<S> {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self::Memory(key)
    }
}

impl<S: EdSigner> Dupe for ManagedSigner<S> {
    fn dupe(&self) -> Self {
        match self {
            Self::Memory(m) => Self::Memory(m.clone()),
            Self::External(s) => Self::External(s.dupe()),
        }
    }
}

impl<S: EdSigner> ed25519_dalek::Signer<ed25519_dalek::Signature> for ManagedSigner<S> {
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError> {
        match self {
            Self::Memory(m) => m.try_sign(msg),
            Self::External(s) => s.try_sign(msg),
        }
    }
}

impl<S: EdSigner> Verifiable for ManagedSigner<S> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            Self::Memory(m) => m.verifying_key(),
            Self::External(s) => s.verifying_key(),
        }
    }
}

impl<S: EdSigner> EdSigner for ManagedSigner<S> {
    fn try_seal<T: Serialize>(&self, paylaod: T) -> Result<Signed<T>, SigningError> {
        Signed::try_sign(paylaod, self)
    }
}
