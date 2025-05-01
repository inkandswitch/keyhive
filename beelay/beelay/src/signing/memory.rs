use std::{cell::RefCell, future::Future, rc::Rc};

use ed25519_dalek::ed25519::signature::SignerMut;
use keyhive_core::crypto::verifiable::Verifiable;

use super::Signing;

#[derive(Clone)]
pub struct MemorySigner(Rc<RefCell<ed25519_dalek::SigningKey>>);

impl MemorySigner {
    pub fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self(Rc::new(RefCell::new(key)))
    }

    pub fn generate() -> Self {
        Self::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()))
    }
}

impl Verifiable for MemorySigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.borrow().verifying_key()
    }
}

impl Signing for MemorySigner {
    type Error = ed25519_dalek::SignatureError;

    fn sign(
        &self,
        message: &[u8],
    ) -> impl Future<Output = Result<ed25519_dalek::Signature, Self::Error>> + Send {
        let result = self.0.borrow_mut().try_sign(message);
        std::future::ready(result)
    }
}
