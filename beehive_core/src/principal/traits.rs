// FIXME rename module?

use super::identifier::Identifier;

pub trait Verifiable {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;

    fn id(&self) -> Identifier {
        Identifier(self.verifying_key())
    }
}
