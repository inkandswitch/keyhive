use super::traits::Verifiable;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    verifier: VerifyingKey,
    signer: SigningKey,
}

impl PartialOrd for Active {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

impl Ord for Active {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}

impl Verifiable for Active {
    fn verifying_key(&self) -> VerifyingKey {
        self.verifier
    }
}

impl Signer<Signature> for Active {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signer.try_sign(message)
    }
}
