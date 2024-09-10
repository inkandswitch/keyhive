use super::traits::Identifiable;
use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stateless {
    verifier: VerifyingKey,
}

// FIXME needed?
impl PartialOrd for Stateless {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifier
            .to_bytes()
            .partial_cmp(&other.verifier.to_bytes())
    }
}

impl Ord for Stateless {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
    }
}

impl Identifiable for Stateless {
    fn id(&self) -> [u8; 32] {
        self.verifier.to_bytes()
    }
}
