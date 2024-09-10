use super::traits::Agent;
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

impl Agent for Stateless {
    fn public_key(&self) -> [u8; 32] {
        self.verifier.to_bytes()
    }
}
