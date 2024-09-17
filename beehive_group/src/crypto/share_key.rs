#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ShareKey(pub x25519_dalek::PublicKey);

impl PartialOrd for ShareKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.as_bytes().partial_cmp(&other.0.as_bytes())
    }
}

impl Ord for ShareKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(&other.0.as_bytes())
    }
}
