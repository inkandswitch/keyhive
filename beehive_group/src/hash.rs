#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hash(pub blake3::Hash);

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.as_bytes().cmp(&other.0.as_bytes()))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(&other.0.as_bytes())
    }
}
