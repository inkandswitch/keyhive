#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 32]);

impl From<[u8; 32]> for NodeId {
    fn from(inner: [u8; 32]) -> Self {
        NodeId(inner)
    }
}

impl From<&[u8]> for NodeId {
    fn from(s: &[u8]) -> Self {
        NodeId(blake3::hash(s).into())
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        s.as_bytes().into()
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        s.as_bytes().into()
    }
}

impl From<ed25519_dalek::VerifyingKey> for NodeId {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        NodeId(vk.to_bytes())
    }
}

impl From<&ed25519_dalek::SigningKey> for NodeId {
    fn from(sk: &ed25519_dalek::SigningKey) -> Self {
        ed25519_dalek::VerifyingKey::from(sk).into()
    }
}
