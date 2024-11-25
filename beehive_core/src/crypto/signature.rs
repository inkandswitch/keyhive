use dupe::Dupe;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl Dupe for Signature {
    fn dupe(&self) -> Self {
        Signature(self.0)
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(signature: ed25519_dalek::Signature) -> Self {
        Signature(signature.to_bytes())
    }
}

impl From<Signature> for ed25519_dalek::Signature {
    fn from(signature: Signature) -> Self {
        ed25519_dalek::Signature::from(signature.0)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw_bytes = Vec::<u8>::deserialize(deserializer)?;
        if let Ok(bytes) = <[u8; 64]>::try_from(raw_bytes) {
            Ok(Signature(bytes))
        } else {
            Err(serde::de::Error::custom("invalid signature length"))
        }
    }
}
