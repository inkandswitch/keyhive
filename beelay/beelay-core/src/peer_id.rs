use std::str::FromStr;

use ed25519_dalek::VerifyingKey;

use crate::hex;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct PeerId(VerifyingKey);

impl PeerId {
    pub(crate) fn as_key(&self) -> &VerifyingKey {
        &self.0
    }
}

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for PeerId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let secret = u.arbitrary::<[u8; 32]>()?;
        let signing_key = ed25519_dalek::SigningKey::from(secret);
        Ok(PeerId(signing_key.verifying_key()))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for PeerId {
    type Err = error::InvalidPeerId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| error::InvalidPeerId)?;
        let bytes = <[u8; 32]>::try_from(bytes).map_err(|_| error::InvalidPeerId)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| error::InvalidPeerId)?;
        Ok(PeerId(key))
    }
}

impl<'a> TryFrom<&'a [u8]> for PeerId {
    type Error = error::InvalidPeerId;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::try_from(value).map_err(|_| error::InvalidPeerId)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| error::InvalidPeerId)?;
        Ok(PeerId(key))
    }
}

impl From<ed25519_dalek::VerifyingKey> for PeerId {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        PeerId(value)
    }
}

pub(crate) mod error {

    pub struct InvalidPeerId;

    impl std::fmt::Display for InvalidPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid peer id")
        }
    }

    impl std::fmt::Debug for InvalidPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidPeerId {}
}
