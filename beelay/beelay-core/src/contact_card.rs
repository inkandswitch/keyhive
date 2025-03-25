use crate::{serialization::hex, PeerId};

#[derive(Debug, Clone, Hash)]
pub struct ContactCard(pub(crate) keyhive_core::contact_card::ContactCard);

impl ContactCard {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        bincode::serialize_into(&mut out, &self.0).unwrap();
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let card = bincode::deserialize(bytes).map_err(|e| ParseError(e.to_string()))?;
        Ok(ContactCard(card))
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    pub fn from_hex_string(s: &str) -> Result<Self, ParseError> {
        let bytes = hex::decode(s).map_err(|e| ParseError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.0.id().0 .0)
    }
}

impl std::fmt::Display for ContactCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to parse contact card: {0}")]
pub struct ParseError(String);
