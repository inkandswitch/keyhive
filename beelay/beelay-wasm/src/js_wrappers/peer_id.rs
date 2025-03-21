use std::str::FromStr;

use beelay_core::PeerId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S: Serializer>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error> {
    peer_id.to_string().serialize(serializer)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PeerId, D::Error> {
    let s = String::deserialize(deserializer)?;
    PeerId::from_str(&s).map_err(serde::de::Error::custom)
}
