use beelay_core::DocumentId;
use serde::{Deserialize, Serializer};

pub(crate) fn serialize<S: Serializer>(
    doc_id: &DocumentId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&doc_id.to_string())
}

pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<DocumentId, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}
