use beelay_core::contact_card::ContactCard;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S>(contact_card: &ContactCard, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(contact_card.to_hex_string().as_str())
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<ContactCard, D::Error> {
    let hex_string = String::deserialize(de)?;
    ContactCard::from_hex_string(&hex_string).map_err(serde::de::Error::custom)
}
