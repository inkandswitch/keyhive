use std::str::FromStr;

use beelay_core::{DocumentId, PeerId};
use serde::Deserialize;

use crate::{KeyhiveEntity, Membered};

pub(crate) struct RemoveMemberArgs {
    pub(crate) membered: Membered,
    pub(crate) member: KeyhiveEntity,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Raw {
    group_id: Option<String>,
    doc_id: Option<String>,
    member: KeyhiveEntity,
}

impl<'de> Deserialize<'de> for RemoveMemberArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = Raw::deserialize(deserializer)?;
        let group = match raw.group_id {
            Some(id_str) => Some(
                PeerId::from_str(&id_str)
                    .map_err(|e| serde::de::Error::custom(format!("Invalid group ID: {}", e)))?,
            ),
            None => None,
        };
        let doc = match raw.doc_id {
            Some(id_str) => Some(
                DocumentId::from_str(&id_str)
                    .map_err(|e| serde::de::Error::custom(format!("Invalid document ID: {}", e)))?,
            ),
            None => None,
        };
        let membered = match (doc, group) {
            (Some(_), Some(_)) => Err(serde::de::Error::custom(
                "Cannot specify both group and document",
            )),
            (Some(doc), None) => Ok(Membered::Document(doc)),
            (None, Some(group)) => Ok(Membered::Group(group)),
            (None, None) => Err(serde::de::Error::custom(
                "Must specify either groupId or docId",
            )),
        }?;
        Ok(RemoveMemberArgs {
            membered,
            member: raw.member,
        })
    }
}
