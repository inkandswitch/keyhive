//! Archive of [`Keyhive`][crate::keyhive::Keyhive].
//!
//! What a replica cannot recompute: its identity and key pairs, the
//! individuals it knows, the certificate set, every CGKA operation it holds,
//! each document's content heads, and the events still waiting. Trees are
//! rebuilt from the operations on load, as a second instance of an identity
//! builds them; group membership is the certificate set.

use crate::{
    content::heads::ContentHeads,
    event::static_event::StaticEvent,
    principal::{
        active::archive::ActiveArchive,
        document::{archive::DocumentArchive, id::DocumentId},
        individual::{id::IndividualId, IndividualState},
    },
};
use beekem::operation::CgkaOperation;
use keyhive_crypto::{content::reference::ContentRef, signed::SerdeSigned};
use keyline::certificate::Certificate;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

/// Serialized representation of [`Keyhive`][crate::keyhive::Keyhive].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Archive<T: ContentRef> {
    /// First, so that an archive in another format is refused on decode.
    pub(crate) version: ArchiveVersion,
    pub(crate) active: ActiveArchive,
    pub(crate) individuals: HashMap<IndividualId, IndividualState>,
    pub(crate) docs: HashMap<DocumentId, DocumentArchive<T>>,
    pub(crate) cgka_ops: Vec<SerdeSigned<CgkaOperation>>,
    pub(crate) certificates: Vec<Certificate<ContentHeads<T>>>,
    pub(crate) pending_events: Vec<StaticEvent<T>>,
}

impl<T: ContentRef> Archive<T> {
    /// Getter for the user that the [`Archive`] is for.
    pub fn id(&self) -> IndividualId {
        self.active.individual.id()
    }
}

/// The archive format: the magic bytes `KHIV`, then the format number. Only
/// the current format decodes, so an archive in another one is refused rather
/// than misread. An archive written before the magic bytes existed starts with
/// its key-pair count instead, which would have to be about 1.4 billion to
/// collide with them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArchiveVersion;

impl ArchiveVersion {
    /// The bytes every archive starts with.
    pub const MAGIC: [u8; 4] = *b"KHIV";

    /// The format this build reads and writes.
    pub const NUMBER: u8 = 2;
}

impl Serialize for ArchiveVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (Self::MAGIC, Self::NUMBER).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArchiveVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (magic, number) = <([u8; 4], u8)>::deserialize(deserializer)?;
        if magic != Self::MAGIC {
            return Err(de::Error::custom(
                "not a keyhive archive, or one written before format 2",
            ));
        }
        if number != Self::NUMBER {
            return Err(de::Error::custom(format!(
                "archive format {number} is not supported; this build reads format {}",
                Self::NUMBER
            )));
        }
        Ok(ArchiveVersion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_current_format_decodes() {
        let bytes = bincode::serialize(&ArchiveVersion).expect("the version serializes");
        assert_eq!(bytes, b"KHIV\x02");
        assert!(bincode::deserialize::<ArchiveVersion>(&bytes).is_ok());
        assert!(
            bincode::deserialize::<ArchiveVersion>(b"KHIV\x03").is_err(),
            "another format number"
        );
        // A format-1 archive starts with its key-pair count as a little-endian
        // u64; two key pairs, say.
        assert!(
            bincode::deserialize::<ArchiveVersion>(&2u64.to_le_bytes()).is_err(),
            "an archive from before the magic bytes"
        );
    }
}
