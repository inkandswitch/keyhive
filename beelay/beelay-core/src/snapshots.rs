use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use crate::{
    effects::TaskEffects, hex, parse, reachability, sedimentree::MinimalTreeHash, CommitCategory,
    DocumentId, PeerId, StorageKey,
};

#[derive(Copy, Clone, PartialEq, Eq, serde::Serialize, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct SnapshotId([u8; 16]);

impl std::str::FromStr for SnapshotId {
    type Err = error::BadSnapshotId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(error::BadSnapshotId::InvalidHex)?;
        if bytes.len() == 16 {
            let mut id = [0; 16];
            id.copy_from_slice(&bytes);
            Ok(Self(id))
        } else {
            Err(error::BadSnapshotId::InvalidLength)
        }
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl std::fmt::Debug for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl SnapshotId {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, id) = parse::arr::<16>(input)?;
        Ok((input, Self(id)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    pub(crate) fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

pub(crate) struct Snapshot {
    root_doc: DocumentId,
    id: SnapshotId,
    we_have_doc: bool,
    local: HashMap<DocumentId, MinimalTreeHash>,
    local_log_offset: usize,
    remote_snapshots: HashMap<PeerId, SnapshotId>,
}

impl Snapshot {
    pub(crate) async fn load<R: rand::Rng>(
        mut effects: TaskEffects<R>,
        root_doc: DocumentId,
    ) -> Self {
        let id = SnapshotId::random(&mut *effects.rng());
        let we_have_doc = !effects
            .load_range(StorageKey::sedimentree_root(
                &root_doc,
                CommitCategory::Content,
            ))
            .await
            .is_empty();
        let docs_to_hashes = if we_have_doc {
            reachability::load_reachable_docs(effects.clone(), root_doc).await
        } else {
            HashMap::new()
        };
        Self {
            id,
            root_doc,
            we_have_doc,
            local: docs_to_hashes,
            local_log_offset: effects.log().offset(),
            remote_snapshots: HashMap::new(),
        }
    }

    pub(crate) fn id(&self) -> SnapshotId {
        self.id
    }

    pub(crate) fn root_doc(&self) -> &DocumentId {
        &self.root_doc
    }

    pub(crate) fn local_log_offset(&self) -> usize {
        self.local_log_offset
    }

    pub(crate) fn we_have_doc(&self) -> bool {
        self.we_have_doc
    }

    pub(crate) fn our_docs(&self) -> HashSet<DocumentId> {
        self.local.keys().cloned().collect()
    }

    pub(crate) fn our_docs_2(&self) -> &HashMap<DocumentId, MinimalTreeHash> {
        &self.local
    }

    pub(crate) fn add_remote(&mut self, peer: PeerId, snapshot: SnapshotId) {
        self.remote_snapshots.insert(peer, snapshot);
    }

    pub(crate) fn remote_snapshots(&self) -> &HashMap<PeerId, SnapshotId> {
        &self.remote_snapshots
    }
}

mod error {
    use crate::hex;

    pub enum BadSnapshotId {
        InvalidHex(hex::FromHexError),
        InvalidLength,
    }

    impl std::fmt::Display for BadSnapshotId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InvalidHex(e) => write!(f, "invalid hex: {:?}", e),
                Self::InvalidLength => write!(f, "invalid length"),
            }
        }
    }

    impl std::fmt::Debug for BadSnapshotId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for BadSnapshotId {}
}
