use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};

use crate::{
    reachability, riblt,
    sedimentree::MinimalTreeHash,
    serialization::{hex, parse, Encode, Parse},
    state::TaskContext,
    CommitCategory, DocumentId, PeerId, StorageKey, TargetNodeInfo,
};

pub struct Snapshots {
    snapshots: HashMap<
        SnapshotId,
        (
            Arc<Snapshot>,
            riblt::Encoder<riblt::doc_and_heads::DocAndHeadsSymbol>,
        ),
    >,
}

impl Snapshots {
    pub(crate) fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
        }
    }

    pub(crate) fn store(&mut self, snapshot: Snapshot) -> Arc<Snapshot> {
        let snapshot = Arc::new(snapshot);
        let encoder = snapshot.encoder();
        self.snapshots
            .insert(snapshot.id(), (snapshot.clone(), encoder));
        snapshot
    }

    pub(crate) fn next_n_symbols(
        &mut self,
        snapshot_id: SnapshotId,
        count: u64,
    ) -> Option<Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>> {
        let (_snapshot, encoder) = self.snapshots.get_mut(&snapshot_id)?;
        let symbols = encoder.next_n_symbols(count);
        Some(symbols)
    }

    pub(crate) fn we_have_snapshot_with_source(&self, source: SnapshotId) -> bool {
        self.snapshots
            .values()
            .any(|(snapshot, _)| snapshot.source() == source)
    }

    pub(crate) fn lookup(&self, snapshot_id: SnapshotId) -> Option<Arc<Snapshot>> {
        self.snapshots
            .get(&snapshot_id)
            .map(|(snapshot, _)| snapshot.clone())
    }
}

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
    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl Encode for SnapshotId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for SnapshotId {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, id) = parse::arr::<16>(input)?;
        Ok((input, Self(id)))
    }
}

pub(crate) struct Snapshot {
    root_doc: DocumentId,
    id: SnapshotId,
    we_have_doc: bool,
    local: HashMap<DocumentId, MinimalTreeHash>,
    local_log_offset: usize,
    remote_snapshots: HashMap<TargetNodeInfo, SnapshotId>,
    // The ID of the snapshot on the first node it was created on, used to avoid forwarding loops
    // TODO: come up with something more principled
    source: SnapshotId,
}

impl Snapshot {
    pub(crate) fn empty<R: rand::Rng + rand::CryptoRng>(
        ctx: &mut TaskContext<R>,
        root_doc: DocumentId,
        source_id: Option<SnapshotId>,
    ) -> Self {
        let id = SnapshotId::random(&mut *ctx.rng().borrow_mut());
        Self {
            id,
            root_doc,
            we_have_doc: false,
            local: HashMap::new(),
            local_log_offset: ctx.log().offset(),
            remote_snapshots: HashMap::new(),
            source: source_id.unwrap_or(id),
        }
    }

    pub(crate) async fn load<R: rand::Rng + rand::CryptoRng>(
        mut ctx: TaskContext<R>,
        requestor: Option<PeerId>,
        root_doc: DocumentId,
        source: Option<SnapshotId>,
    ) -> Self {
        let id = SnapshotId::random(&mut *ctx.rng().borrow_mut());
        let we_have_doc = !ctx
            .storage()
            .load_range(StorageKey::sedimentree_root(
                &root_doc,
                CommitCategory::Content,
            ))
            .await
            .is_empty();
        let docs_to_hashes = if we_have_doc {
            reachability::load_reachable_docs(ctx.clone(), requestor, root_doc).await
        } else {
            HashMap::new()
        };
        Self {
            id,
            root_doc,
            we_have_doc,
            local: docs_to_hashes,
            local_log_offset: ctx.log().offset(),
            remote_snapshots: HashMap::new(),
            source: source.unwrap_or(id),
        }
    }

    pub(crate) fn id(&self) -> SnapshotId {
        self.id
    }

    pub(crate) fn source(&self) -> SnapshotId {
        self.source
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

    pub(crate) fn our_doc_ids(&self) -> HashSet<DocumentId> {
        self.local
            .keys()
            .chain(std::iter::once(&self.root_doc))
            .cloned()
            .collect()
    }

    pub(crate) fn our_docs(&self) -> &HashMap<DocumentId, MinimalTreeHash> {
        &self.local
    }

    pub(crate) fn add_remote(&mut self, remote: TargetNodeInfo, snapshot: SnapshotId) {
        self.remote_snapshots.insert(remote, snapshot);
    }

    pub(crate) fn remote_snapshots(&self) -> &HashMap<TargetNodeInfo, SnapshotId> {
        &self.remote_snapshots
    }

    pub(crate) fn encoder(&self) -> riblt::Encoder<riblt::doc_and_heads::DocAndHeadsSymbol> {
        let mut enc = riblt::Encoder::new();
        for (doc, heads) in self.local.iter() {
            enc.add_symbol(&riblt::doc_and_heads::DocAndHeadsSymbol::new(doc, heads));
        }
        enc
    }
}

mod error {
    use crate::serialization::hex;

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
