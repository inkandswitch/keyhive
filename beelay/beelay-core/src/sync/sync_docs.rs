use std::{
    array,
    collections::{HashMap, HashSet},
    hash::Hash,
};

use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
};

use crate::{
    network::PeerAddress,
    parse::{self, Parse},
    sedimentree::MinimalTreeHash,
    serialization::Encode,
    DocumentId, PeerId, TaskContext,
};

use super::{reachable_docs::DocState, riblt, SessionId};

#[derive(Debug)]
pub(super) struct SyncDocsResult {
    pub out_of_sync: HashSet<DocumentId>,
    #[allow(dead_code)]
    pub in_sync: HashSet<DocumentId>,
}

#[tracing::instrument(skip(ctx, local_docs), fields(remote=%remote))]
pub(super) async fn sync_docs<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    session: SessionId,
    local_docs: HashMap<DocumentId, DocState>,
    init_remote_symbols: Vec<riblt::CodedSymbol<DocStateHash>>,
    remote: PeerId,
    target: PeerAddress,
) -> Result<SyncDocsResult, super::Error> {
    tracing::trace!(
        num_local_docs = local_docs.len(),
        "beginning doc collection sync"
    );
    let mut decoder = riblt::Decoder::new();
    for state in local_docs.values() {
        decoder.add_symbol(&state.hash);
    }

    let mut symbols = init_remote_symbols;
    const BATCH_SIZE: usize = 100;
    let mut iterations = 0;

    loop {
        tracing::trace!(?iterations, "processing RIBLT symbols");
        for symbol in &symbols {
            decoder.add_coded_symbol(symbol);
            decoder.try_decode().unwrap();
        }
        if decoder.decoded() {
            break;
        }
        iterations += 1;
        symbols = ctx
            .requests()
            .sessions()
            .fetch_doc_symbols(target, session, BATCH_SIZE as u32)
            .await??;
    }

    tracing::trace!("RIBLT sync completed");

    let only_remote_states = decoder
        .get_remote_symbols()
        .into_iter()
        .map(|s| Ok::<_, error::SyncDocs>((s.symbol().doc_id()?, s.symbol().hash())))
        .collect::<Result<HashMap<_, _>, _>>()?;

    let only_local_states = decoder
        .get_local_symbols()
        .into_iter()
        .map(|s| Ok::<_, error::SyncDocs>((s.symbol().doc_id()?, s.symbol().hash())))
        .collect::<Result<HashMap<_, _>, _>>()?;

    let (in_sync, local_out_of_sync) = local_docs.keys().partition::<HashSet<_>, _>(|doc_id| {
        only_remote_states.get(doc_id).is_none() && only_local_states.get(doc_id).is_none()
    });

    let out_of_sync = local_out_of_sync
        .union(&only_remote_states.keys().copied().collect())
        .copied()
        .collect();

    Ok(SyncDocsResult {
        out_of_sync,
        in_sync,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct DocStateHash {
    doc_id: [u8; 32],
    hash: [u8; 32],
}

impl DocStateHash {
    pub(crate) fn construct(
        doc: &DocumentId,
        tree: MinimalTreeHash,
        cgka_ops: &Vec<Signed<CgkaOperation>>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tree.as_bytes());
        let mut cgka = cgka_ops.iter().map(|o| Digest::hash(o)).collect::<Vec<_>>();
        cgka.sort();
        for op in cgka {
            hasher.update(op.as_slice());
        }
        let hash = hasher.finalize();
        Self {
            doc_id: *doc.as_bytes(),
            hash: *hash.as_bytes(),
        }
    }

    fn doc_id(&self) -> Result<DocumentId, error::SyncDocs> {
        DocumentId::try_from(self.doc_id).map_err(|e| {
            tracing::error!(err=?e, "unable to parse doc ID from symbol");
            error::SyncDocs::BadSymbol
        })
    }

    fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

impl riblt::Symbol for DocStateHash {
    fn zero() -> Self {
        Self {
            doc_id: [0; 32],
            hash: [0; 32],
        }
    }

    fn xor(&self, other: &Self) -> Self {
        Self {
            doc_id: array::from_fn(|i| self.doc_id[i] ^ other.doc_id[i]),
            hash: array::from_fn(|i| self.hash[i] ^ other.hash[i]),
        }
    }

    fn hash(&self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.doc_id);
        hasher.update(&self.hash);
        let mut out_builder = hasher.finalize_xof();
        let mut out = [0_u8; 8];
        out_builder.fill(&mut out);
        u64::from_be_bytes(out)
    }
}

impl Encode for DocStateHash {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.doc_id);
        out.extend_from_slice(&self.hash);
    }
}

impl<'a> Parse<'a> for DocStateHash {
    fn parse(
        input: crate::parse::Input<'a>,
    ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
        input.parse_in_ctx("DocStateHash", |input| {
            let (input, doc_id) = parse::arr::<32>(input)?;
            let (input, hash) = parse::arr::<32>(input)?;
            Ok((input, DocStateHash { doc_id, hash }))
        })
    }
}

pub(crate) mod error {
    use crate::network::RpcError;

    #[derive(Debug, thiserror::Error)]
    pub(crate) enum SyncDocs {
        #[error("a symbol had an incorrect tag")]
        BadSymbol,
        #[error(transparent)]
        Rpc(#[from] RpcError),
        #[error("session expired")]
        SessionExpired,
        #[error("session not found")]
        SessionNotFound,
        #[error("session error: {0}")]
        Session(String),
    }
}
