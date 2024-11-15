use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
};

use keyhive_core::{
    crypto::digest::Digest,
    principal::group::membership_operation::{MembershipOperation, StaticMembershipOperation},
};

pub(crate) use keyhive_sync_id::KeyhiveSyncId;
mod keyhive_agent_sync;
pub(crate) use keyhive_agent_sync::{
    request_agent_ops_from_forwarding_peers, KeyhiveAgentSyncSessions,
};
mod keyhive_sync_id;

#[tracing::instrument(skip(ctx, peer))]
pub(crate) async fn sync_keyhive<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    peer: TargetNodeInfo,
    additional_peers_to_send: Vec<PeerId>,
) {
    tracing::debug!("syncing keyhive auth graph");
    // start a keyhive auth sync session
    let remote_peer_id = match peer.last_known_peer_id {
        Some(p) => p,
        None => ctx.requests().ping(peer.clone()).await.unwrap(),
    };
    let local_ops = ctx
        .keyhive()
        .keyhive_ops(*remote_peer_id.as_key(), additional_peers_to_send);
    let mut decoder = riblt::Decoder::<OpHash>::new();
    for op_hash in local_ops.keys() {
        decoder.add_symbol(&OpHash::from(*op_hash));
    }
    tracing::trace!("beginning sync");
    let Ok((session_id, first_symbols)) = ctx.requests().begin_auth_sync(peer.clone()).await else {
        tracing::warn!("error begining auth sync");
        return;
    };
    for symbol in first_symbols {
        decoder.add_coded_symbol(&symbol);
        decoder.try_decode().unwrap();
        if decoder.decoded() {
            break;
        }
    }

    while !decoder.decoded() {
        let Ok(next_symbols) = ctx
            .requests()
            .keyhive_symbols(peer.clone(), session_id)
            .await
        else {
            tracing::warn!("failed to fetch symbols, exiting");
            return;
        };
        for symbol in next_symbols {
            decoder.add_coded_symbol(&symbol);
            decoder.try_decode().unwrap();
            if decoder.decoded() {
                break;
            }
        }
    }
    decoder.try_decode().unwrap();

    let to_download = decoder
        .get_remote_symbols()
        .iter()
        .map(|c| c.symbol())
        .collect::<Vec<_>>();
    if !to_download.is_empty() {
        tracing::trace!(?to_download, "downloading ops");
        let ops = ctx
            .requests()
            .request_keyhive_ops(peer.clone(), session_id, to_download)
            .await
            .unwrap();
        ctx.keyhive()
            .apply_keyhive_ops(ops.into_iter().map(|o| o.0.into()).collect())
            .expect("FIXME");
    } else {
        tracing::trace!("no new keyhive ops to download");
    }

    let hashes_to_upload = decoder
        .get_local_symbols()
        .iter()
        .map(|c| c.symbol())
        .collect::<HashSet<_>>();
    if !hashes_to_upload.is_empty() {
        tracing::trace!(?hashes_to_upload, "uploading ops");
        let to_upload = hashes_to_upload
            .into_iter()
            .map(|h| local_ops.get(&(h.into())).unwrap().clone().into())
            .collect();
        ctx.requests()
            .upload_keyhive_ops(peer, to_upload, session_id)
            .await
            .unwrap();
    } else {
        tracing::trace!("no keyhive ops to upload");
    }
}

use crate::{
    documents::CommitHash,
    network::TargetNodeInfo,
    riblt,
    serialization::{leb128, parse, Encode, Parse},
    state::TaskContext,
    PeerId,
};

pub(crate) struct KeyhiveSyncSessions {
    sessions: HashMap<KeyhiveSyncId, Session>,
}

impl KeyhiveSyncSessions {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub(crate) fn new_session<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        ops: HashMap<Digest<MembershipOperation<CommitHash>>, MembershipOperation<CommitHash>>,
    ) -> (KeyhiveSyncId, Vec<riblt::CodedSymbol<OpHash>>) {
        tracing::trace!("creating new sync session");
        let session_id = KeyhiveSyncId::random(rng);
        let mut encoder = riblt::Encoder::new();
        for op_hash in ops.keys() {
            encoder.add_symbol(&OpHash::from(*op_hash));
        }
        let first_10_symbols = encoder.next_n_symbols(10);
        let session = Session { ops, encoder };
        self.sessions.insert(session_id, session);
        (session_id, first_10_symbols)
    }

    pub(crate) fn next_n_symbols(
        &mut self,
        session_id: KeyhiveSyncId,
        n: u64,
    ) -> Option<Vec<riblt::CodedSymbol<OpHash>>> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return None;
        };
        Some(session.next_n_symbols(n))
    }
}

// TODO: Fill out all the ops keyhive can produce here
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyhiveOp(pub(crate) StaticMembershipOperation<CommitHash>);

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for KeyhiveOp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let op = u.arbitrary::<StaticMembershipOperation<CommitHash>>()?;
        Ok(Self(op))
    }
}

impl From<StaticMembershipOperation<CommitHash>> for KeyhiveOp {
    fn from(op: StaticMembershipOperation<CommitHash>) -> Self {
        Self(op)
    }
}

impl From<MembershipOperation<CommitHash>> for KeyhiveOp {
    fn from(op: MembershipOperation<CommitHash>) -> Self {
        Self(op.into())
    }
}

impl Encode for KeyhiveOp {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        // For now just serialize to JSON
        let encoded = bincode::serialize(&self.0).unwrap();
        leb128::encode_uleb128(buf, encoded.len() as u64);
        buf.extend_from_slice(&encoded);
    }
}

impl Parse<'_> for KeyhiveOp {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, raw) = parse::slice(input)?;
        let decoded = bincode::deserialize(&raw)
            .map_err(|e| input.error(format!("failed to parse op: {}", e)))?;
        Ok((input, Self(decoded)))
    }
}

impl From<KeyhiveOp> for StaticMembershipOperation<CommitHash> {
    fn from(op: KeyhiveOp) -> Self {
        op.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct OpHash(pub(crate) [u8; 32]);

impl From<OpHash> for Digest<StaticMembershipOperation<CommitHash>> {
    fn from(hash: OpHash) -> Self {
        Self::from(hash.0)
    }
}

impl From<OpHash> for Digest<MembershipOperation<CommitHash>> {
    fn from(hash: OpHash) -> Self {
        Self::from(hash.0)
    }
}

impl From<Digest<MembershipOperation<CommitHash>>> for OpHash {
    fn from(digest: Digest<MembershipOperation<CommitHash>>) -> Self {
        Self(*digest.raw.as_bytes())
    }
}

impl Encode for OpHash {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for OpHash {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, hash) = parse::arr::<32>(input)?;
        Ok((input, Self(hash)))
    }
}

impl riblt::Symbol for OpHash {
    fn zero() -> Self {
        Self([0; 32])
    }

    fn xor(&self, other: &Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] ^ other.0[i]))
    }

    fn hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

struct Session {
    ops: HashMap<Digest<MembershipOperation<CommitHash>>, MembershipOperation<CommitHash>>,
    encoder: riblt::Encoder<OpHash>,
}

impl Session {
    fn next_n_symbols(&mut self, n: u64) -> Vec<riblt::CodedSymbol<OpHash>> {
        self.encoder.next_n_symbols(n as u64)
    }
}
