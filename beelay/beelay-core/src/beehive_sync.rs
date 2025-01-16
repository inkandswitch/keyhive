mod beehive_sync_id;
use dupe::Dupe;
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
};

use beehive_core::{
    beehive::Beehive,
    crypto::digest::Digest,
    principal::group::operation::{Operation, StaticOperation},
};
pub(crate) use beehive_sync_id::BeehiveSyncId;

pub(crate) async fn sync_beehive<R: rand::Rng + rand::CryptoRng>(
    effects: TaskEffects<R>,
    peer: TargetNodeInfo,
) {
    // start a beehive auth sync session
    let local_ops = effects
        .beehive_ops(*peer.last_known_peer_id.unwrap().as_key())
        .values()
        .map(|op| BeehiveOp(op.dupe().into()))
        .collect::<Vec<_>>();
    let (session_id, first_symbols) = effects.begin_auth_sync(peer.clone()).await.unwrap();
    let mut decoder = riblt::Decoder::<OpHash>::new();
    for symbol in first_symbols {
        decoder.add_coded_symbol(&symbol);
    }

    while !decoder.decoded() {
        let next_symbols = effects
            .beehive_symbols(peer.clone(), session_id)
            .await
            .unwrap();
        for symbol in next_symbols {
            decoder.add_coded_symbol(&symbol);
        }
    }
    decoder.try_decode().unwrap();

    let to_download = decoder
        .get_remote_symbols()
        .iter()
        .map(|c| c.symbol())
        .collect();
    let ops = effects
        .request_beehive_ops(peer.clone(), session_id, to_download)
        .await
        .unwrap();

    effects
        .apply_beehive_ops(ops.into_iter().map(|o| o.0.into()).collect())
        .expect("FIXME");

    let hashes_to_upload = decoder
        .get_local_symbols()
        .iter()
        .map(|c| c.symbol())
        .collect::<HashSet<_>>();
    let to_upload = local_ops
        .iter()
        .filter(|op| hashes_to_upload.contains(&op.op_hash()))
        .cloned()
        .collect::<Vec<_>>();
    effects.upload_beehive_ops(peer, to_upload).await.unwrap();
}

use crate::{
    deser::{Encode, Parse},
    effects::TaskEffects,
    parse,
    peer_address::TargetNodeInfo,
    riblt, CommitHash, PeerId,
};

pub(crate) struct BeehiveSyncSessions {
    sessions: HashMap<BeehiveSyncId, Session>,
}

impl BeehiveSyncSessions {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub(crate) fn new_session<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        beehive: &beehive_core::beehive::Beehive<CommitHash, R>,
    ) -> (BeehiveSyncId, Vec<riblt::CodedSymbol<OpHash>>) {
        let session_id = BeehiveSyncId::random(rng);
        let ops: HashMap<OpHash, BeehiveOp> = ops(beehive).map(|op| (op.op_hash(), op)).collect();
        let mut encoder = riblt::Encoder::new();
        for op_hash in ops.keys() {
            encoder.add_symbol(op_hash);
        }
        let first_10_symbols = encoder.next_n_symbols(10);
        let session = Session { ops, encoder };
        self.sessions.insert(session_id, session);
        (session_id, first_10_symbols)
    }

    pub(crate) fn next_n_symbols(
        &mut self,
        session_id: BeehiveSyncId,
        n: u64,
    ) -> Option<Vec<riblt::CodedSymbol<OpHash>>> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return None;
        };
        Some(session.next_n_symbols(n))
    }
}

// TODO: Fill out all the ops beehive can produce here
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BeehiveOp(pub(crate) StaticOperation<CommitHash>);

impl From<StaticOperation<CommitHash>> for BeehiveOp {
    fn from(op: StaticOperation<CommitHash>) -> Self {
        Self(op)
    }
}

impl From<Operation<CommitHash>> for BeehiveOp {
    fn from(op: Operation<CommitHash>) -> Self {
        Self(op.into())
    }
}

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for BeehiveOp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        todo!()
    }
}

impl BeehiveOp {
    pub(crate) fn op_hash(&self) -> OpHash {
        // beehive::digest
        OpHash(
            *beehive_core::crypto::digest::Digest::hash(&self.0)
                .raw
                .as_bytes(),
        )
    }
}

impl Encode for BeehiveOp {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        // For now just serialize to JSON
        let encoded = serde_json::to_vec(&self.0).unwrap();
        crate::leb128::encode_uleb128(buf, encoded.len() as u64);
        buf.extend_from_slice(&encoded);
    }
}

impl Parse<'_> for BeehiveOp {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, raw) = parse::slice(input)?;
        let decoded = serde_json::from_slice(raw)
            .map_err(|e| input.error(format!("failed to parse op: {}", e)))?;
        Ok((input, Self(decoded)))
    }
}

impl From<BeehiveOp> for StaticOperation<CommitHash> {
    fn from(op: BeehiveOp) -> Self {
        op.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct OpHash(pub(crate) [u8; 32]);

impl From<OpHash> for Digest<StaticOperation<CommitHash>> {
    fn from(hash: OpHash) -> Self {
        Self::from(hash.0)
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
    ops: HashMap<OpHash, BeehiveOp>,
    encoder: riblt::Encoder<OpHash>,
}

impl Session {
    fn next_n_symbols(&mut self, n: u64) -> Vec<riblt::CodedSymbol<OpHash>> {
        self.encoder.next_n_symbols(n as u64)
    }
}

fn ops<'a, R: rand::Rng + rand::CryptoRng>(
    beehive: &'a Beehive<CommitHash, R>,
) -> impl Iterator<Item = BeehiveOp> + 'a {
    std::iter::empty()
}
