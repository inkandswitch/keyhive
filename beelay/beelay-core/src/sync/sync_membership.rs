use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use keyhive_core::{crypto::digest::Digest, event::static_event::StaticEvent};

use crate::{
    network::RpcError,
    parse::{self, Parse},
    riblt,
    serialization::Encode,
    sync::server_session::MakeSymbols,
    CommitHash, PeerId,
};

use super::{SessionId, SyncEffects};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct MembershipSymbol {
    hash: Digest<StaticEvent<CommitHash>>,
}

impl riblt::Symbol for MembershipSymbol {
    fn zero() -> Self {
        Self {
            hash: Digest::from([0; 32]),
        }
    }

    fn xor(&self, other: &Self) -> Self {
        let us = self.hash.as_slice();
        let other = other.hash.as_slice();
        Self {
            hash: Digest::from(std::array::from_fn(|i| us[i] ^ other[i])),
        }
    }

    fn hash(&self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.hash.as_slice());
        let mut out_builder = hasher.finalize_xof();
        let mut out = [0_u8; 8];
        out_builder.fill(&mut out);
        u64::from_be_bytes(out)
    }
}

impl Encode for MembershipSymbol {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash.as_slice())
    }
}

impl<'a> Parse<'a> for MembershipSymbol {
    fn parse(
        input: crate::parse::Input<'a>,
    ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
        let (input, arr) = parse::arr::<32>(input)?;
        Ok((
            input,
            Self {
                hash: Digest::from(arr),
            },
        ))
    }
}

impl<'a> From<&'a StaticEvent<CommitHash>> for MembershipSymbol {
    fn from(evt: &'a StaticEvent<CommitHash>) -> Self {
        Self {
            hash: Digest::hash(evt),
        }
    }
}

#[tracing::instrument(skip(effects, local_ops, symbols), fields(num_symbols = symbols.len()))]
pub(crate) async fn sync_membership<
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R>,
>(
    effects: E,
    session_id: SessionId,
    mut symbols: Vec<riblt::CodedSymbol<MembershipSymbol>>,
    local_ops: HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>>,
    with_remote: PeerId,
) -> Result<(), error::SyncMembership> {
    tracing::debug!(num_local_ops = local_ops.len(), "running membership sync");

    let mut decoder = riblt::Decoder::new();
    for op_hash in local_ops.keys() {
        decoder.add_symbol(&MembershipSymbol {
            hash: op_hash.clone(),
        });
    }

    let mut offset = symbols.len();
    const BATCH_SIZE: usize = 100;

    loop {
        tracing::trace!("running RIBLT sync");
        for symbol in symbols {
            decoder.add_coded_symbol(&symbol);
            decoder.try_decode().unwrap();
        }
        if decoder.decoded() {
            break;
        }
        symbols = effects
            .fetch_membership_symbols(
                session_id,
                MakeSymbols {
                    offset,
                    count: BATCH_SIZE,
                },
            )
            .await?;
        offset += BATCH_SIZE;
    }

    let local_op_hashes = decoder
        .get_local_symbols()
        .into_iter()
        .map(|s| s.symbol().hash)
        .collect::<HashSet<_>>();
    let remote_op_hashes = decoder
        .get_remote_symbols()
        .into_iter()
        .map(|s| s.symbol().hash)
        .collect::<HashSet<_>>();

    let to_upload = local_op_hashes
        .difference(&remote_op_hashes)
        .map(|h| local_ops.get(h).unwrap().clone())
        .collect::<Vec<_>>();
    let upload_fut = async {
        if to_upload.is_empty() {
            tracing::trace!("no membership ops to upload");
            Ok(())
        } else {
            tracing::trace!(num_to_upload = to_upload.len(), "uploading ops");
            effects.upload_membership_ops(session_id, to_upload).await
        }
    };

    let to_download = remote_op_hashes
        .difference(&local_op_hashes)
        .cloned()
        .collect::<Vec<_>>();

    let download = async {
        if !to_download.is_empty() {
            tracing::trace!(num_to_download = to_download.len(), "downloading ops");
            let ops = effects
                .fetch_membership_ops(session_id, to_download)
                .await?;
            effects
                .keyhive()
                .ingest_membership_ops(ops)
                .await
                .map_err(|e| error::SyncMembership::IngestionFailed(e.to_string()))?;
        } else {
            tracing::trace!("no membership ops to download");
        }
        Ok::<_, error::SyncMembership>(())
    };

    let (upload_result, download_result) = futures::future::join(upload_fut, download).await;

    upload_result?;
    download_result?;
    Ok(())
}

pub(crate) mod error {
    use super::RpcError;

    #[derive(Debug, thiserror::Error)]
    pub(crate) enum SyncMembership {
        #[error("ingestion failed: {0}")]
        IngestionFailed(String),
        #[error(transparent)]
        Rpc(#[from] RpcError),
    }
}
