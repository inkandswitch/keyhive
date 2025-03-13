use std::{array, collections::HashMap, hash::Hash};

use keyhive_core::{
    cgka::{error::CgkaError, operation::CgkaOperation},
    crypto::{digest::Digest, signed::Signed},
    keyhive::ReceiveCgkaOpError,
};

use crate::{
    network::{messages::SessionResponse, RpcError},
    parse::{self, Parse},
    riblt,
    serialization::Encode,
    state::keyhive::error::Ingest,
    sync::{server_session::MakeSymbols, SessionId, SyncEffects},
    DocumentId,
};

pub(super) async fn sync_cgka<
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone,
>(
    effects: E,
    session_id: SessionId,
    doc_id: DocumentId,
) -> Result<(), SyncCgkaError> {
    let mut decoder = riblt::Decoder::new();
    let local_ops = effects
        .keyhive()
        .cgka_ops_for_doc(doc_id)
        .await?
        .into_iter()
        .map(|op| (Digest::hash(&op), op))
        .collect::<HashMap<_, _>>();

    for (hash, _) in &local_ops {
        decoder.add_symbol(&CgkaSymbol(*hash));
    }

    let mut remote_symbols = unpack_session_resp(
        effects
            .fetch_cgka_symbols(
                session_id,
                doc_id.clone(),
                MakeSymbols {
                    offset: 0,
                    count: 10,
                },
            )
            .await?,
    )?;
    let mut offset = 0;
    const BATCH_SIZE: usize = 100;

    loop {
        for symbol in remote_symbols {
            decoder.add_coded_symbol(&symbol);
            decoder.try_decode().expect("FIXME");
            offset += 1;
        }
        if decoder.decoded() {
            break;
        }
        remote_symbols = unpack_session_resp(
            effects
                .fetch_cgka_symbols(
                    session_id,
                    doc_id.clone(),
                    MakeSymbols {
                        offset,
                        count: BATCH_SIZE,
                    },
                )
                .await?,
        )?;
    }

    let to_download = decoder
        .get_remote_symbols()
        .into_iter()
        .map(|s| s.symbol().0)
        .collect::<Vec<_>>();

    let do_download = async {
        if !to_download.is_empty() {
            tracing::trace!(num_to_download = to_download.len(), "downloading cgka ops");
            let ops = unpack_session_resp(
                effects
                    .fetch_cgka_ops(session_id, doc_id.clone(), to_download)
                    .await?,
            )?;
            effects.keyhive().ingest_cgka_ops(ops).await?;
            effects.mark_doc_changed(&doc_id);
        } else {
            tracing::trace!("no cgka ops to download");
        }
        Ok::<_, SyncCgkaError>(())
    };

    let to_upload = decoder
        .get_local_symbols()
        .into_iter()
        .filter_map(|s| local_ops.get(&s.symbol().0))
        .cloned()
        .collect::<Vec<_>>();

    let upload = async {
        if !to_upload.is_empty() {
            tracing::trace!(num_to_upload = to_upload.len(), "uploading cgka ops");
            effects
                .upload_cgka_ops(session_id, doc_id.clone(), to_upload)
                .await
                .map_err(SyncCgkaError::from)?;
        } else {
            tracing::trace!("no cgka ops to upload");
        }
        Ok(())
    };

    futures::future::try_join(do_download, upload).await?;

    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct CgkaSymbol(Digest<Signed<CgkaOperation>>);

impl<'a> From<&'a Signed<CgkaOperation>> for CgkaSymbol {
    fn from(op: &'a Signed<CgkaOperation>) -> Self {
        Self(Digest::hash(op))
    }
}

impl CgkaSymbol {
    #[cfg(test)]
    pub(crate) fn digest(&self) -> Digest<Signed<CgkaOperation>> {
        self.0
    }
}

impl riblt::Symbol for CgkaSymbol {
    fn zero() -> Self {
        Self([0; 32].into())
    }

    fn xor(&self, other: &Self) -> Self {
        Self(array::from_fn(|i| self.0.as_slice()[i] ^ other.0.as_slice()[i]).into())
    }

    fn hash(&self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.0.as_slice());
        let mut out_builder = hasher.finalize_xof();
        let mut out = [0_u8; 8];
        out_builder.fill(&mut out);
        u64::from_be_bytes(out)
    }
}

impl Encode for CgkaSymbol {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.as_slice());
    }
}

impl<'a> Parse<'a> for CgkaSymbol {
    fn parse(
        input: crate::parse::Input<'a>,
    ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
        let (input, bytes) = parse::arr::<32>(input)?;
        let symbol = Self(bytes.into());
        Ok((input, symbol))
    }
}

fn unpack_session_resp<R>(resp: SessionResponse<R>) -> Result<R, SyncCgkaError> {
    match resp {
        SessionResponse::Ok(result) => Ok(result),
        SessionResponse::SessionExpired => Err(SyncCgkaError::SessionExpired),
        SessionResponse::SessionNotFound => Err(SyncCgkaError::SessionNotFound),
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SyncCgkaError {
    #[error(transparent)]
    Cgka(#[from] CgkaError),
    #[error(transparent)]
    CgkaOp(#[from] ReceiveCgkaOpError),
    #[error(transparent)]
    IngestionFailed(#[from] Ingest),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("session expired")]
    SessionExpired,
    #[error("session not found")]
    SessionNotFound,
}
