use std::{array, collections::HashMap, hash::Hash};

use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
};

use crate::{
    network::PeerAddress,
    parse::{self, Parse},
    riblt,
    serialization::Encode,
    sync::SessionId,
    DocumentId, TaskContext,
};

pub(super) async fn sync_cgka<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    peer_address: PeerAddress,
    session_id: SessionId,
    doc_id: DocumentId,
) -> Result<(), super::super::Error> {
    let mut decoder = riblt::Decoder::new();
    let local_ops = ctx
        .state()
        .keyhive()
        .cgka_ops_for_doc(doc_id)
        .await
        .map_err(|e| {
            tracing::warn!(err=?e, "error getting local cgka ops");
            crate::sync::Error::Other(format!("error getting local cgka ops: {:?}", e))
        })?
        .into_iter()
        .map(|op| (Digest::hash(&op), op))
        .collect::<HashMap<_, _>>();

    for hash in local_ops.keys() {
        decoder.add_symbol(&CgkaSymbol(*hash));
    }

    let mut remote_symbols = ctx
        .requests()
        .sessions()
        .fetch_cgka_symbols(peer_address, session_id, doc_id, 10)
        .await??;
    const BATCH_SIZE: usize = 100;

    loop {
        for symbol in remote_symbols {
            decoder.add_coded_symbol(&symbol);
            decoder.try_decode().expect("FIXME");
        }
        if decoder.decoded() {
            break;
        }
        remote_symbols = ctx
            .requests()
            .sessions()
            .fetch_cgka_symbols(peer_address, session_id, doc_id, BATCH_SIZE as u32)
            .await??;
    }

    let to_download = decoder
        .get_remote_symbols()
        .into_iter()
        .map(|s| s.symbol().0)
        .collect::<Vec<_>>();

    let do_download = async {
        if !to_download.is_empty() {
            tracing::trace!(num_to_download = to_download.len(), "downloading cgka ops");
            let ops = ctx
                .requests()
                .sessions()
                .fetch_cgka_ops(peer_address, session_id, doc_id, to_download)
                .await??;
            ctx.state()
                .keyhive()
                .ingest_cgka_ops(ops)
                .await
                .map_err(|e| super::super::Error::Other(e.to_string()))?;
            ctx.state().docs().mark_changed(&doc_id);
        } else {
            tracing::trace!("no cgka ops to download");
        }
        Ok::<_, super::super::Error>(())
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
            ctx.requests()
                .upload_cgka_ops(peer_address, to_upload)
                .await?;
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
        out.extend_from_slice(self.0.as_slice());
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
