use std::collections::HashMap;

use keyhive_core::{
    cgka::{error::CgkaError, operation::CgkaOperation},
    crypto::signed::Signed,
};

use crate::{sedimentree, task_context, DocumentId, PeerId, TaskContext};

use super::DocStateHash;

pub(crate) struct ReachableDocs {
    pub(crate) doc_states: HashMap<DocumentId, DocState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DocState {
    pub(crate) hash: DocStateHash,
    pub(crate) cgka_ops: Vec<Signed<CgkaOperation>>,
    pub(crate) sedimentree: sedimentree::SedimentreeSummary,
}

impl<'a> From<&'a DocState> for DocStateHash {
    fn from(doc_state: &'a DocState) -> Self {
        doc_state.hash
    }
}

impl ReachableDocs {
    #[tracing::instrument(level = "trace", skip(ctx))]
    pub(crate) async fn load<R: rand::Rng + rand::CryptoRng + Clone>(
        ctx: TaskContext<R>,
        for_remote: PeerId,
    ) -> Result<Self, Error> {
        let docs = ctx
            .state()
            .keyhive()
            .docs_accessible_to_agent(for_remote)
            .await;
        tracing::trace!(num_docs = docs.len(), "loaded accessible docs");
        let doc_states = docs.iter().map(|doc_id| {
            let ctx = ctx.clone();
            async move {
                let tree =
                    sedimentree::storage::load(ctx.storage().doc_storage(doc_id.clone())).await?;
                if let Some(tree) = tree {
                    let summary = tree.minimize().summarize();
                    let cgka_ops = ctx
                        .state()
                        .keyhive()
                        .cgka_ops_for_doc(doc_id.clone())
                        .await?;
                    let hash = DocStateHash::construct(&doc_id, tree.minimal_hash(), &cgka_ops);
                    Ok::<_, Error>(Some((
                        doc_id.clone(),
                        DocState {
                            hash,
                            cgka_ops,
                            sedimentree: summary,
                        },
                    )))
                } else {
                    tracing::warn!(?doc_id, "no data found for doc");
                    Ok(None)
                }
            }
        });
        let doc_states = futures::future::try_join_all(doc_states).await?;
        Ok(Self {
            doc_states: doc_states.into_iter().filter_map(|state| state).collect(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    LoadDoc(#[from] task_context::SedimentreeStorageError),
    #[error(transparent)]
    CgkaOps(#[from] CgkaError),
}
