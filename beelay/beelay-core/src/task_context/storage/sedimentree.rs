use crate::{
    parse::{self, Parse},
    serialization::Encode,
    DocumentId, StorageKey,
};

#[derive(Clone)]
pub(crate) struct DocStorage {
    doc_id: DocumentId,
    io_handle: crate::io::IoHandle,
}

impl DocStorage {
    pub fn new(io_handle: crate::io::IoHandle, doc: DocumentId) -> Self {
        DocStorage {
            doc_id: doc,
            io_handle,
        }
    }
}

impl sedimentree::storage::Storage for DocStorage {
    type Error = Error;

    async fn load_loose_commits(&self) -> Result<Vec<sedimentree::LooseCommit>, Self::Error> {
        let raw_commits = super::Storage {
            io_handle: &self.io_handle,
        }
        .load_range(StorageKey::sedimentree_commits(&self.doc_id))
        .await;
        raw_commits
            .into_values()
            .map(|raw| {
                let input = parse::Input::new(&raw);
                let (_input, commit) = sedimentree::LooseCommit::parse(input)
                    .map_err(|e| Error::InvalidCommit(e.to_string()))?;
                Ok(commit)
            })
            .collect::<Result<Vec<_>, _>>()
    }

    async fn load_strata(&self) -> Result<Vec<sedimentree::Stratum>, Self::Error> {
        let raw_strata = super::Storage {
            io_handle: &self.io_handle,
        }
        .load_range(StorageKey::sedimentree_strata(&self.doc_id))
        .await;
        raw_strata
            .into_values()
            .map(|raw| {
                let input = parse::Input::new(&raw);
                let (_input, stratum) = sedimentree::Stratum::parse(input)
                    .map_err(|e| Error::InvalidCommit(e.to_string()))?;
                Ok(stratum)
            })
            .collect::<Result<Vec<_>, _>>()
    }

    async fn save_loose_commit(&self, commit: sedimentree::LooseCommit) -> Result<(), Self::Error> {
        let raw = commit.encode();
        super::Storage {
            io_handle: &self.io_handle,
        }
        .put(
            StorageKey::sedimentree_commit(&self.doc_id, commit.hash().into()),
            raw,
        )
        .await;
        Ok(())
    }

    async fn save_stratum(&self, stratum: sedimentree::Stratum) -> Result<(), Self::Error> {
        let raw = stratum.encode();
        super::Storage {
            io_handle: &self.io_handle,
        }
        .put(
            StorageKey::sedimentree_stratum(&self.doc_id, stratum.start().into(), stratum.end().into()),
            raw,
        )
        .await;
        Ok(())
    }

    async fn load_blob(
        &self,
        blob_hash: sedimentree::Digest,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(super::Storage {
            io_handle: &self.io_handle,
        }
        .load(StorageKey::blob(blob_hash.into()))
        .await)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid commit: {0}")]
    InvalidCommit(String),
}
