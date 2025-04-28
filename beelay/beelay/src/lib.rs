use beelay_core::{
    io::{IoResult, IoTask},
    loading::Step,
    Beelay, Config, UnixTimestampMillis,
};
pub use beelay_core::{Commit, CommitBundle, CommitHash, CommitOrBundle, DocumentId, StorageKey};
use futures::StreamExt;

pub mod document;
pub mod signing;
pub mod storage;

pub struct Repo<S: storage::Storage, K: signing::Signing, R: rand::RngCore + rand::CryptoRng> {
    pub storage: S,
    pub signing: K,
    pub core: Beelay<R>,
}

impl<S: storage::Storage, K: signing::Signing, R: rand::RngCore + rand::CryptoRng + Clone>
    Repo<S, K, R>
{
    pub fn new(storage: S, signing: K, core: Beelay<R>) -> Self {
        Self {
            storage,
            signing,
            core,
        }
    }

    pub async fn load(storage: S, signer: K, csprng: R) -> Self {
        let now = UnixTimestampMillis::now();
        let config = Config::new(csprng, signer.verifying_key());
        let init = Beelay::load(config, now);

        let running_tasks = futures::stream::FuturesUnordered::new();
        let mut completed_tasks = Vec::new();

        let beelay = loop {
            match step {
                Step::Loading(loading, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(&mut storage, &mut signing_key, task);
                        running_tasks.push(result);
                    }
                    if let Some(task_result) = running_tasks.pop() {
                        step = loading.handle_io_complete(UnixTimestampMillis::now(), task_result);
                        continue;
                    } else {
                        panic!("no tasks running but still loading");
                    }
                }
                Step::Loaded(beelay, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(&mut storage, &mut signing_key, task);
                        running_tasks.push(result);
                    }
                    break beelay;
                }
            }
            let next_task = running_tasks.select_next_some();
        };

        Self::new(storage, signing, core)
    }

    pub async fn create(&self, initial_commit: Commit) -> DocumentId {
        todo!()
    }

    pub async fn add_commits(
        &self,
        doc_id: &DocumentId,
        commits: Vec<CommitOrBundle>,
    ) -> Result<(), error::AddCommits> {
        Err(error::AddCommits)
    }

    pub async fn find(&self, document_id: DocumentId) -> Option<document::Document> {
        None
    }
}

async fn handle_task<S: storage::Storage, K: signing::Signing>(
    storage: &mut S,
    signer: &mut K,
    task: IoTask,
) -> IoResult {
    todo!()
}

pub mod error {
    #[derive(Debug, thiserror::Error)]
    #[error("failed")]
    pub struct AddCommits;
}
