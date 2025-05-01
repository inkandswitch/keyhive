use beelay_core::{
    io::{IoAction, IoResult, IoTask},
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
    pub core: Beelay<R>, // TODO wrap me!
}

impl<
        S: storage::Storage + Clone,
        K: signing::Signing + Clone,
        R: rand::RngCore + rand::CryptoRng + Clone + 'static,
    > Repo<S, K, R>
{
    pub fn new(storage: S, signing: K, core: Beelay<R>) -> Self {
        Self {
            storage,
            signing,
            core,
        }
    }

    pub async fn load(storage: S, signer: K, csprng: R) -> Self {
        let config = Config::new(csprng, signer.verifying_key());
        let init = Beelay::load(config, UnixTimestampMillis::now());
        let mut running_tasks = futures::stream::FuturesUnordered::new();

        let mut loading = match init {
            Step::Loading(loading, io_tasks) => {
                for task in io_tasks {
                    let fut = handle_task(storage.clone(), signer.clone(), task);
                    running_tasks.push(fut);
                }
                loading
            }
            Step::Loaded(loaded, io_tasks) => {
                futures::future::join_all(
                    io_tasks
                        .into_iter()
                        .map(|task| handle_task(storage.clone(), signer.clone(), task)),
                )
                .await;

                return Self {
                    storage,
                    signing: signer,
                    core: loaded,
                };
            }
        };

        loop {
            let next = running_tasks.select_next_some().await;
            match loading.handle_io_complete(UnixTimestampMillis::now(), next) {
                Step::Loading(next_loading, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(storage.clone(), signer.clone(), task);
                        running_tasks.push(result);
                    }
                    loading = next_loading
                }
                Step::Loaded(loaded, io_tasks) => {
                    futures::future::join_all(
                        io_tasks
                            .into_iter()
                            .map(|task| handle_task(storage.clone(), signer.clone(), task)),
                    )
                    .await;

                    return Self {
                        storage,
                        signing: signer,
                        core: loaded,
                    };
                }
            };
        }
    }

    pub async fn create(&self, initial_commit: Commit) -> DocumentId {
        todo!()
    }

    pub async fn add_commits(
        &self,
        doc_id: &DocumentId,
        commits: Vec<CommitOrBundle>,
    ) -> Result<(), error::AddCommits> {
        // TODO
        Err(error::AddCommits)
    }

    pub async fn find(&self, document_id: DocumentId) -> Option<document::Document> {
        // TODO
        None
    }
}

async fn handle_task<S: storage::Storage, K: signing::Signing>(
    mut storage: S,
    signer: K,
    task: IoTask,
) -> IoResult {
    let task_id = task.id();
    match task.take_action() {
        IoAction::Load { key } => {
            let content = storage.load(key).await.expect("FIXME");
            IoResult::load(task_id, content)
        }
        IoAction::LoadRange { prefix } => {
            let range = storage.load_range(prefix).await.expect("FIXME");
            IoResult::load_range(task_id, range)
        }
        IoAction::ListOneLevel { prefix } => {
            let one_level = storage.list_one_level(prefix).await.expect("FIXME");
            IoResult::list_one_level(task_id, one_level)
        }
        IoAction::Put { key, data } => {
            storage.put(key, data).await;
            IoResult::put(task_id)
        }
        IoAction::Delete { key } => {
            storage.delete(key).await;
            IoResult::delete(task_id)
        }
        IoAction::Sign { payload } => {
            let signature = signer.sign(&payload).await.unwrap();
            IoResult::sign(task_id, signature)
        }
    }
}

pub mod error {
    #[derive(Debug, thiserror::Error)]
    #[error("failed")]
    pub struct AddCommits;
}
