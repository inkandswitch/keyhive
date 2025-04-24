use std::{collections::HashMap, future::Future};

use beelay_core::{
    io::{IoResult, IoTask},
    loading::Step,
    Beelay, Config, StorageKey, UnixTimestampMillis,
};
use futures::StreamExt;
use keyhive_core::crypto::verifiable::Verifiable;

pub struct Repo<S: Storage, K: Signing, R: rand::RngCore + rand::CryptoRng> {
    pub storage: S,
    pub signing: K,
    pub core: Beelay<R>,
}

impl<S: Storage, K: Signing, R: rand::RngCore + rand::CryptoRng + Clone> Repo<S, K, R> {
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
}

async fn handle_task<S: Storage, K: Signing>(
    storage: &mut S,
    signer: &mut K,
    task: IoTask,
) -> IoResult {
    todo!()
}

pub trait Signing: Verifiable {}

pub trait Storage {
    type Error: std::error::Error;

    fn put(
        &mut self,
        key: StorageKey,
        value: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn load(
        &mut self,
        key: StorageKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send;

    // Load the tree from this prefix
    fn load_range(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<HashMap<StorageKey, Vec<u8>>, Self::Error>> + Send;

    fn delete(&mut self, key: StorageKey) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
