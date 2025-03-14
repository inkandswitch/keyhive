use std::str::FromStr;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use futures::channel::mpsc;
use futures::channel::oneshot;
use keyhive_core::keyhive::Keyhive;

use crate::doc_state::DocState;
use crate::io::{IoHandle, IoResult};
use crate::state::State;
use crate::task_context::Storage;
use crate::{driver, DocumentId, PeerId, Signer};
use crate::{io::IoTask, task_context::DocStorage, Beelay, StorageKey, UnixTimestampMillis};

pub struct Loading<R: rand::Rng + rand::CryptoRng + Clone + 'static> {
    driver: driver::Driver,
    result: oneshot::Receiver<LoadedParts<R>>,
}

pub(crate) struct LoadedParts<R: rand::Rng + rand::CryptoRng> {
    pub(crate) state: Rc<RefCell<State<R>>>,
    pub(crate) peer_id: PeerId,
}

pub enum Step<R: rand::Rng + rand::CryptoRng + Clone + 'static> {
    Loading(Loading<R>, Vec<IoTask>),
    Loaded(Beelay<R>, Vec<IoTask>),
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> Loading<R> {
    pub(crate) fn new(
        now: UnixTimestampMillis,
        driver: driver::Driver,
        rx_loaded: oneshot::Receiver<LoadedParts<R>>,
    ) -> Step<R> {
        let loading = Self {
            result: rx_loaded,
            driver,
        };
        loading.step(now)
    }

    fn step(mut self, now: UnixTimestampMillis) -> Step<R> {
        let new_events = self.driver.step(now);
        if let Ok(Some(parts)) = self.result.try_recv() {
            Step::Loaded(Beelay::loaded(parts, self.driver), new_events.new_tasks)
        } else {
            Step::Loading(self, new_events.new_tasks)
        }
    }

    pub fn handle_io_complete(mut self, now: UnixTimestampMillis, result: IoResult) -> Step<R> {
        self.driver.handle_io_complete(result);
        self.step(now)
    }
}

pub(crate) async fn load_keyhive<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    io: IoHandle,
    rng: R,
    signer: Signer,
) -> (
    Keyhive<Signer, crate::CommitHash, crate::keyhive::Listener, R>,
    mpsc::UnboundedReceiver<
        keyhive_core::event::Event<Signer, crate::CommitHash, crate::keyhive::Listener>,
    >,
) {
    let (tx, rx) = mpsc::unbounded();
    let listener = crate::keyhive::Listener::new(tx);

    // let signer = Signer::new(verifying_key, io.clone());
    let mut keyhive = if let Some(archive) = crate::keyhive_storage::load_archive(io.clone()).await
    {
        tracing::trace!("keyhive archive found on disk, attempting to load");
        match keyhive_core::keyhive::Keyhive::try_from_archive(
            &archive,
            signer.clone(),
            listener.clone(),
            rng.clone(),
        ) {
            Ok(k) => {
                tracing::debug!("loaded keyhive archive");
                k
            }
            Err(e) => {
                tracing::error!(err=?e, "failed to load keyhive archive");
                keyhive_core::keyhive::Keyhive::generate(signer, listener.clone(), rng.clone())
                    .await
                    .unwrap()
            }
        }
    } else {
        tracing::trace!("no archive found on disk, creating a new one");
        let result =
            keyhive_core::keyhive::Keyhive::generate(signer, listener.clone(), rng.clone())
                .await
                .unwrap();
        let archived = result.into_archive();
        crate::keyhive_storage::save_archive(io.clone(), archived).await;
        result
    };
    let events = crate::keyhive_storage::load_events(io).await;
    tracing::trace!(num_events = events.len(), "loading keyhive events");
    for event in events {
        if let Err(e) = keyhive.receive_static_event(event) {
            tracing::error!(err=?e, "failed to handle keyhive event");
        }
    }

    (keyhive, rx)
}

pub(crate) async fn load_docs(io: IoHandle) -> HashMap<DocumentId, DocState> {
    let docs = Storage::new(&io)
        .list_one_level(StorageKey::sedimentrees())
        .await;
    tracing::debug!(num_docs = docs.len(), "loading documents");
    let load_futs = docs.into_iter().filter_map(|doc_id_key| {
        let Some(name) = doc_id_key.name() else {
            return None;
        };
        let doc_id = match DocumentId::from_str(name) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(?doc_id_key, err=?e, "failed to parse stored document id");
                return None;
            }
        };
        let doc_storage = DocStorage::new(io.clone(), doc_id);
        Some(async move {
            let doc = crate::sedimentree::storage::load(doc_storage).await;
            (doc_id, doc)
        })
    });
    futures::future::join_all(load_futs)
        .await
        .into_iter()
        .filter_map(|(doc_id, doc_result)| match doc_result {
            Ok(Some(doc)) => Some((doc_id, DocState::new(doc))),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(err=?e, %doc_id, "failed to load document");
                None
            }
        })
        .collect()
}
