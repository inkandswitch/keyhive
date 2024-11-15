use std::collections::{HashMap, HashSet};

use beelay_core::{
    io::{IoAction, IoResult},
    Audience, BundleSpec, PeerAddress, PeerId, RequestId, RpcResponse, SignedMessage, SnapshotId,
    StoryResult, UnixTimestamp,
};
pub use beelay_core::{
    AddLink, Commit, CommitBundle, CommitHash, CommitOrBundle, DocumentHeads, DocumentId,
    Forwarding, StorageKey, StreamDirection, SyncDocResult,
};
use ed25519_dalek::SigningKey;
use error::ConnectionError;
use futures::{
    channel::{mpsc, oneshot},
    pin_mut, Future, FutureExt, Sink, SinkExt, Stream, StreamExt as _,
};
mod runtime;
mod storage;
pub use storage::Storage;
use tracing::Instrument;
mod fs_store;
pub mod tokio;
mod websocket;

#[derive(Clone)]
pub struct Beelay {
    peer_id: PeerId,
    core_tx: futures::channel::mpsc::Sender<Message>,
}

impl Beelay {
    pub fn builder() -> BeelayBuilder<rand::rngs::OsRng, storage::InMemoryStorage> {
        BeelayBuilder::new(rand::rngs::OsRng, storage::InMemoryStorage::new())
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub async fn create_doc(&mut self) -> Result<DocumentId, error::Error> {
        let (tx, rx) = oneshot::channel();
        self.core_tx.send(Message::CreateDoc(tx)).await?;
        Ok(rx.await?)
    }

    pub async fn add_commits(
        &mut self,
        doc_id: DocumentId,
        commits: Vec<Commit>,
    ) -> Result<Vec<BundleSpec>, error::Error> {
        let (tx, rx) = oneshot::channel();
        self.core_tx
            .send(Message::AddCommits(tx, doc_id, commits))
            .await?;
        Ok(rx.await?)
    }

    pub async fn add_link(&mut self, add: AddLink) -> Result<(), error::Error> {
        let (tx, rx) = oneshot::channel();
        self.core_tx.send(Message::AddLink(tx, add)).await?;
        Ok(rx.await?)
    }

    pub async fn add_bundle(
        &mut self,
        doc: DocumentId,
        bundle: CommitBundle,
    ) -> Result<(), error::Error> {
        let (tx, rx) = oneshot::channel();
        self.core_tx
            .send(Message::AddBundle(tx, doc, bundle))
            .await?;
        Ok(rx.await?)
    }

    pub async fn load_doc(
        &mut self,
        doc_id: DocumentId,
    ) -> Result<Option<Vec<CommitOrBundle>>, error::Error> {
        let (tx, rx) = oneshot::channel();
        self.core_tx.send(Message::LoadDoc(tx, doc_id)).await?;
        Ok(rx.await?)
    }

    pub async fn peers(&self) -> Result<HashSet<PeerAddress>, error::Error> {
        let (tx, rx) = oneshot::channel();
        let mut core_tx = self.core_tx.clone();
        core_tx.send(Message::Peers(tx)).await?;
        Ok(rx.await?)
    }

    pub async fn sync_doc(
        &mut self,
        doc_id: DocumentId,
    ) -> Result<
        HashMap<PeerAddress, Result<SyncDocResult, beelay_core::error::SyncDoc>>,
        error::Error,
    > {
        let mut results = Vec::new();
        let peers = self.peers().await?;
        for peer in peers {
            let (tx, rx) = oneshot::channel();
            self.core_tx
                .send(Message::SyncDoc(tx, doc_id, peer.clone()))
                .await?;
            results.push(async move {
                let result = rx.await?;
                Ok::<_, error::Error>((peer, result))
            });
        }
        let results = futures::future::join_all(results.into_iter());
        let result = results.await.into_iter().collect::<Result<Vec<_>, _>>()?;
        Ok(result.into_iter().collect())
    }

    pub async fn new_bundle_requests(
        &mut self,
    ) -> Result<impl Stream<Item = beelay_core::BundleSpec>, error::Error> {
        let (tx, rx) = futures::channel::mpsc::channel(16);
        self.core_tx
            .send(Message::ListenForBundleRequests(tx))
            .await?;
        Ok(rx)
    }

    pub async fn listen(
        &self,
        peer: PeerAddress,
        snapshot: SnapshotId,
    ) -> Result<(), error::Error> {
        let (tx, rx) = oneshot::channel();
        let mut core_tx = self.core_tx.clone();
        core_tx.send(Message::Listen(peer, snapshot, tx)).await?;
        let _ = rx.await;
        Ok(())
    }

    /// Handle a stream, first performing a handshake
    pub fn accept_stream<'a, 'b, RecvError, MsgStream, SendError, MsgSink>(
        &'a self,
        stream: MsgStream,
        sink: MsgSink,
        receive_audience: Option<String>,
        forwarding: Forwarding,
    ) -> Connecting<
        impl Future<Output = Result<(), error::ConnectionError<RecvError, SendError>>> + 'b,
    >
    where
        MsgStream: Stream<Item = Result<Vec<u8>, RecvError>> + Send + 'b,
        MsgSink: Sink<Vec<u8>, Error = SendError> + Send + 'b,
        RecvError: std::error::Error,
        SendError: std::error::Error + Send + 'b,
    {
        self.handle_stream(
            stream,
            sink,
            StreamDirection::Accepting { receive_audience },
            forwarding,
        )
    }

    pub fn connect_stream<'a, 'b, RecvError, MsgStream, SendError, MsgSink>(
        &'a self,
        stream: MsgStream,
        sink: MsgSink,
        remote_audience: Audience,
        forwarding: Forwarding,
    ) -> Connecting<
        impl Future<Output = Result<(), error::ConnectionError<RecvError, SendError>>> + 'b,
    >
    where
        MsgStream: Stream<Item = Result<Vec<u8>, RecvError>> + Send + 'b,
        MsgSink: Sink<Vec<u8>, Error = SendError> + Send + 'b,
        RecvError: std::error::Error,
        SendError: std::error::Error + Send + 'b,
    {
        self.handle_stream(
            stream,
            sink,
            StreamDirection::Connecting { remote_audience },
            forwarding,
        )
    }

    #[tracing::instrument(skip(self, stream, sink), fields(peer_id = tracing::field::Empty))]
    fn handle_stream<'a, 'b, RecvError, MsgStream, SendError, MsgSink>(
        &'a self,
        stream: MsgStream,
        sink: MsgSink,
        direction: StreamDirection,
        forwarding: Forwarding,
    ) -> Connecting<
        impl Future<Output = Result<(), error::ConnectionError<RecvError, SendError>>> + 'b,
    >
    where
        MsgStream: Stream<Item = Result<Vec<u8>, RecvError>> + Send + 'b,
        MsgSink: Sink<Vec<u8>, Error = SendError> + Send + 'b,
        RecvError: std::error::Error,
        SendError: std::error::Error + Send + 'b,
    {
        {
            tracing::Span::current().record("peer_id", self.peer_id.to_string());
        }
        let mut core_tx = self.core_tx.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut ready_tx = Some(ready_tx);
        let driver = async move {
            let (tx, rx) = oneshot::channel();
            let msg = Message::NewStream(direction, forwarding, tx);
            core_tx.send(msg).await.map_err(|_| ConnectionError::DriverStopped)?;
            let (stream_id, mut stream_evts) = rx
                .await
                .map_err(|_| error::ConnectionError::DriverStopped)?;

            pin_mut!(stream);
            pin_mut!(sink);

            loop {
                futures::select! {
                    incoming = stream.next().fuse() => match incoming {
                        Some(msg) => {
                            let msg = match msg {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::warn!(err=?e, "error receiving message");
                                    break;
                                }
                            };
                            let (tx, rx) = oneshot::channel();
                            let msg = Message::HandleMessage(stream_id, msg, tx);
                            core_tx.send(msg).await.map_err(|_| ConnectionError::DriverStopped)?;
                            let result = rx.await.map_err(|_| ConnectionError::DriverStopped)?;
                            if let Err(e) = result {
                                tracing::warn!(err=?e, "error handling stream event");
                            }
                        },
                        None => {
                            tracing::debug!("incoming stream closed");
                            let (tx, rx) = oneshot::channel();
                            let msg = Message::DisconnectStream(stream_id, tx);
                            core_tx.send(msg).await.map_err(|_| ConnectionError::DriverStopped)?;
                            let _ = rx.await;
                            break;
                        }
                    },
                    stream_evt = stream_evts.next().fuse() => match stream_evt {
                        Some(evt) => match evt {
                            beelay_core::StreamEvent::Close => {
                                tracing::debug!("stream event stream closed");
                                break;
                            }
                            beelay_core::StreamEvent::HandshakeComplete { their_peer_id: _ } => {
                                tracing::debug!("handshake complete");
                                if let Some(ready_tx) = ready_tx.take() {
                                    let _ = ready_tx.send(());
                                }
                            }
                            beelay_core::StreamEvent::Send(vec) => {
                                if let Err(e) = sink.send(vec).await {
                                    tracing::warn!(err=?e, "error sending message, closing channel");
                                    break;
                                }
                            }
                        },
                        None => {
                            tracing::debug!("stream event stream closed unexpectedly");
                            break;
                        }
                    }
                }
            }
            if let Err(e) = sink.close().await {
                tracing::warn!(err=?e, "error closing sink");
            }
            Ok(())
        }
        .instrument(tracing::info_span!("handle_stream"));
        Connecting {
            ready: ready_rx,
            driver,
        }
    }

    pub async fn handle_request(
        &self,
        req: beelay_core::SignedMessage,
    ) -> Result<beelay_core::RpcResponse, error::Error> {
        let (tx, rx) = oneshot::channel();
        let mut core_tx = self.core_tx.clone();
        core_tx.send(Message::HandleRequest(req, tx)).await?;
        Ok(rx.await?)
    }

    pub async fn stop(&self) {
        let (tx, rx) = oneshot::channel();
        let mut core_tx = self.core_tx.clone();
        let _ = core_tx.send(Message::Stop(tx)).await;
        let _ = rx.await;
    }
}

pub struct BeelayBuilder<
    R: rand::Rng + rand::CryptoRng + Send + 'static,
    S: Storage + Send + Clone + 'static,
> {
    rng: R,
    storage: S,
    signing_key: SigningKey,
}

impl<R: rand::Rng + rand::CryptoRng + Send + 'static, S: Storage + Send + Clone + 'static>
    BeelayBuilder<R, S>
{
    pub fn new(mut rng: R, storage: S) -> Self {
        let signing_key = SigningKey::generate(&mut rng);
        Self {
            rng,
            storage,
            signing_key,
        }
    }

    pub fn with_storage<S2: Storage + Send + Clone + 'static>(
        self,
        storage: S2,
    ) -> BeelayBuilder<R, S2> {
        BeelayBuilder {
            rng: self.rng,
            storage,
            signing_key: self.signing_key,
        }
    }

    pub fn with_rng<R2: rand::Rng + rand::CryptoRng + Send + 'static>(
        self,
        rng: R2,
    ) -> BeelayBuilder<R2, S> {
        BeelayBuilder {
            rng,
            storage: self.storage,
            signing_key: self.signing_key,
        }
    }

    pub fn with_signing_key(self, key: SigningKey) -> BeelayBuilder<R, S> {
        BeelayBuilder {
            rng: self.rng,
            storage: self.storage,
            signing_key: key,
        }
    }

    pub async fn spawn<Runtime: runtime::RuntimeHandle>(self, runtime: Runtime) -> Beelay {
        let (tx, rx) = futures::channel::mpsc::channel(16);
        let signing_key = self.signing_key.clone();
        #[allow(clippy::let_underscore_future)]
        let _ = runtime.spawn(drive(rx, self));
        Beelay {
            core_tx: tx,
            peer_id: beelay_core::PeerId::from(signing_key.verifying_key()),
        }
    }

    #[cfg(feature = "tokio")]
    pub async fn spawn_tokio(self) -> Beelay {
        self.spawn(::tokio::runtime::Handle::current()).await
    }
}

#[derive(Debug)]
enum Message {
    NewStream(
        beelay_core::StreamDirection,
        Forwarding,
        oneshot::Sender<(
            beelay_core::StreamId,
            mpsc::Receiver<beelay_core::StreamEvent>,
        )>,
    ),
    DisconnectStream(beelay_core::StreamId, oneshot::Sender<()>),
    HandleMessage(
        beelay_core::StreamId,
        Vec<u8>,
        oneshot::Sender<Result<(), beelay_core::StreamError>>,
    ),
    RegisterEndpoint(
        beelay_core::Audience,
        Forwarding,
        futures::channel::oneshot::Sender<(
            beelay_core::EndpointId,
            mpsc::Receiver<(beelay_core::RequestId, beelay_core::SignedMessage)>,
        )>,
    ),
    UnregisterEndpoint(
        beelay_core::EndpointId,
        futures::channel::oneshot::Sender<()>,
    ),
    HandleRequest(
        SignedMessage,
        futures::channel::oneshot::Sender<beelay_core::RpcResponse>,
    ),
    HandleResponse(RequestId, RpcResponse),
    CreateDoc(oneshot::Sender<DocumentId>),
    AddCommits(oneshot::Sender<Vec<BundleSpec>>, DocumentId, Vec<Commit>),
    SyncDoc(
        oneshot::Sender<Result<SyncDocResult, beelay_core::error::SyncDoc>>,
        DocumentId,
        PeerAddress,
    ),
    AddLink(oneshot::Sender<()>, AddLink),
    AddBundle(oneshot::Sender<()>, DocumentId, CommitBundle),
    LoadDoc(oneshot::Sender<Option<Vec<CommitOrBundle>>>, DocumentId),
    ListenForBundleRequests(futures::channel::mpsc::Sender<beelay_core::BundleSpec>),
    Peers(oneshot::Sender<HashSet<PeerAddress>>),
    Listen(
        PeerAddress,
        SnapshotId,
        oneshot::Sender<Result<(), beelay_core::error::Listen>>,
    ),
    Stop(oneshot::Sender<()>),
}

#[tracing::instrument(skip(input, builder), fields(peer_id = tracing::field::Empty))]
async fn drive<
    R: rand::Rng + rand::CryptoRng + Send + 'static,
    S: Storage + Clone + Send + 'static,
>(
    input: futures::channel::mpsc::Receiver<Message>,
    builder: BeelayBuilder<R, S>,
) {
    {
        let our_peer_id = beelay_core::PeerId::from(builder.signing_key.verifying_key());
        tracing::Span::current().record("peer_id", our_peer_id.to_string());
    }
    let mut core = beelay_core::Beelay::new(builder.rng, Some(builder.signing_key));
    let mut awaiting_stories = HashMap::new();
    let mut awaiting_requests = HashMap::new();
    let mut awaiting_stop = Vec::new();
    let mut endpoints = HashMap::new();

    let mut stream_listeners: HashMap<
        beelay_core::StreamId,
        Vec<mpsc::Sender<beelay_core::StreamEvent>>,
    > = HashMap::new();

    let storage = builder.storage;
    let mut bundle_spec_listeners = Vec::new();

    enum Event<S: Storage> {
        Input(Message),
        InputDropped,
        IoComplete(Result<IoResult, S::Error>),
    }

    impl<S: Storage> std::fmt::Debug for Event<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Event::Input(msg) => write!(f, "Event::Input({:?})", msg),
                Event::InputDropped => write!(f, "Event::InputDropped"),
                Event::IoComplete(_) => write!(f, "Event::IoComplete"),
            }
        }
    }

    let mut events = futures::stream::SelectAll::new();
    events.push(
        input
            .map(Event::<S>::Input)
            .chain(futures::stream::once(async { Event::InputDropped }))
            .boxed(),
    );

    tracing::debug!("beelay driver started");

    while let Some(event) = events.next().await {
        let event_results = match event {
            Event::Input(message) => match message {
                Message::Stop(reply) => {
                    awaiting_stop.push(reply);
                    let event = beelay_core::Event::stop();
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::NewStream(direction, forwarding, reply) => {
                    let (story_id, event) =
                        beelay_core::Event::create_stream(direction, forwarding);
                    awaiting_stories.insert(story_id, AwaitingStory::CreateStream(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::DisconnectStream(stream_id, reply) => {
                    let (story_id, event) = beelay_core::Event::disconnect_stream(stream_id);
                    awaiting_stories.insert(story_id, AwaitingStory::DisconnectStream(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::HandleMessage(stream, msg, reply) => {
                    let (story_id, event) = beelay_core::Event::handle_message(stream, msg);
                    awaiting_stories.insert(story_id, AwaitingStory::HandleMessage(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::RegisterEndpoint(remote_audience, forwarding, reply) => {
                    let (story_id, event) =
                        beelay_core::Event::register_endpoint(remote_audience, forwarding);
                    awaiting_stories.insert(story_id, AwaitingStory::RegisterEndpoint(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::UnregisterEndpoint(endpoint_id, reply) => {
                    let (story_id, event) = beelay_core::Event::unregister_endpoint(endpoint_id);
                    awaiting_stories.insert(story_id, AwaitingStory::UnregisterEndpoint(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::HandleRequest(req, reply) => {
                    let (request_id, event) = beelay_core::Event::handle_request(req);
                    awaiting_requests.insert(request_id, reply);
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::HandleResponse(req_id, resp) => {
                    let event = beelay_core::Event::handle_response(req_id, resp);
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::CreateDoc(reply) => {
                    let (story_id, event) = beelay_core::Event::create_doc();
                    awaiting_stories.insert(story_id, AwaitingStory::CreateDoc(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::AddCommits(reply, dag_id, commits) => {
                    let (story_id, event) = beelay_core::Event::add_commits(dag_id, commits);
                    awaiting_stories.insert(story_id, AwaitingStory::AddCommits(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::SyncDoc(reply, doc_id, peer) => {
                    let (story_id, event) = beelay_core::Event::sync_doc(doc_id, peer);
                    awaiting_stories.insert(story_id, AwaitingStory::SyncDoc(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::AddLink(reply, addlink) => {
                    let (story_id, event) = beelay_core::Event::add_link(addlink);
                    awaiting_stories.insert(story_id, AwaitingStory::AddLink(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::AddBundle(reply, doc, bundle) => {
                    let (story_id, event) = beelay_core::Event::add_bundle(doc, bundle);
                    awaiting_stories.insert(story_id, AwaitingStory::AddBundle(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::LoadDoc(reply, dag_id) => {
                    let (story_id, event) = beelay_core::Event::load_doc(dag_id);
                    awaiting_stories.insert(story_id, AwaitingStory::LoadDoc(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
                Message::ListenForBundleRequests(listener) => {
                    bundle_spec_listeners.push(listener);
                    continue;
                }
                Message::Peers(reply) => {
                    let peers = endpoints
                        .keys()
                        .copied()
                        .map(PeerAddress::from)
                        .chain(stream_listeners.keys().copied().map(PeerAddress::from))
                        .collect();
                    let _ = reply.send(peers);
                    continue;
                }
                Message::Listen(peer, snapshot, reply) => {
                    let (story, event) = beelay_core::Event::listen(peer, snapshot);
                    awaiting_stories.insert(story, AwaitingStory::Listen(reply));
                    core.handle_event(UnixTimestamp::now(), event)
                }
            },
            Event::IoComplete(result) => match result {
                Ok(r) => {
                    core.handle_event(UnixTimestamp::now(), beelay_core::Event::io_complete(r))
                }
                Err(e) => {
                    tracing::error!(err=?e, "error running storage task");
                    panic!("error in storage: {:?}", e);
                }
            },
            Event::InputDropped => {
                tracing::warn!("sender for beelay-core dropped, stopping driver");
                return;
            }
        };
        let event_results = event_results.unwrap();
        for (story_id, result) in event_results.completed_stories {
            let Ok(result) = result else {
                // We're stopping, just drop the result
                continue;
            };
            let awaiting = awaiting_stories.remove(&story_id).unwrap();
            match (result, awaiting) {
                (
                    StoryResult::RegisterEndpoint(endpoint_id),
                    AwaitingStory::RegisterEndpoint(reply),
                ) => {
                    let (tx, rx) = mpsc::channel(16);
                    endpoints.insert(endpoint_id, tx);
                    if let Err(e) = reply.send((endpoint_id, rx)) {
                        tracing::warn!(err=?e, "error sending register_endpoint reply");
                    }
                }
                (StoryResult::UnregisterEndpoint, AwaitingStory::UnregisterEndpoint(reply)) => {
                    if let Err(e) = reply.send(()) {
                        tracing::warn!(err=?e, "error sending unregister_endpoint reply");
                    }
                }
                (StoryResult::CreateStream(stream_id), AwaitingStory::CreateStream(reply)) => {
                    let (tx, rx) = mpsc::channel(16);
                    stream_listeners.insert(stream_id, vec![tx]);
                    if let Err(e) = reply.send((stream_id, rx)) {
                        tracing::warn!(err=?e, "error sending create_stream reply");
                    }
                }
                (StoryResult::DisconnectStream, AwaitingStory::DisconnectStream(reply)) => {
                    if let Err(e) = reply.send(()) {
                        tracing::warn!(err=?e, "error sending disconnect_stream reply");
                    }
                }
                (StoryResult::HandleMessage(result), AwaitingStory::HandleMessage(reply)) => {
                    if let Err(e) = reply.send(result) {
                        tracing::warn!(err=?e, "error sending handle_message reply");
                    }
                }
                (StoryResult::CreateDoc(doc_id), AwaitingStory::CreateDoc(reply)) => {
                    if let Err(e) = reply.send(doc_id) {
                        tracing::warn!(err=?e, "error sending create_dag reply");
                    }
                }
                (
                    StoryResult::AddCommits(new_required_bundles),
                    AwaitingStory::AddCommits(reply),
                ) => {
                    if let Err(e) = reply.send(new_required_bundles) {
                        tracing::warn!(err=?e, "error sending add_commits reply");
                    }
                }
                (StoryResult::SyncDoc(result), AwaitingStory::SyncDoc(reply)) => {
                    if reply.send(result).is_err() {
                        tracing::warn!("error sending sync_doc reply");
                    }
                }
                (StoryResult::AddLink, AwaitingStory::AddLink(reply)) => {
                    if let Err(e) = reply.send(()) {
                        tracing::warn!(err=?e, "error sending add_link reply");
                    }
                }
                (StoryResult::LoadDoc(dag), AwaitingStory::LoadDoc(reply)) => {
                    if let Err(e) = reply.send(dag) {
                        tracing::warn!(err=?e, "error sending load_dag reply");
                    }
                }
                (StoryResult::AddBundle, AwaitingStory::AddBundle(reply)) => {
                    if let Err(e) = reply.send(()) {
                        tracing::warn!(err=?e, "error sending add_bundle reply");
                    }
                }
                (StoryResult::Listen(result), AwaitingStory::Listen(reply)) => {
                    if let Err(e) = reply.send(result) {
                        tracing::warn!(err=?e, "error sending listen reply");
                    }
                }
                (result, awaiting) => {
                    panic!(
                        "unexpected result {:?} for awaiting story {:?}",
                        result, awaiting
                    );
                }
            }
        }
        for (request_id, response) in event_results.completed_requests {
            let Ok(response) = response else {
                continue;
            };
            if let Some(tx) = awaiting_requests.remove(&request_id) {
                if tx.send(response).is_err() {
                    tracing::warn!("error sending response");
                }
            } else {
                tracing::warn!("unexpected response: {:?}", response);
            }
        }
        for (endpoint_id, new_requests) in event_results.new_requests {
            if let Some(tx) = endpoints.get_mut(&endpoint_id) {
                for beelay_core::NewRequest { id, request } in new_requests {
                    if tx.try_send((id, request)).is_err() {
                        todo!("handle congested endpoints");
                    }
                }
            } else {
                tracing::warn!("unexpected new requests for endpoint: {:?}", endpoint_id);
            }
        }
        for new_task in event_results.new_tasks {
            let task_id = new_task.id();
            let mut storage = storage.clone();
            let task = async move {
                let result = match new_task.take_action() {
                    IoAction::Put { key, data } => {
                        storage.put(key, data).await.map(|_| IoResult::put(task_id))
                    }
                    IoAction::Load { key } => storage
                        .load(key)
                        .await
                        .map(|result| IoResult::load(task_id, result)),
                    IoAction::LoadRange { prefix } => storage
                        .load_range(prefix)
                        .await
                        .map(|result| IoResult::load_range(task_id, result)),
                    IoAction::Delete { key } => {
                        storage.delete(key).await.map(|_| IoResult::delete(task_id))
                    }
                };
                Event::IoComplete(result)
            };
            events.push(futures::stream::once(task).boxed());
        }
        for (stream_id, evts) in event_results.new_stream_events {
            if let Some(senders) = stream_listeners.get_mut(&stream_id) {
                for sender in senders {
                    for evt in &evts {
                        // TODO: handle busy senders
                        sender.try_send(evt.clone()).unwrap();
                    }
                }
            }
        }
        if event_results.stopped {
            break;
        }
    }
    for reply in awaiting_stop {
        let _ = reply.send(());
    }
    tracing::info!("beelay driver stopped");
}

#[derive(Debug)]
enum AwaitingStory {
    CreateDoc(oneshot::Sender<DocumentId>),
    AddCommits(oneshot::Sender<Vec<BundleSpec>>),
    AddLink(oneshot::Sender<()>),
    AddBundle(oneshot::Sender<()>),
    SyncDoc(oneshot::Sender<Result<SyncDocResult, beelay_core::error::SyncDoc>>),
    LoadDoc(oneshot::Sender<Option<Vec<CommitOrBundle>>>),
    Listen(oneshot::Sender<Result<(), beelay_core::error::Listen>>),
    CreateStream(
        oneshot::Sender<(
            beelay_core::StreamId,
            mpsc::Receiver<beelay_core::StreamEvent>,
        )>,
    ),
    DisconnectStream(oneshot::Sender<()>),
    HandleMessage(oneshot::Sender<Result<(), beelay_core::StreamError>>),
    RegisterEndpoint(
        oneshot::Sender<(
            beelay_core::EndpointId,
            mpsc::Receiver<(beelay_core::RequestId, beelay_core::SignedMessage)>,
        )>,
    ),
    UnregisterEndpoint(oneshot::Sender<()>),
}

pub struct Connecting<F> {
    pub ready: oneshot::Receiver<()>,
    pub driver: F,
}

pub mod error {
    pub struct Error(ErrorKind);

    impl From<futures::channel::mpsc::SendError> for Error {
        fn from(_: futures::channel::mpsc::SendError) -> Self {
            Self(ErrorKind::DriverStopped)
        }
    }

    impl From<futures::channel::oneshot::Canceled> for Error {
        fn from(_: futures::channel::oneshot::Canceled) -> Self {
            Self(ErrorKind::DriverStopped)
        }
    }

    pub(super) enum ErrorKind {
        DriverStopped,
        #[allow(dead_code)]
        Storage(String),
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                ErrorKind::DriverStopped => write!(f, "driver stopped"),
                ErrorKind::Storage(ref s) => write!(f, "storage error: {}", s),
            }
        }
    }

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for Error {}

    pub enum ConnectionError<RecvErr: std::error::Error, SendErr: std::error::Error> {
        DriverStopped,
        Recv(RecvErr),
        Send(SendErr),
    }

    impl<R: std::error::Error> From<futures::channel::mpsc::SendError>
        for ConnectionError<R, futures::channel::mpsc::SendError>
    {
        fn from(e: futures::channel::mpsc::SendError) -> Self {
            Self::Send(e)
        }
    }

    impl<RecvErr: std::error::Error, SendErr: std::error::Error> std::fmt::Display
        for ConnectionError<RecvErr, SendErr>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::DriverStopped => write!(f, "driver stopped"),
                Self::Recv(ref e) => write!(f, "error receiving message: {}", e),
                Self::Send(ref e) => write!(f, "error sending message: {}", e),
            }
        }
    }

    impl<RecvErr: std::error::Error, SendErr: std::error::Error> std::fmt::Debug
        for ConnectionError<RecvErr, SendErr>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl<RecvErr: std::error::Error, SendErr: std::error::Error> std::error::Error
        for ConnectionError<RecvErr, SendErr>
    {
    }
}
