use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use effects::IncomingResponse;
use futures::{future::LocalBoxFuture, FutureExt};
use io::IoResult;
use messages::{BlobRef, Message, Notification, Request, Response, TreePart, UploadItem};
pub use messages::{Envelope, Payload};
use rand::Rng;

mod blob;
pub use blob::BlobHash;
mod commit;
pub use commit::{Commit, CommitBundle, CommitHash, CommitOrBundle, InvalidCommitHash};
mod storage_key;
pub use storage_key::StorageKey;
mod reachability;
mod request_handlers;
pub use error::{Error, InvalidPeerId, InvalidRequestId};
pub mod io;
pub use io::IoTaskId;
mod stories;
pub use stories::{StoryId, StoryResult};
mod effects;
pub mod messages;
mod sedimentree;
mod snapshots;
mod subscriptions;
pub use snapshots::SnapshotId;
pub(crate) mod riblt;

mod hex;
mod leb128;
mod parse;

// # Notes on the use of async
//
// This library is designed to be a pure state machine which operates purely in terms of events
// which you feed to [`Beelay::handle_event`]. This makes it easy to integrate with diverse
// platforms via FFI. However, writing out the various state machines which are required to
// implement this is quite tedious and so we use use `async/await` syntax to make it more
// manageable. What does this mean?
//
// Async/await functions are compiled to state machines. Each of these state machines has a `poll`
// method which returns either `Poll::Ready(result)` to indicate that it's finished or
// `Poll::Pending` to indicate that there is more work to do. The `async/await` machinery wires up
// all the nested calls to `.await` such that the top level state machine returns `Poll::Pending`
// whenever it's nested state machines return `Poll::Pending`. It is the responsibility of whomever
// is calling `poll` to arrange for the state machine to be woken up again when something has
// changed. Arranging for this to happen is the cause of most of the complexity of async runtimes.
//
// In our case, it's quite simple to know when we need to wake up a future. We have two kinds of
// future, one representing a request we are in the process of handling, and one representing a
// "story" - a task initiated by the user. These are identified by a `RequestId` and a `StoryId`
// respectively. We represent each request and story type as async functions in `requests` and
// `stories` modules. The first argument to each of these functions is a `TaskEffects` struct. This
// struct keeps track of the ID of the initiating task and provides methods to initiate asynchronus
// work (e.g. `TaskEffects::load` to load things from storage). This means that we can track which
// tasks are waiting for which external events, then, whenever an external event arrives which
// completes the asynchronous work (such as a completed load from storage) we can look up the
// future representing the execution of that task and call `poll` on it.
//
// Most of the details of wiring up the effect tracking is in the `effects` module. But the concrete
// outcome is that all asynchronous work is represented as asynchronous functions in the `TaskEffects`
// struct, which must be passed as the first arguemtn to request and story handlers.

/// The main entrypoint for this library
///
/// A `Beelay` is a little state machine. You interact with it by creating [`Event`]s and passing
/// them to the [`Beelay::handle_event`] method. The `handle_event` method will return an
/// [`EventResults`] struct on each call which contains any effects which need to be applied to the
/// outside world. These effects are:
///
/// * New messages to be sent to peers
/// * Storage tasks to be executed
/// * Completed stories
///
/// Stories? A story represents a long running task which was initiated by the outside world. For
/// example, if the caller wants to add some commits to a DAG, then they will create an event
/// representing the initiation of a story using [`Event::add_commits`]. This method returns both
/// an event to be passed to the `Beelay` and a `StoryId` which will be used to notify the caller
/// when the story is complete (and pass the results back to the caller).
pub struct Beelay<R> {
    peer_id: PeerId,
    /// The requests we are currently handling (i.e. the values here represent state machines which
    /// are suspended waiting for storage tasks to complete).
    request_handlers: HashMap<RequestId, LocalBoxFuture<'static, Option<OutgoingResponse>>>,
    /// Long running stories which are currently in progress
    stories: HashMap<StoryId, LocalBoxFuture<'static, StoryResult>>,
    /// The state which is available to each task (request handler or story)
    state: Rc<RefCell<effects::State<R>>>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct DocumentId([u8; 16]);

impl serde::Serialize for DocumentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as  the bs58 string
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl std::fmt::Display for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bs58::encode(&self.0).with_check().into_string().fmt(f)
    }
}

impl std::fmt::Debug for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DocumentId({})", self)
    }
}

impl From<[u8; 16]> for DocumentId {
    fn from(value: [u8; 16]) -> Self {
        DocumentId(value)
    }
}

impl std::str::FromStr for DocumentId {
    type Err = error::InvalidDocumentId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).with_check(None).into_vec()?;

        if bytes.len() == 16 {
            let mut id = [0; 16];
            id.copy_from_slice(&bytes);
            Ok(DocumentId(id))
        } else {
            Err(error::InvalidDocumentId::InvalidLength)
        }
    }
}

impl DocumentId {
    pub fn random<R: Rng>(rng: &mut R) -> DocumentId {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        DocumentId(id)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("DocumentId", |input| {
            let (input, bytes) = parse::arr::<16>(input)?;
            Ok((input, DocumentId::from(bytes)))
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

// The reason Beelay is not automatically Send is because it contains a few Rc<RefCell<T>> fields.
// And because it contains the `LocalBoxFuture` fields.
//
// The Rc fields are not send because:
//
// - Rc is not Send because it contains a pointer to both the data and the reference count.
// - RefCell is not Send because it allows mutable access to its contents across threads.
//
// However, we only allow mutation of the `Beelay` via the `handle_event` method and we never hand
// out the internal `Rc<RefCell<_>>` fields to anyone else. Specifically, the `Rc` fields exist so
// that we can hand mutable references to the `State` field to the `poll` method of the
// futures which we store in the `request_handlers` and `stories` maps. These references never
// escape the `Beelay`.
//
// The `LocalBoxFuture` fields are not Send for the same reason (they contain references to the
// `State` field). So the same reasoning applies.
//
// I _think_ that this means it is safe to implement Send for Beelay. If it turns out that this
// is not the case then we would need to switch to using `Arc<RwLock<T>>` instead of
// `Rc<RefCell<T>>` which I am loath to do because it is not no_std compatible.
unsafe impl<R: Send> Send for Beelay<R> {}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
enum Task {
    Request(RequestId),
    Story(StoryId),
}

impl From<StoryId> for Task {
    fn from(value: StoryId) -> Self {
        Task::Story(value)
    }
}

impl From<RequestId> for Task {
    fn from(value: RequestId) -> Self {
        Task::Request(value)
    }
}

impl<R: rand::Rng + 'static> Beelay<R> {
    pub fn new(peer_id: PeerId, rng: R) -> Beelay<R> {
        Beelay {
            peer_id: peer_id.clone(),
            request_handlers: HashMap::new(),
            stories: HashMap::new(),
            state: Rc::new(RefCell::new(effects::State::new(rng, peer_id))),
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    #[tracing::instrument(skip(self, event), fields(local_peer=%self.peer_id))]
    pub fn handle_event(&mut self, event: Event) -> Result<EventResults, Error> {
        let mut woken_tasks: Vec<Task> = Vec::new();
        let mut event_results = EventResults {
            new_messages: Vec::new(),
            new_tasks: Vec::new(),
            completed_stories: HashMap::new(),
            notifications: Vec::new(),
            requested_docs: Vec::new(),
        };
        match event.0 {
            EventInner::IoComplete(result) => {
                woken_tasks.extend(self.state.borrow_mut().io.io_complete(result));
            }
            EventInner::Receive(envelope) => {
                let peer = envelope.sender().clone();
                match envelope.take_payload().into_message() {
                    Message::Request(id, request) => {
                        tracing::debug!(
                            request_id=%id,
                            request=%request,
                            %peer,
                            "received request"
                        );
                        if let Request::CreateSnapshot { root_doc } = &request {
                            event_results
                                .requested_docs
                                .push((peer.clone(), root_doc.clone()));
                        }
                        let req_effects = effects::TaskEffects::new(id, self.state.clone());
                        let response =
                            request_handlers::handle_request(req_effects, peer, id, request)
                                .boxed_local();
                        woken_tasks.push(id.into());
                        self.request_handlers.insert(id, response);
                    }
                    Message::Response(id, response) => {
                        tracing::debug!(
                            request_id=%id,
                            response=%response,
                            %peer,
                            "received response"
                        );
                        let response = IncomingResponse { id, response };
                        woken_tasks.extend(self.state.borrow_mut().io.response_received(response));
                    }
                    Message::Notification(notification) => {
                        tracing::debug!(?notification, "received notification");
                        let Notification {
                            from_peer,
                            doc,
                            data,
                        } = notification;
                        let UploadItem { blob, tree_part } = data;
                        let BlobRef::Inline(blob) = blob else {
                            panic!("blob refs in notifications not yet supported");
                        };
                        let data = match tree_part {
                            TreePart::Commit { hash, parents } => {
                                CommitOrBundle::Commit(Commit::new(parents, blob, hash))
                            }
                            TreePart::Stratum {
                                start,
                                end,
                                checkpoints,
                            } => CommitOrBundle::Bundle(
                                CommitBundle::builder()
                                    .start(start)
                                    .end(end)
                                    .bundled_commits(blob)
                                    .checkpoints(checkpoints)
                                    .build(),
                            ),
                        };
                        event_results.notifications.push(DocEvent {
                            peer: from_peer,
                            doc,
                            data,
                        });
                    }
                }
            }
            EventInner::BeginStory(story_id, story) => {
                let task_effects = effects::TaskEffects::new(story_id, self.state.clone());
                let future = stories::handle_story(task_effects, story);
                self.stories.insert(story_id, future);
                woken_tasks.push(story_id.into());
            }
        }
        let waker = Arc::new(effects::NoopWaker).into();
        for task in woken_tasks {
            let mut cx = std::task::Context::from_waker(&waker);
            match task {
                Task::Request(req_id) => {
                    if let std::task::Poll::Ready(response) = self
                        .request_handlers
                        .get_mut(&req_id)
                        .unwrap()
                        .poll_unpin(&mut cx)
                    {
                        if let Some(response) = response {
                            event_results.new_messages.push(Envelope {
                                sender: self.peer_id.clone(),
                                recipient: response.target,
                                payload: Payload::new(Message::Response(
                                    response.id,
                                    response.response,
                                )),
                            });
                        }
                        self.request_handlers.remove(&req_id);
                    };
                }
                Task::Story(story_id) => {
                    if let Some(fut) = self.stories.get_mut(&story_id) {
                        if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                            event_results.completed_stories.insert(story_id, result);
                            self.stories.remove(&story_id);
                        };
                    } else {
                        if cfg!(debug_assertions) {
                            panic!("woken task not found");
                        } else {
                            tracing::error!(?story_id, "woken task not found")
                        }
                    }
                }
            }
        }
        event_results
            .new_tasks
            .extend(self.state.borrow_mut().io.pop_new_tasks());
        event_results.new_messages.extend(
            self.state
                .borrow_mut()
                .io
                .pop_new_requests()
                .into_iter()
                .map(|(id, req)| Envelope {
                    sender: self.peer_id.clone(),
                    recipient: req.target,
                    payload: Payload::new(Message::Request(id, req.request)),
                }),
        );
        for (peer, notifications) in self.state.borrow_mut().new_notifications().into_iter() {
            event_results
                .new_messages
                .extend(notifications.into_iter().map(|n| Envelope {
                    sender: self.peer_id.clone(),
                    recipient: peer.clone(),
                    payload: Payload::new(Message::Notification(n)),
                }))
        }
        Ok(event_results)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocEvent {
    pub peer: PeerId,
    pub doc: DocumentId,
    pub data: CommitOrBundle,
}

/// Returned by [`Beelay::handle_event`] to indicate the effects of the event which was handled
#[derive(Debug, Default)]
pub struct EventResults {
    /// New messages which should be send to the peers referenced by [`Envelope::recipient`] struct
    pub new_messages: Vec<Envelope>,
    /// New storage tasks which should be executed
    pub new_tasks: Vec<io::IoTask>,
    /// Stories which have completed
    pub completed_stories: HashMap<StoryId, StoryResult>,
    /// New notifications
    pub notifications: Vec<DocEvent>,
    /// Documents requested
    pub requested_docs: Vec<(PeerId, DocumentId)>,
}

#[derive(Debug)]
pub struct Event(EventInner);

impl Event {
    /// A storage task completed
    pub fn io_complete(result: IoResult) -> Event {
        Event(EventInner::IoComplete(result))
    }

    /// A message was received from the network
    pub fn receive(envelope: Envelope) -> Event {
        Event(EventInner::Receive(Box::new(envelope)))
    }

    pub fn sync_doc(root_id: DocumentId, with_peer: PeerId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        (
            story_id,
            Event(EventInner::BeginStory(
                story_id,
                Story::SyncDoc {
                    root_id,
                    peer: with_peer,
                },
            )),
        )
    }

    pub fn add_commits(root_id: DocumentId, commits: Vec<Commit>) -> (StoryId, Event) {
        let story_id = StoryId::new();
        (
            story_id,
            Event(EventInner::BeginStory(
                story_id,
                Story::AddCommits {
                    doc_id: root_id,
                    commits,
                },
            )),
        )
    }

    pub fn create_doc() -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(story_id, Story::CreateDoc));
        (story_id, event)
    }

    pub fn load_doc(doc_id: DocumentId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(story_id, Story::LoadDoc { doc_id }));
        (story_id, event)
    }

    pub fn add_link(add: AddLink) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(story_id, Story::AddLink(add)));
        (story_id, event)
    }

    pub fn add_bundle(doc: DocumentId, bundle: CommitBundle) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::AddBundle {
                doc_id: doc,
                bundle,
            },
        ));
        (story_id, event)
    }

    pub fn listen(peer: PeerId, snapshot: SnapshotId) -> (StoryId, Event) {
        let story_id = StoryId::new();
        let event = Event(EventInner::BeginStory(
            story_id,
            Story::Listen {
                peer_id: peer,
                snapshot_id: snapshot,
            },
        ));
        (story_id, event)
    }
}

#[derive(Debug)]
pub struct AddLink {
    pub from: DocumentId,
    pub to: DocumentId,
}

#[derive(Debug)]
enum EventInner {
    IoComplete(io::IoResult),
    Receive(Box<Envelope>),
    BeginStory(StoryId, Story),
}

#[derive(Debug)]
enum Story {
    SyncDoc {
        root_id: DocumentId,
        peer: PeerId,
    },
    AddCommits {
        doc_id: DocumentId,
        commits: Vec<Commit>,
    },
    LoadDoc {
        doc_id: DocumentId,
    },
    CreateDoc,
    AddLink(AddLink),
    AddBundle {
        doc_id: DocumentId,
        bundle: CommitBundle,
    },
    Listen {
        peer_id: PeerId,
        snapshot_id: SnapshotId,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct RequestId([u8; 16]);

impl serde::Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        hex::encode(&self.0).serialize(serializer)
    }
}

impl RequestId {
    pub fn new<R: Rng>(rng: &mut R) -> RequestId {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        RequestId(id)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, RequestId), parse::ParseError> {
        input.with_context("request id", |input| {
            let (input, bytes) = parse::arr::<16>(input)?;
            Ok((input, RequestId::from(bytes)))
        })
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for RequestId {
    type Err = error::InvalidRequestId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0; 16];
        if s.len() != 32 {
            return Err(error::InvalidRequestId);
        }
        for (i, byte) in bytes.iter_mut().enumerate() {
            let byte_str = &s[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(byte_str, 16).map_err(|_| error::InvalidRequestId)?;
        }
        Ok(RequestId(bytes))
    }
}

impl From<[u8; 16]> for RequestId {
    fn from(value: [u8; 16]) -> Self {
        RequestId(value)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct PeerId(String);

impl PeerId {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, PeerId), parse::ParseError> {
        input.with_context("PeerId", |input| {
            let (input, bytes) = parse::slice(input)?;
            let id = std::str::from_utf8(bytes).map_err(|e| input.error(e.to_string()))?;
            Ok((input, PeerId(id.to_string())))
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        crate::leb128::encode_uleb128(buf, self.0.as_bytes().len() as u64);
        buf.extend_from_slice(self.0.as_bytes());
    }

    pub fn random<R: Rng>(r: &mut R) -> PeerId {
        PeerId(format!("{:x}", r.gen::<u64>()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for PeerId {
    fn from(value: String) -> Self {
        PeerId(value)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for PeerId {
    type Err = error::InvalidPeerId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PeerId(s.to_string()))
    }
}

pub(crate) struct OutgoingResponse {
    target: PeerId,
    id: RequestId,
    response: Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum CommitCategory {
    Content,
    Index,
}

impl std::fmt::Display for CommitCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CommitCategory::Content => write!(f, "content"),
            CommitCategory::Index => write!(f, "index"),
        }
    }
}

impl CommitCategory {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, CommitCategory), parse::ParseError> {
        input.with_context("CommitCategory", |input| {
            let (input, cat) = parse::u8(input)?;
            match cat {
                0 => Ok((input, CommitCategory::Content)),
                1 => Ok((input, CommitCategory::Index)),
                other => Err(input.error(format!("invalid commit category {}", other))),
            }
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            CommitCategory::Content => buf.push(0),
            CommitCategory::Index => buf.push(1),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct DocumentHeads(Vec<crate::CommitHash>);

impl DocumentHeads {
    pub(crate) fn new(heads: Vec<crate::CommitHash>) -> Self {
        DocumentHeads(heads)
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("DocumentDagHeads", |input| {
            let (input, heads) = parse::many(input, CommitHash::parse)?;
            Ok((input, DocumentHeads::new(heads)))
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        crate::leb128::encode_uleb128(buf, self.0.len() as u64);
        for head in &self.0 {
            head.encode(buf);
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for DocumentHeads {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[")?;
        for (idx, hash) in self.0.iter().enumerate() {
            if idx > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", hash)?;
        }
        write!(f, "]")
    }
}

impl<'a> IntoIterator for &'a DocumentHeads {
    type Item = &'a crate::CommitHash;
    type IntoIter = std::slice::Iter<'a, crate::CommitHash>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Debug, Clone)]
pub struct BundleSpec {
    pub doc: DocumentId,
    pub start: CommitHash,
    pub end: CommitHash,
    pub checkpoints: Vec<CommitHash>,
}

mod error {
    pub struct Error(pub(super) String);

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for Error {}

    pub struct InvalidRequestId;

    impl std::fmt::Display for InvalidRequestId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid request id")
        }
    }

    impl std::fmt::Debug for InvalidRequestId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidRequestId {}

    pub struct InvalidPeerId;

    impl std::fmt::Display for InvalidPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid peer id")
        }
    }

    impl std::fmt::Debug for InvalidPeerId {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidPeerId {}

    pub enum InvalidDocumentId {
        InvalidLength,
        InvalidEncoding(bs58::decode::Error),
    }

    impl std::fmt::Display for InvalidDocumentId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                InvalidDocumentId::InvalidLength => write!(f, "invalid DocumentId length"),
                InvalidDocumentId::InvalidEncoding(e) => {
                    write!(f, "invalid DocumentId encoding: {}", e)
                }
            }
        }
    }

    impl std::fmt::Debug for InvalidDocumentId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidDocumentId {}

    impl From<bs58::decode::Error> for InvalidDocumentId {
        fn from(e: bs58::decode::Error) -> Self {
            InvalidDocumentId::InvalidEncoding(e)
        }
    }
}

#[derive(Debug)]
pub struct SyncDocResult {
    pub found: bool,
    pub snapshot: snapshots::SnapshotId,
    pub differing_docs: HashSet<DocumentId>,
}

mod test {
    #[allow(dead_code)]
    fn is_send<T: Send>() {}

    #[test]
    fn test_send() {
        is_send::<super::Beelay<rand::rngs::StdRng>>();
    }
}
