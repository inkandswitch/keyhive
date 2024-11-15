use crate::{
    commands::{AddLink, Command},
    io::{self, IoResult},
    keyhive,
    network::InnerRpcResponse,
    Access, Audience, CommandId, Commit, CommitBundle, DocumentId, EndpointId, Forwarding,
    OutboundRequestId, PeerAddress, PeerId, RpcResponse, SignedMessage, SnapshotId,
    StreamDirection, StreamId,
};

#[derive(Debug)]
pub struct Event(pub(super) EventInner);

impl Event {
    /// A storage task completed
    pub fn io_complete(result: IoResult) -> Event {
        Event(EventInner::IoComplete(result))
    }

    // Submit a new request to be handled
    pub fn handle_request(
        request: SignedMessage,
        receive_audience: Option<String>,
    ) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::HandleRequest {
                request: request.0,
                receive_audience,
            },
        ));
        (command_id, event)
    }

    // Submit the response to an outgoing request
    pub fn handle_response(id: OutboundRequestId, response: RpcResponse) -> Event {
        Event(EventInner::HandleResponse(id, response.0))
    }

    // Begin synchronizing a document
    pub fn sync_doc(root_id: DocumentId, remote: PeerAddress) -> (CommandId, Event) {
        let command_id = CommandId::new();
        (
            command_id,
            Event(EventInner::BeginCommand(
                command_id,
                Command::SyncDoc { root_id, remote },
            )),
        )
    }

    // Add some commits to a document
    #[tracing::instrument(skip(commits))]
    pub fn add_commits(root_id: DocumentId, commits: Vec<Commit>) -> (CommandId, Event) {
        let command_id = CommandId::new();
        (
            command_id,
            Event(EventInner::BeginCommand(
                command_id,
                Command::AddCommits {
                    doc_id: root_id,
                    commits,
                },
            )),
        )
    }

    // Create a new document
    pub fn create_doc(access: Access, initial_commit: Commit) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::CreateDoc(initial_commit, access),
        ));
        (command_id, event)
    }

    // Load a document from storage
    pub fn load_doc(doc_id: DocumentId) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::LoadDoc { doc_id },
        ));
        (command_id, event)
    }

    // Add a link from one document to another
    pub fn add_link(add: AddLink) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(command_id, Command::AddLink(add)));
        (command_id, event)
    }

    // Add a bundle of commits to a document
    pub fn add_bundle(doc: DocumentId, bundle: CommitBundle) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::AddBundle {
                doc_id: doc,
                bundle,
            },
        ));
        (command_id, event)
    }

    // Listen for changes since `snapshot` form `to_peer`
    pub fn listen(to_peer: PeerAddress, snapshot: SnapshotId) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::Listen {
                peer: to_peer,
                snapshot_id: snapshot,
            },
        ));
        (command_id, event)
    }

    pub fn create_stream(direction: StreamDirection, forwarding: Forwarding) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::CreateStream(direction, forwarding),
        ));
        (command_id, event)
    }

    pub fn disconnect_stream(stream_id: StreamId) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::DisconnectStream { stream_id },
        ));
        (command_id, event)
    }

    pub fn handle_message(stream_id: StreamId, message: Vec<u8>) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::HandleStreamMessage {
                stream_id,
                msg: message,
            },
        ));
        (command_id, event)
    }

    pub fn register_endpoint(audience: Audience, forwarding: Forwarding) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::RegisterEndpoint(audience, forwarding),
        ));
        (command_id, event)
    }

    pub fn unregister_endpoint(endpoint_id: EndpointId) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::UnregisterEndpoints(endpoint_id),
        ));
        (command_id, event)
    }

    pub fn stop() -> Event {
        let command_id = CommandId::new();
        Event(EventInner::BeginCommand(command_id, Command::Stop))
    }

    pub fn add_member(doc_id: DocumentId, peer: PeerId) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::Keyhive(keyhive::KeyhiveCommand::AddMember(doc_id, peer)),
        ));
        (command_id, event)
    }

    pub fn remove_member(doc_id: DocumentId, peer: PeerId) -> (CommandId, Event) {
        let command_id = CommandId::new();
        let event = Event(EventInner::BeginCommand(
            command_id,
            Command::Keyhive(keyhive::KeyhiveCommand::RemoveMember(doc_id, peer)),
        ));
        (command_id, event)
    }
}

#[derive(Debug)]
pub(super) enum EventInner {
    IoComplete(io::IoResult),
    HandleResponse(OutboundRequestId, InnerRpcResponse),
    BeginCommand(CommandId, Command),
}
