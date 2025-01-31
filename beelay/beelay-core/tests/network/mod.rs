use std::collections::{BTreeMap, HashMap, VecDeque};

use beelay_core::{
    io::{IoAction, IoResult},
    BundleSpec, CommitHash, CommitOrBundle, DocEvent, DocumentId, Forwarding, MemberAccess, PeerId,
    SnapshotId, SyncDocResult, UnixTimestamp,
};

pub struct BeelayHandle<'a> {
    pub network: &'a mut Network,
    pub peer_id: beelay_core::PeerId,
}

impl BeelayHandle<'_> {
    pub fn create_doc(&mut self, access: beelay_core::Access) -> DocumentId {
        self.create_doc_with_contents(access, vec![9, 9, 9, 8, 8, 8])
    }

    pub fn create_doc_with_contents(
        &mut self,
        access: beelay_core::Access,
        content: Vec<u8>,
    ) -> DocumentId {
        let initial_commit = beelay_core::Commit::new(vec![], content, CommitHash::from([1; 32]));
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::create_doc(access, initial_commit);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::CreateDoc(doc_id))) => doc_id,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn sync_doc<A: Into<beelay_core::PeerAddress>>(
        &mut self,
        doc: DocumentId,
        remote: A,
    ) -> SyncDocResult {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::sync_doc(doc, remote.into());
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::SyncDoc(result))) => result.unwrap(),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn listen<A: Into<beelay_core::PeerAddress>>(
        &mut self,
        to_address: A,
        from_snapshot: SnapshotId,
    ) {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::listen(to_address.into(), from_snapshot);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::Listen(result))) => result.unwrap(),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn add_commits(
        &mut self,
        doc_id: DocumentId,
        commits: Vec<beelay_core::Commit>,
    ) -> Vec<BundleSpec> {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::add_commits(doc_id, commits);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::AddCommits(new_bundles_needed))) => {
                new_bundles_needed
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn add_link(&mut self, add: beelay_core::AddLink) {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::add_link(add);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::AddLink)) => (),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn load_doc(&mut self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::load_doc(doc_id);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::LoadDoc(commits))) => commits,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn pop_notifications(&mut self) -> Vec<DocEvent> {
        std::mem::take(
            &mut self
                .network
                .beelays
                .get_mut(&self.peer_id)
                .unwrap()
                .notifications,
        )
    }

    pub fn register_endpoint(
        &mut self,
        other: &PeerId,
        forward: Forwarding,
    ) -> beelay_core::EndpointId {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) =
                beelay_core::Event::register_endpoint(beelay_core::Audience::peer(other), forward);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let endpoint_id = match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::RegisterEndpoint(endpoint_id))) => endpoint_id,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
        beelay.endpoints.insert(endpoint_id, *other);
        endpoint_id
    }

    pub fn dirty_shutdown(&mut self) {
        self.network
            .beelays
            .get_mut(&self.peer_id)
            .unwrap()
            .shutdown = true;
    }

    pub fn shutdown(&mut self) {
        {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let event = beelay_core::Event::stop();
            beelay.inbox.push_back(event);
        }
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let mut iterations = 0;
        loop {
            if beelay.shutdown {
                break;
            }
            iterations += 1;
            if iterations > 100 {
                panic!("shutdown didn't complete after 100 iterations");
            }
            beelay.handle_events();
        }
    }

    pub fn add_member(
        &mut self,
        doc: DocumentId,
        peer: PeerId,
        access: MemberAccess,
    ) -> Result<(), beelay_core::error::AddMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::add_member(doc, peer, access);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::KeyhiveCommandResult::AddMember(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn remove_member(
        &mut self,
        doc: DocumentId,
        peer: PeerId,
    ) -> Result<(), beelay_core::error::RemoveMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::remove_member(doc, peer);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::KeyhiveCommandResult::RemoveMember(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn query_access(
        &mut self,
        doc: DocumentId,
    ) -> Result<
        HashMap<beelay_core::PeerId, beelay_core::MemberAccess>,
        beelay_core::error::QueryAccess,
    > {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::query_access(doc);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::KeyhiveCommandResult::QueryAccess(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }
}

pub struct Network {
    beelays: HashMap<beelay_core::PeerId, BeelayWrapper<rand::rngs::ThreadRng>>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            beelays: HashMap::new(),
        }
    }

    pub fn beelay(&mut self, peer: &PeerId) -> BeelayHandle {
        assert!(self.beelays.contains_key(peer));
        BeelayHandle {
            network: self,
            peer_id: *peer,
        }
    }

    pub fn create_peer(&mut self, nickname: &str) -> PeerId {
        let beelay = BeelayWrapper::new(beelay_core::Beelay::new(
            rand::thread_rng(),
            UnixTimestamp::now(),
            None,
        ));
        let peer_id = beelay.core.peer_id();
        test_utils::add_rewrite(peer_id.to_string(), nickname);
        self.beelays.insert(peer_id, beelay);
        self.run_until_quiescent();
        peer_id
    }

    pub fn connect_stream(
        &mut self,
        left: &PeerId,
        right: &PeerId,
        forwarding: ConnForwarding,
    ) -> ConnectedPair {
        let left_stream_id = {
            let beelay = self.beelays.get_mut(left).unwrap();
            let forward = match forwarding {
                ConnForwarding::LeftToRight | ConnForwarding::Both => Forwarding::Forward,
                _ => Forwarding::DontForward,
            };
            beelay.create_stream(
                right,
                beelay_core::StreamDirection::Connecting {
                    remote_audience: beelay_core::Audience::peer(right),
                },
                forward,
            )
        };
        let right_stream_id = {
            let beelay = self.beelays.get_mut(right).unwrap();
            let forward = match forwarding {
                ConnForwarding::RightToLeft | ConnForwarding::Both => Forwarding::Forward,
                _ => Forwarding::DontForward,
            };
            beelay.create_stream(
                left,
                beelay_core::StreamDirection::Accepting {
                    receive_audience: None,
                },
                forward,
            )
        };
        self.run_until_quiescent();
        ConnectedPair {
            left_to_right: left_stream_id,
            right_to_left: right_stream_id,
        }
    }

    pub fn run_until_quiescent(&mut self) {
        loop {
            let mut messages_this_round = HashMap::new();

            for (source_id, beelay) in self.beelays.iter_mut() {
                beelay.handle_events();
                if !beelay.outbox.is_empty() {
                    messages_this_round.insert(*source_id, std::mem::take(&mut beelay.outbox));
                }
            }
            if messages_this_round.is_empty() {
                break;
            }
            for (sender, outbound) in messages_this_round {
                for msg in outbound {
                    match msg {
                        Message::Request {
                            target,
                            senders_req_id,
                            request,
                        } => {
                            let target_beelay = self.beelays.get_mut(&target).unwrap();
                            let signed_message =
                                beelay_core::SignedMessage::decode(&request).unwrap();
                            let (command_id, event) =
                                beelay_core::Event::handle_request(signed_message, None);
                            target_beelay.inbox.push_back(event);
                            target_beelay
                                .handling_requests
                                .insert(command_id, (senders_req_id, sender));
                        }
                        Message::Response {
                            target,
                            id,
                            response,
                        } => {
                            let target = self.beelays.get_mut(&target).unwrap();
                            let response = beelay_core::RpcResponse::decode(&response).unwrap();
                            let event = beelay_core::Event::handle_response(id, response);
                            target.inbox.push_back(event);
                        }
                        Message::Stream { target, msg } => {
                            let target_beelay = self.beelays.get_mut(&target).unwrap();
                            let incoming_stream_id = target_beelay
                                .streams
                                .iter()
                                .find_map(
                                    |(stream, peer)| {
                                        if *peer == sender {
                                            Some(stream)
                                        } else {
                                            None
                                        }
                                    },
                                )
                                .unwrap();
                            let (_command, event) =
                                beelay_core::Event::handle_message(*incoming_stream_id, msg);
                            target_beelay.inbox.push_back(event);
                        }
                    }
                }
            }
        }
    }
}

enum Message {
    Request {
        target: PeerId,
        senders_req_id: beelay_core::OutboundRequestId,
        request: Vec<u8>,
    },
    Response {
        target: PeerId,
        id: beelay_core::OutboundRequestId,
        response: Vec<u8>,
    },
    Stream {
        target: PeerId,
        msg: Vec<u8>,
    },
}

pub struct BeelayWrapper<R: rand::Rng + rand::CryptoRng> {
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: beelay_core::Beelay<R>,
    outbox: Vec<Message>,
    inbox: VecDeque<beelay_core::Event>,
    completed_commands: HashMap<
        beelay_core::CommandId,
        Result<beelay_core::CommandResult, beelay_core::error::Stopping>,
    >,
    notifications: Vec<DocEvent>,
    handling_requests: HashMap<beelay_core::CommandId, (beelay_core::OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, beelay_core::PeerId>,
    streams: HashMap<beelay_core::StreamId, beelay_core::PeerId>,
    starting_streams: HashMap<beelay_core::CommandId, beelay_core::PeerId>,
    shutdown: bool,
}

impl<R: rand::Rng + rand::CryptoRng> BeelayWrapper<R> {
    fn new(core: beelay_core::Beelay<R>) -> Self {
        Self {
            storage: BTreeMap::new(),
            core,
            outbox: Vec::new(),
            inbox: VecDeque::new(),
            completed_commands: HashMap::new(),
            notifications: Vec::new(),
            handling_requests: HashMap::new(),
            endpoints: HashMap::new(),
            streams: HashMap::new(),
            starting_streams: HashMap::new(),
            shutdown: false,
        }
    }

    pub fn create_stream(
        &mut self,
        target: &PeerId,
        direction: beelay_core::StreamDirection,
        forwarding: Forwarding,
    ) -> beelay_core::StreamId {
        let (command, event) = beelay_core::Event::create_stream(direction, forwarding);
        self.starting_streams.insert(command, *target);
        self.inbox.push_back(event);
        self.handle_events();
        match self.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::CreateStream(stream_id))) => stream_id,
            Some(other) => panic!(
                "unexpected command result when creating stream: {:?}",
                other
            ),
            None => panic!("no command result when creating stream"),
        }
    }

    pub fn handle_events(&mut self) {
        if self.shutdown {
            return;
        }
        while let Some(event) = self.inbox.pop_front() {
            let results = self
                .core
                .handle_event(beelay_core::UnixTimestamp::now(), event)
                .unwrap();
            for task in results.new_tasks.into_iter() {
                let event = self.handle_task(task);
                self.inbox.push_back(event);
            }
            for (command, result) in results.completed_commands.into_iter() {
                if let Ok(beelay_core::CommandResult::CreateStream(stream_id)) = result {
                    let target = self
                        .starting_streams
                        .remove(&command)
                        .expect("should be a starting stream registered");
                    self.streams.insert(stream_id, target);
                }
                if let Ok(beelay_core::CommandResult::HandleRequest(response)) = &result {
                    let Ok(response) = response else {
                        continue;
                    };
                    if let Some((sender_req_id, sender)) = self.handling_requests.remove(&command) {
                        self.outbox.push(Message::Response {
                            target: sender,
                            id: sender_req_id,
                            response: response.encode(),
                        });
                    }
                }
                self.completed_commands.insert(command, result);
            }
            for (target, msgs) in results.new_requests {
                let peer_id = self.endpoints.get(&target).expect("endpoint doesn't exist");
                for msg in msgs {
                    self.outbox.push(Message::Request {
                        target: *peer_id,
                        senders_req_id: msg.id,
                        request: msg.request.encode(),
                    })
                }
            }
            for (id, events) in results.new_stream_events {
                for event in events {
                    tracing::trace!(?event, "stream event");
                    match event {
                        beelay_core::StreamEvent::Send(msg) => {
                            let target = self.streams.get(&id).unwrap();
                            self.outbox.push(Message::Stream {
                                target: *target,
                                msg,
                            })
                        }
                        beelay_core::StreamEvent::HandshakeComplete { .. } => {}
                        beelay_core::StreamEvent::Close => {}
                    }
                }
            }
            self.notifications.extend(results.notifications.into_iter());
            if results.stopped {
                self.shutdown = true;
            }
        }
    }

    pub fn handle_task(&mut self, task: beelay_core::io::IoTask) -> beelay_core::Event {
        let id = task.id();
        let result = match task.take_action() {
            IoAction::Load { key } => {
                let data = self.storage.get(&key).cloned();
                IoResult::load(id, data)
            }
            IoAction::Put { key, data } => {
                self.storage.insert(key, data);
                IoResult::put(id)
            }
            IoAction::Delete { key } => {
                self.storage.remove(&key);
                IoResult::delete(id)
            }
            IoAction::LoadRange { prefix } => {
                let results = self
                    .storage
                    .iter()
                    .filter_map(|(k, v)| {
                        if prefix.is_prefix_of(k) {
                            Some((k.clone(), v.clone()))
                        } else {
                            None
                        }
                    })
                    .collect();
                IoResult::load_range(id, results)
            }
        };
        beelay_core::Event::io_complete(result)
    }

    pub fn pop_notifications(&mut self) -> Vec<DocEvent> {
        std::mem::take(&mut self.notifications)
    }
}

pub enum ConnForwarding {
    LeftToRight,
    RightToLeft,
    Both,
    Neither,
}

pub struct ConnectedPair {
    pub left_to_right: beelay_core::StreamId,
    pub right_to_left: beelay_core::StreamId,
}
