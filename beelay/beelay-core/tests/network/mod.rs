use std::collections::{BTreeMap, HashMap, VecDeque};

use beelay_core::{
    io::{IoAction, IoResult},
    BundleSpec, CommitHash, CommitOrBundle, DocEvent, DocumentId, Forwarding, PeerAddress, PeerId,
    SnapshotId, SyncDocResult,
};

pub struct BeelayHandle<'a> {
    pub network: &'a mut Network,
    pub peer_id: beelay_core::PeerId,
}

impl BeelayHandle<'_> {
    pub fn create_doc(&mut self) -> DocumentId {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::create_doc();
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::CreateDoc(doc_id))) => doc_id,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    pub fn create_doc_with_contents(&mut self, content: Vec<u8>) -> DocumentId {
        let doc = self.create_doc();
        let commit = beelay_core::Commit::new(vec![], content, CommitHash::from([1; 32]));
        self.add_commits(doc, vec![commit]);
        doc
    }

    pub fn sync_doc<A: Into<beelay_core::PeerAddress>>(
        &mut self,
        doc: DocumentId,
        remote: A,
    ) -> SyncDocResult {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::sync_doc(doc, remote.into());
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::SyncDoc(result))) => result.unwrap(),
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    pub fn listen<A: Into<beelay_core::PeerAddress>>(
        &mut self,
        to_address: A,
        from_snapshot: SnapshotId,
    ) {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::listen(to_address.into(), from_snapshot);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::Listen(result))) => result.unwrap(),
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    pub fn add_commits(
        &mut self,
        doc_id: DocumentId,
        commits: Vec<beelay_core::Commit>,
    ) -> Vec<BundleSpec> {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::add_commits(doc_id, commits);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::AddCommits(new_bundles_needed))) => {
                new_bundles_needed
            }
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    pub fn add_link(&mut self, add: beelay_core::AddLink) {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::add_link(add);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::AddLink)) => (),
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    pub fn load_doc(&mut self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::load_doc(doc_id);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::LoadDoc(commits))) => commits,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
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
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) =
                beelay_core::Event::register_endpoint(beelay_core::Audience::peer(other), forward);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let endpoint_id = match beelay.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::RegisterEndpoint(endpoint_id))) => endpoint_id,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
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
}

pub struct Network {
    beelays: HashMap<beelay_core::PeerId, BeelayWrapper>,
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
        let beelay = BeelayWrapper::new(beelay_core::Beelay::new(rand::thread_rng(), None));
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
                            let (req_id, event) =
                                beelay_core::Event::handle_request(signed_message);
                            target_beelay.inbox.push_back(event);
                            target_beelay
                                .handling_requests
                                .insert(req_id, (senders_req_id, sender));
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
                            let (_story, event) =
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

pub struct BeelayWrapper {
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: beelay_core::Beelay<rand::rngs::ThreadRng>,
    outbox: Vec<Message>,
    inbox: VecDeque<beelay_core::Event>,
    completed_stories: HashMap<
        beelay_core::StoryId,
        Result<beelay_core::StoryResult, beelay_core::error::Stopping>,
    >,
    notifications: Vec<DocEvent>,
    handling_requests:
        HashMap<beelay_core::InboundRequestId, (beelay_core::OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, beelay_core::PeerId>,
    streams: HashMap<beelay_core::StreamId, beelay_core::PeerId>,
    starting_streams: HashMap<beelay_core::StoryId, beelay_core::PeerId>,
    shutdown: bool,
}

impl BeelayWrapper {
    fn new(core: beelay_core::Beelay<rand::rngs::ThreadRng>) -> Self {
        Self {
            storage: BTreeMap::new(),
            core,
            outbox: Vec::new(),
            inbox: VecDeque::new(),
            completed_stories: HashMap::new(),
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
        let (story, event) = beelay_core::Event::create_stream(direction, forwarding);
        self.starting_streams.insert(story, *target);
        self.inbox.push_back(event);
        self.handle_events();
        match self.completed_stories.remove(&story) {
            Some(Ok(beelay_core::StoryResult::CreateStream(stream_id))) => stream_id,
            Some(other) => panic!("unexpected story result when creating stream: {:?}", other),
            None => panic!("no story result when creating stream"),
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
            for (story, result) in results.completed_stories.into_iter() {
                if let Ok(beelay_core::StoryResult::CreateStream(stream_id)) = result {
                    let target = self
                        .starting_streams
                        .remove(&story)
                        .expect("should be a starting stream registered");
                    self.streams.insert(stream_id, target);
                }
                self.completed_stories.insert(story, result);
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
            for (id, result) in results.completed_requests {
                let Ok(result) = result else {
                    continue;
                };
                if let Some((sender_req_id, sender)) = self.handling_requests.remove(&id) {
                    self.outbox.push(Message::Response {
                        target: sender,
                        id: sender_req_id,
                        response: result.encode(),
                    });
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
