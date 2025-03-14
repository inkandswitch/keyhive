use std::collections::{BTreeMap, HashMap, VecDeque};

use beelay_core::{
    io::{IoAction, IoResult},
    keyhive::{KeyhiveCommandResult, KeyhiveEntityId, MemberAccess},
    BundleSpec, CommitHash, CommitOrBundle, DocumentId, Event, PeerId, UnixTimestamp,
};
use ed25519_dalek::SigningKey;
use keyhive_core::contact_card::ContactCard;
use signature::SignerMut;

#[allow(dead_code)]
pub struct BeelayHandle<'a> {
    pub network: &'a mut Network,
    pub peer_id: beelay_core::PeerId,
}

impl BeelayHandle<'_> {
    #[allow(dead_code)]
    pub fn create_doc(
        &mut self,
        other_owners: Vec<ContactCard>,
    ) -> Result<(DocumentId, beelay_core::Commit), beelay_core::error::Create> {
        self.create_doc_with_contents(vec![9, 9, 9, 8, 8, 8], other_owners)
    }

    #[allow(dead_code)]
    pub fn contact_card(&self) -> ContactCard {
        self.network.beelays[&self.peer_id].contact_card()
    }

    #[allow(dead_code)]
    pub fn create_doc_with_contents(
        &mut self,
        content: Vec<u8>,
        other_owners: Vec<ContactCard>,
    ) -> Result<(DocumentId, beelay_core::Commit), beelay_core::error::Create> {
        let hash = CommitHash::from(blake3::hash(&content).as_bytes());
        let initial_commit = beelay_core::Commit::new(vec![], content, hash);
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) =
                beelay_core::Event::create_doc(initial_commit.clone(), other_owners);
            beelay.inbox.push_back(event);
            beelay.handle_events();
            command
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::CreateDoc(doc_id))) => {
                let doc_id = doc_id?;
                Ok((doc_id, initial_commit))
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn doc_status(&mut self, doc: &DocumentId) -> beelay_core::doc_status::DocStatus {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = beelay_core::Event::query_status(doc.clone());
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::QueryStatus(status))) => status,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn add_commits(
        &mut self,
        doc_id: DocumentId,
        commits: Vec<beelay_core::Commit>,
    ) -> Result<Vec<BundleSpec>, beelay_core::error::AddCommits> {
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn pop_notifications(
        &mut self,
    ) -> HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>> {
        std::mem::take(
            &mut self
                .network
                .beelays
                .get_mut(&self.peer_id)
                .unwrap()
                .notifications,
        )
    }

    #[allow(dead_code)]
    pub fn register_endpoint(&mut self, other: &PeerId) -> beelay_core::EndpointId {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) =
                beelay_core::Event::register_endpoint(beelay_core::Audience::peer(other));
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

    #[allow(dead_code)]
    pub fn dirty_shutdown(&mut self) {
        self.network
            .beelays
            .get_mut(&self.peer_id)
            .unwrap()
            .shutdown = true;
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn add_member_to_doc(
        &mut self,
        doc: DocumentId,
        member: ContactCard,
        access: MemberAccess,
    ) {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::add_member_to_doc(doc, member, access);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::keyhive::KeyhiveCommandResult::AddMemberToDoc,
            ))) => (),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn remove_member_from_doc(
        &mut self,
        doc: DocumentId,
        member: KeyhiveEntityId,
    ) -> Result<(), beelay_core::error::RemoveMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::remove_member_from_doc(doc, member);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::keyhive::KeyhiveCommandResult::RemoveMemberFromDoc(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn create_group(&mut self) -> Result<beelay_core::PeerId, beelay_core::error::CreateGroup> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::create_group();
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(KeyhiveCommandResult::CreateGroup(r)))) => {
                r
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn add_member_to_group(
        &mut self,
        add: beelay_core::keyhive::AddMemberToGroup,
    ) -> Result<(), beelay_core::error::AddMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::add_member_to_group(add);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::keyhive::KeyhiveCommandResult::AddMemberToGroup(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn remove_member_from_group(
        &mut self,
        remove: beelay_core::keyhive::RemoveMemberFromGroup,
    ) -> Result<(), beelay_core::error::RemoveMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::remove_member_from_group(remove);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::keyhive::KeyhiveCommandResult::RemoveMemberFromGroup(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn query_access(
        &mut self,
        doc: DocumentId,
    ) -> Result<
        HashMap<beelay_core::PeerId, beelay_core::keyhive::MemberAccess>,
        beelay_core::error::QueryAccess,
    > {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::query_access(doc);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::keyhive::KeyhiveCommandResult::QueryAccess(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    #[allow(dead_code)]
    pub fn storage(&self) -> &BTreeMap<beelay_core::StorageKey, Vec<u8>> {
        &self.network.beelays.get(&self.peer_id).unwrap().storage
    }

    #[cfg(feature = "debug_events")]
    pub fn log_keyhive_events(
        &mut self,
        nicknames: keyhive_core::debug_events::Nicknames,
    ) -> keyhive_core::debug_events::DebugEventTable {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = beelay_core::Event::log_keyhive_events(nicknames);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();

        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                beelay_core::keyhive::KeyhiveCommandResult::DebugEvents(events),
            ))) => events,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }
}

pub struct Network {
    beelays: HashMap<beelay_core::PeerId, BeelayWrapper<rand::rngs::ThreadRng>>,
}

impl Network {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            beelays: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn beelay(&mut self, peer: &PeerId) -> BeelayHandle {
        assert!(self.beelays.contains_key(peer));
        BeelayHandle {
            network: self,
            peer_id: *peer,
        }
    }

    #[allow(dead_code)]
    pub fn create_peer(&mut self, nickname: &str) -> PeerId {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        self.load_peer(nickname, BTreeMap::new(), signing_key)
    }

    #[allow(dead_code)]
    pub fn create_peer_with_key(&mut self, nickname: &str, signing_key: SigningKey) -> PeerId {
        self.load_peer(nickname, BTreeMap::new(), signing_key)
    }

    pub(crate) fn load_peer(
        &mut self,
        nickname: &str,
        mut storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
        mut signing_key: SigningKey,
    ) -> PeerId {
        let peer_id = PeerId::from(signing_key.verifying_key());
        test_utils::add_rewrite(peer_id.to_string(), nickname);
        let mut step = beelay_core::Beelay::load(
            rand::thread_rng(),
            UnixTimestamp::now(),
            signing_key.verifying_key(),
        );
        let mut completed_tasks = Vec::new();
        let beelay = loop {
            match step {
                beelay_core::loading::Step::Loading(loading, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(&mut storage, &mut signing_key, task);
                        completed_tasks.push(result);
                    }
                    if let Some(task_result) = completed_tasks.pop() {
                        step = loading.handle_io_complete(UnixTimestamp::now(), task_result);
                        continue;
                    } else {
                        panic!("no tasks completed but still loading");
                    }
                }
                beelay_core::loading::Step::Loaded(beelay, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(&mut storage, &mut signing_key, task);
                        completed_tasks.push(result);
                    }
                    break beelay;
                }
            }
        };

        let peer_id = beelay.peer_id();
        let mut beelay = BeelayWrapper::new(signing_key, nickname, beelay);
        beelay.storage = storage;
        for result in completed_tasks {
            beelay.inbox.push_back(Event::io_complete(result));
        }
        // beelay.handle_events();
        self.beelays.insert(peer_id, beelay);
        self.run_until_quiescent();
        tracing::info!("loading complete");
        peer_id
    }

    // Create a stream from left to right (i.e. the left peer will send the hello message)
    #[allow(dead_code)]
    pub fn connect_stream(&mut self, left: &PeerId, right: &PeerId) -> ConnectedPair {
        let left_stream_id = {
            let beelay = self.beelays.get_mut(left).unwrap();
            beelay.create_stream(
                right,
                beelay_core::StreamDirection::Connecting {
                    remote_audience: beelay_core::Audience::peer(right),
                },
            )
        };
        let right_stream_id = {
            let beelay = self.beelays.get_mut(right).unwrap();
            beelay.create_stream(
                left,
                beelay_core::StreamDirection::Accepting {
                    receive_audience: None,
                },
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
    #[allow(dead_code)]
    nickname: String,
    signing_key: SigningKey,
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: beelay_core::Beelay<R>,
    outbox: Vec<Message>,
    inbox: VecDeque<beelay_core::Event>,
    completed_commands: HashMap<
        beelay_core::CommandId,
        Result<beelay_core::CommandResult, beelay_core::error::Stopping>,
    >,
    notifications: HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>>,
    handling_requests: HashMap<beelay_core::CommandId, (beelay_core::OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, beelay_core::PeerId>,
    streams: HashMap<beelay_core::StreamId, beelay_core::PeerId>,
    starting_streams: HashMap<beelay_core::CommandId, beelay_core::PeerId>,
    shutdown: bool,
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> BeelayWrapper<R> {
    #[allow(dead_code)]
    fn new(signing_key: SigningKey, nickname: &str, core: beelay_core::Beelay<R>) -> Self {
        Self {
            nickname: nickname.to_string(),
            signing_key,
            storage: BTreeMap::new(),
            core,
            outbox: Vec::new(),
            inbox: VecDeque::new(),
            completed_commands: HashMap::new(),
            notifications: HashMap::new(),
            handling_requests: HashMap::new(),
            endpoints: HashMap::new(),
            streams: HashMap::new(),
            starting_streams: HashMap::new(),
            shutdown: false,
        }
    }

    #[allow(dead_code)]
    pub fn contact_card(&self) -> ContactCard {
        self.core.contact_card().clone()
    }

    pub fn create_stream(
        &mut self,
        target: &PeerId,
        direction: beelay_core::StreamDirection,
    ) -> beelay_core::StreamId {
        let (command, event) = beelay_core::Event::create_stream(direction);
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
                        beelay_core::StreamEvent::Close => {}
                    }
                }
            }
            for (doc_id, events) in results.notifications.into_iter() {
                self.notifications.entry(doc_id).or_default().extend(events);
            }
            if results.stopped {
                self.shutdown = true;
            }
        }
    }

    pub fn handle_task(&mut self, task: beelay_core::io::IoTask) -> beelay_core::Event {
        let result = handle_task(&mut self.storage, &mut self.signing_key, task);
        beelay_core::Event::io_complete(result)
    }

    #[allow(dead_code)]
    pub fn pop_notifications(
        &mut self,
    ) -> HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>> {
        std::mem::take(&mut self.notifications)
    }
}

fn handle_task(
    storage: &mut BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    signing_key: &mut SigningKey,
    task: beelay_core::io::IoTask,
) -> beelay_core::io::IoResult {
    let id = task.id();
    match task.take_action() {
        IoAction::Load { key } => {
            let data = storage.get(&key).cloned();
            IoResult::load(id, data)
        }
        IoAction::Put { key, data } => {
            storage.insert(key, data);
            IoResult::put(id)
        }
        IoAction::Delete { key } => {
            storage.remove(&key);
            IoResult::delete(id)
        }
        IoAction::LoadRange { prefix } => {
            let results = storage
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
        IoAction::ListOneLevel { prefix } => {
            let keys_in_storage = storage.keys().map(|k| k.to_string()).collect::<Vec<_>>();
            tracing::trace!(prefix = ?prefix, ?keys_in_storage, "listing one level of storage");
            let results = storage
                .keys()
                .filter_map(|k| k.onelevel_deeper(&prefix))
                .collect();
            IoResult::list_one_level(id, results)
        }
        IoAction::Sign { payload } => {
            let signature = signing_key.sign(&payload);
            IoResult::sign(id, signature)
        }
    }
}

pub struct ConnectedPair {
    #[allow(dead_code)]
    pub left_to_right: beelay_core::StreamId,
    #[allow(dead_code)]
    pub right_to_left: beelay_core::StreamId,
}
