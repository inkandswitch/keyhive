use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use beelay_core::{
    io::{IoAction, IoResult},
    BundleSpec, CommitHash, CommitOrBundle, DocEvent, DocumentId, PeerId, SnapshotId,
    SyncDocResult,
};

fn init_logging() {
    let _ = tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .pretty()
        .try_init();
}

#[test]
fn save_and_load() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");

    let doc_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc_id, vec![commit1.clone()]);

    let loaded = network.beelay(&peer1).load_doc(doc_id).unwrap();
    assert_eq!(loaded, vec![CommitOrBundle::Commit(commit1)]);
}

#[test]
fn create_and_sync() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    let doc1_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone(), commit2.clone()]);

    let doc2_id = network.beelay(&peer1).create_doc();
    let commit3 = beelay_core::Commit::new(vec![], vec![7, 8, 9], CommitHash::from([3; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc2_id, vec![commit3.clone()]);

    network.beelay(&peer1).add_link(beelay_core::AddLink {
        from: doc1_id,
        to: doc2_id,
    });

    let sync_with_2 = network.beelay(&peer2).sync_doc(doc1_id, peer1.clone());

    let commits_on_2: HashSet<beelay_core::Commit> = network
        .beelay(&peer2)
        .load_doc(doc1_id)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit");
            };
            c
        })
        .collect();
    let expected_commits = vec![commit1.clone(), commit2.clone()]
        .into_iter()
        .collect::<HashSet<_>>();

    let docs_on_2 = sync_with_2
        .differing_docs
        .into_iter()
        .collect::<HashSet<_>>();
    let expected_docs = vec![doc1_id, doc2_id].into_iter().collect::<HashSet<_>>();

    if !(docs_on_2 == expected_docs) {
        println!("failed to converge");
        assert_eq!(docs_on_2, vec![doc1_id, doc2_id].into_iter().collect());
    }

    assert_eq!(commits_on_2, expected_commits);
}

#[test]
fn request_from_connected() {
    // Test that in a network like this:
    //
    // peer1 <-> peer2 <-> peer3
    //
    // If peer1 has a document and peer 2 is configured to forward requests to
    // peer1 then requesting the document on peer3 will result in the document
    // being synced to peer3.

    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    network.forward_requests(&peer2, &peer1);

    let doc1_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    network.beelay(&peer3).sync_doc(doc1_id, peer2.clone());
    let commits_on_3: HashSet<beelay_core::Commit> = network
        .beelay(&peer3)
        .load_doc(doc1_id)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit");
            };
            c
        })
        .collect();
    let expected_commits = vec![commit1.clone()].into_iter().collect::<HashSet<_>>();
    assert_eq!(commits_on_3, expected_commits);
}

#[test]
fn listen_to_connected() {
    // Test that in a network like this:
    //
    // peer1 <-> peer2 <-> peer3
    //
    // If peer1 has a document and peer 2 is configured to forward requests to
    // peer1 then listening to the document on peer3 will result in updates on
    // peer1 being propagated to peer3.

    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    network.forward_requests(&peer2, &peer1);

    let doc1_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    // Sync up
    let sync_with_2 = network.beelay(&peer3).sync_doc(doc1_id, peer2.clone());

    // Now listen to further changes on peer3
    network
        .beelay(&peer3)
        .listen(&peer2, sync_with_2.remote_snapshot);

    // Now make a change on peer1
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit2.clone()]);

    // The commits should have been forwarded to peer3
    let commits_on_3: HashSet<beelay_core::Commit> = network
        .beelay(&peer3)
        .load_doc(doc1_id)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let CommitOrBundle::Commit(c) = c else {
                panic!("expected commit");
            };
            c
        })
        .collect();
    let expected_commits = vec![commit1.clone(), commit2.clone()]
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(commits_on_3, expected_commits);
}

#[test]
fn listen() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    let doc1_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    let _sync_with_2 = network.beelay(&peer1).sync_doc(doc1_id, peer2.clone());
    let sync_with_3 = network.beelay(&peer2).sync_doc(doc1_id, peer3.clone());
    network
        .beelay(&peer2)
        .listen(&peer3, sync_with_3.remote_snapshot);

    // Now add a commit on beelay 3 and check that it appears on beelay 2
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer3)
        .add_commits(doc1_id, vec![commit2.clone()]);
    let notifications = network.beelay(&peer2).pop_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0],
        DocEvent {
            peer: peer3,
            doc: doc1_id,
            data: CommitOrBundle::Commit(commit2)
        }
    );
}

#[test]
fn three_peers_listening_to_each_other_do_not_loop() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");
    let peer3 = network.create_peer("peer3");

    network.forward_requests(&peer2, &peer3);
    network.forward_requests(&peer2, &peer1);

    let doc1_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    let sync_with_2 = network.beelay(&peer1).sync_doc(doc1_id, peer2.clone());
    network
        .beelay(&peer1)
        .listen(&peer2, sync_with_2.remote_snapshot);

    let sync_with_3 = network.beelay(&peer3).sync_doc(doc1_id, peer2.clone());
    network
        .beelay(&peer3)
        .listen(&peer2, sync_with_3.remote_snapshot);

    // Now add a commit on beelay 1 and check that everything terminates
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit2.clone()]);
}

#[test]
fn two_peers_listening_to_each_other_do_not_loop() {
    init_logging();
    let mut network = Network::new();
    let peer1 = network.create_peer("peer1");
    let peer2 = network.create_peer("peer2");

    network.forward_requests(&peer1, &peer2);
    network.forward_requests(&peer2, &peer1);

    let doc1_id = network.beelay(&peer1).create_doc();
    let commit1 = beelay_core::Commit::new(vec![], vec![1, 2, 3], CommitHash::from([1; 32]));
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit1.clone()]);

    let sync_with_2 = network.beelay(&peer1).sync_doc(doc1_id, peer2.clone());
    network
        .beelay(&peer1)
        .listen(&peer2, sync_with_2.remote_snapshot);
    network
        .beelay(&peer2)
        .listen(&peer1, sync_with_2.local_snapshot);

    // Now add a commit on beelay 1 and check that everything terminates
    let commit2 = beelay_core::Commit::new(
        vec![commit1.hash()],
        vec![4, 5, 6],
        CommitHash::from([2; 32]),
    );
    network
        .beelay(&peer1)
        .add_commits(doc1_id, vec![commit2.clone()]);
}

#[test]
fn saving_many_times_loads_correctly() {
    init_logging();
    let mut network = Network::new();
    let peer = network.create_peer("peer");

    let doc_id = network.beelay(&peer).create_doc();

    let mut saved_commits = HashSet::new();

    const NUM_COMMITS: usize = 101;
    let mut last_commit_hash = None;
    for i in 0..NUM_COMMITS {
        let this_hash = CommitHash::from([i as u8; 32]);
        let commit = beelay_core::Commit::new(
            last_commit_hash.iter().cloned().collect(),
            vec![i as u8; 3],
            this_hash,
        );
        saved_commits.insert(commit.clone());
        network.beelay(&peer).add_commits(doc_id, vec![commit]);
        last_commit_hash = Some(this_hash);
    }

    let loaded_commits = network
        .beelay(&peer)
        .load_doc(doc_id)
        .expect("doc not found")
        .into_iter()
        .map(|c_or_b| {
            let CommitOrBundle::Commit(c) = c_or_b else {
                panic!("expected a commit");
            };
            c
        })
        .collect::<HashSet<_>>();
    assert_eq!(loaded_commits.len(), NUM_COMMITS);
    if loaded_commits != saved_commits {
        let diff = loaded_commits
            .symmetric_difference(&saved_commits)
            .collect::<Vec<_>>();
        println!(
            "saved and loaded commits differ, {} differing elements",
            diff.len()
        );
        println!("difference: {:?}", diff);
    }
}

struct BeelayHandle<'a> {
    network: &'a mut Network,
    peer_id: beelay_core::PeerId,
}

impl<'a> BeelayHandle<'a> {
    fn create_doc(&mut self) -> DocumentId {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::create_doc();
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(beelay_core::StoryResult::CreateDoc(doc_id)) => doc_id,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    fn sync_doc(&mut self, doc: DocumentId, peer: PeerId) -> SyncDocResult {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::sync_doc(doc, peer);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(beelay_core::StoryResult::SyncDoc(result)) => result,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    fn listen(&mut self, with_peer: &PeerId, from_snapshot: SnapshotId) {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::listen(with_peer.clone(), from_snapshot);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(beelay_core::StoryResult::Listen) => (),
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    fn add_commits(
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
            Some(beelay_core::StoryResult::AddCommits(new_bundles_needed)) => new_bundles_needed,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    fn add_link(&mut self, add: beelay_core::AddLink) {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::add_link(add);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(beelay_core::StoryResult::AddLink) => (),
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    fn load_doc(&mut self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let story = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (story, event) = beelay_core::Event::load_doc(doc_id);
            beelay.inbox.push_back(event);
            story
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_stories.remove(&story) {
            Some(beelay_core::StoryResult::LoadDoc(commits)) => commits,
            Some(other) => panic!("unexpected story result: {:?}", other),
            None => panic!("no story result"),
        }
    }

    fn pop_notifications(&mut self) -> Vec<DocEvent> {
        std::mem::take(
            &mut self
                .network
                .beelays
                .get_mut(&self.peer_id)
                .unwrap()
                .notifications,
        )
    }
}

struct Network {
    beelays: HashMap<beelay_core::PeerId, BeelayWrapper>,
}

impl Network {
    fn new() -> Self {
        Self {
            beelays: HashMap::new(),
        }
    }

    fn beelay(&mut self, peer: &PeerId) -> BeelayHandle {
        assert!(self.beelays.contains_key(peer));
        BeelayHandle {
            network: self,
            peer_id: peer.clone(),
        }
    }

    fn create_peer(&mut self, nickname: &str) -> PeerId {
        // let peer_id = beelay_core::PeerId::random(&mut rand::thread_rng());
        let peer_id = beelay_core::PeerId::from(nickname.to_string());
        let beelay = BeelayWrapper::new(beelay_core::Beelay::new(
            peer_id.clone(),
            rand::thread_rng(),
        ));
        self.beelays.insert(peer_id.clone(), beelay);
        self.run_until_quiescent();
        peer_id
    }

    fn forward_requests(&mut self, from: &PeerId, to: &PeerId) {
        self.beelays
            .get_mut(from)
            .unwrap()
            .peers_to_forward_to
            .push(to.clone());
    }

    fn run_until_quiescent(&mut self) {
        loop {
            let mut messages_this_round = HashMap::new();
            for (_, beelay) in self.beelays.iter_mut() {
                beelay.handle_events();
                for envelope in beelay.outbox.drain(..) {
                    messages_this_round
                        .entry(envelope.recipient().clone())
                        .or_insert_with(Vec::new)
                        .push(envelope);
                }
            }
            if messages_this_round.is_empty() {
                break;
            }
            for (recipient, envelopes) in messages_this_round {
                self.beelays
                    .get_mut(&recipient)
                    .unwrap()
                    .inbox
                    .extend(envelopes.into_iter().map(beelay_core::Event::receive));
            }
        }
    }
}

struct BeelayWrapper {
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: beelay_core::Beelay<rand::rngs::ThreadRng>,
    outbox: Vec<beelay_core::Envelope>,
    inbox: VecDeque<beelay_core::Event>,
    completed_stories: HashMap<beelay_core::StoryId, beelay_core::StoryResult>,
    notifications: Vec<DocEvent>,
    peers_to_forward_to: Vec<beelay_core::PeerId>,
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
            peers_to_forward_to: Vec::new(),
        }
    }

    fn handle_events(&mut self) {
        while let Some(event) = self.inbox.pop_front() {
            let results = self.core.handle_event(event).unwrap();
            self.outbox.extend(results.new_messages.into_iter());
            for task in results.new_tasks.into_iter() {
                let event = self.handle_task(task);
                self.inbox.push_back(event);
            }
            for (story, result) in results.completed_stories.into_iter() {
                self.completed_stories.insert(story, result);
            }
            self.notifications.extend(results.notifications.into_iter());
        }
    }

    fn handle_task(&mut self, task: beelay_core::io::IoTask) -> beelay_core::Event {
        let id = task.id();
        let result = match task.take_action() {
            IoAction::Load { key } => {
                //tracing::debug!(%key, "load");
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
            IoAction::Ask { about: _ } => {
                IoResult::ask(id, self.peers_to_forward_to.iter().cloned().collect())
            }
        };
        beelay_core::Event::io_complete(result)
    }
}
