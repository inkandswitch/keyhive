use future_form::Local;
use std::sync::Arc;

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    listener::no_listener::NoListener,
    principal::{
        agent::Agent, individual::op::KeyOp, membered::Membered, peer::Peer, public::Public,
    },
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::signer::memory::MemorySigner;
use nonempty::nonempty;

fn main() {
    divan::main();
}

type BenchAgent = Agent<Local, MemorySigner, [u8; 32], NoListener>;

/// Number of extra prekey expand+ rotate cycles per peer.
///
/// Each cycle adds 2 KeyOps (1 Add + 1 Rotate), so with the initial Add from
/// the contact card, each peer ends up with 1 + (2 * PREKEY_ROTATIONS_PER_PEER) ops.
const PREKEY_ROTATIONS_PER_PEER: usize = 5;

#[divan::bench(args = [
    (5, 10),
    (10, 20),
    (15, 30),
    (20, 40),
    (30, 60),
])]
fn reachable_prekey_ops_for_agent(
    bencher: divan::Bencher,
    (n_peers, n_public_docs): (usize, usize),
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (keyhive, agent) = rt.block_on(async {
        let alice = make_simple_keyhive().await.unwrap();

        let public_indie = Public.individual();
        let public_peer: Peer<Local, _, _, _> =
            Peer::Individual(public_indie.id(), Arc::new(Mutex::new(public_indie)));

        let mut docs = Vec::with_capacity(n_public_docs);
        for i in 0..n_public_docs {
            let hash: [u8; 32] = blake3::hash(&(i as u64).to_le_bytes()).into();
            let doc = alice
                .generate_doc(vec![public_peer.dupe()], nonempty![hash])
                .await
                .unwrap();
            docs.push(doc);
        }

        let mut last_peer_on_alice = None;
        for _ in 0..n_peers {
            let peer = make_simple_keyhive().await.unwrap();
            let peer_contact = peer.contact_card().await.unwrap();
            let peer_on_alice = alice.receive_contact_card(&peer_contact).await.unwrap();
            let peer_id = { peer_on_alice.lock().await.id() };

            // Accumulate prekey ops: expand then rotate, propagating each to Alice.
            for _ in 0..PREKEY_ROTATIONS_PER_PEER {
                let add_op = peer.expand_prekeys().await.unwrap();
                alice
                    .receive_prekey_op(&KeyOp::Add(add_op.dupe()))
                    .await
                    .unwrap();

                let rot_op = peer
                    .rotate_prekey(add_op.payload().share_key)
                    .await
                    .unwrap();
                alice
                    .receive_prekey_op(&KeyOp::Rotate(rot_op))
                    .await
                    .unwrap();
            }

            for doc in &docs {
                let doc_id = { doc.lock().await.doc_id() };
                alice
                    .add_member(
                        Agent::Individual(peer_id, peer_on_alice.dupe()),
                        &Membered::Document(doc_id, doc.dupe()),
                        Access::Edit,
                        &[],
                    )
                    .await
                    .unwrap();
            }

            last_peer_on_alice = Some((peer_id, peer_on_alice));
        }

        let (peer_id, peer_on_alice) = last_peer_on_alice.expect("need at least 1 peer");
        let agent: BenchAgent = Agent::Individual(peer_id, peer_on_alice);

        (alice, agent)
    });

    bencher.bench_local(|| {
        rt.block_on(async {
            keyhive.reachable_prekey_ops_for_agent(&agent).await;
        });
    });
}
