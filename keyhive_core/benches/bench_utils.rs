use dupe::Dupe;
use future_form::Sendable;
use keyhive_core::{
    content::heads::ContentHeads,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::individual::{id::IndividualId, op::KeyOp},
    store::ciphertext::memory::MemoryCiphertextStore,
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::signer::memory::MemorySigner;
use keyline::power::Power;
use keyline_memory::MemoryKeyline;
use nonempty::nonempty;
use rand::rngs::OsRng;

pub type BenchKeyhive = Keyhive<
    Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    OsRng,
    MemoryKeyline<ContentHeads<[u8; 32]>>,
>;
pub struct Scenario {
    pub keyhive: BenchKeyhive,
    pub agents: Vec<IndividualId>,
}

/// Set up a scenario with `n_peers` peers, each added to 2 docs.
///
/// One group is created containing the second half of the peers and added to
/// the second doc, so there is overlapping membership via both direct and
/// transitive paths.
///
/// If `prekey_rotations_per_peer > 0`, each peer will have that many extra
/// expand + rotate cycles applied before being added to docs.
pub async fn setup_scenario(n_peers: usize, prekey_rotations_per_peer: usize) -> Scenario {
    let alice = make_simple_keyhive().await.unwrap();

    // Create peers (with optional prekey rotations)
    let mut peers_on_alice = Vec::with_capacity(n_peers);
    for _ in 0..n_peers {
        let peer = make_simple_keyhive().await.unwrap();
        let peer_contact = peer.generate_contact_card().await.unwrap();
        let peer_id = alice.receive_contact_card(&peer_contact).await.unwrap();

        for _ in 0..prekey_rotations_per_peer {
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

        peers_on_alice.push(peer_id);
    }

    // doc1: all peers are direct members
    let doc1_id = alice
        .generate_doc(vec![], nonempty![[0u8; 32]])
        .await
        .unwrap();
    for peer_id in &peers_on_alice {
        alice
            .add_member(*peer_id, doc1_id, Power::Edit)
            .await
            .unwrap();
    }

    // doc2: first half are direct members
    let doc2_id = alice
        .generate_doc(vec![], nonempty![[1u8; 32]])
        .await
        .unwrap();
    let half = n_peers / 2;
    for peer_id in &peers_on_alice[..half] {
        alice
            .add_member(*peer_id, doc2_id, Power::Read)
            .await
            .unwrap();
    }

    // group: second half of peers, then group added to doc2
    let group_id = alice.generate_group(vec![]).await.unwrap();
    for peer_id in &peers_on_alice[half..] {
        alice
            .add_member(*peer_id, group_id, Power::Edit)
            .await
            .unwrap();
    }
    alice
        .add_member(group_id, doc2_id, Power::Read)
        .await
        .unwrap();

    Scenario {
        keyhive: alice,
        agents: peers_on_alice,
    }
}
