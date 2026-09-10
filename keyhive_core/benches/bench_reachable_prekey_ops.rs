use dupe::Dupe;
use keyhive_core::{
    access::Access,
    principal::{individual::op::KeyOp, public::Public},
    test_utils::make_simple_keyhive,
};
use nonempty::nonempty;

fn main() {
    divan::main();
}

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

    let (keyhive, peer_id) = rt.block_on(async {
        let alice = make_simple_keyhive().await.unwrap();

        let mut docs = Vec::with_capacity(n_public_docs);
        for i in 0..n_public_docs {
            let hash: [u8; 32] = blake3::hash(&(i as u64).to_le_bytes()).into();
            let doc = alice
                .generate_doc(vec![Public.id()], nonempty![hash])
                .await
                .unwrap();
            docs.push(doc);
        }

        let mut last_peer_id = None;
        for _ in 0..n_peers {
            let peer = make_simple_keyhive().await.unwrap();
            let peer_contact = peer.generate_contact_card().await.unwrap();
            let peer_id = alice.receive_contact_card(&peer_contact).await.unwrap();

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

            for doc_id in &docs {
                alice
                    .add_member(peer_id, *doc_id, Access::Edit, &[])
                    .await
                    .unwrap();
            }

            last_peer_id = Some(peer_id);
        }

        let peer_id = last_peer_id.expect("need at least 1 peer");

        (alice, peer_id)
    });

    bencher.bench_local(|| {
        rt.block_on(async {
            keyhive.reachable_prekey_ops_for_agent(peer_id).await;
        });
    });
}
