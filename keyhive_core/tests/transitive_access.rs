use std::{cell::RefCell, rc::Rc};

use keyhive_core::{
    access::Access, crypto::signer::memory::MemorySigner, keyhive::Keyhive,
    listener::no_listener::NoListener, principal::individual::Individual,
};
use nonempty::nonempty;

async fn make_keyhive() -> Keyhive<MemorySigner> {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    Keyhive::generate(sk, NoListener, rand::thread_rng())
        .await
        .unwrap()
}

#[tokio::test]
async fn test_group_members_have_access_to_group_docs() {
    let mut alice = make_keyhive().await;
    let mut bob = make_keyhive().await;
    let bob_contact = bob.contact_card().await.unwrap();

    let bob_on_alice = Rc::new(RefCell::new(Individual::from(bob_contact)));
    assert!(alice.register_individual(bob_on_alice.clone()));

    let group = alice.generate_group(vec![]).await.unwrap();
    alice
        .add_member(
            bob_on_alice.clone().into(),
            &mut group.clone().into(),
            Access::Read,
            &vec![],
        )
        .await
        .unwrap();
    let init_content = "hello".as_bytes();
    let init_hash = blake3::hash(init_content);

    let doc = alice
        .generate_doc(vec![group.clone().into()], nonempty![*init_hash.as_bytes()])
        .await
        .unwrap();

    let reachable = alice.docs_reachable_by_agent(&bob_on_alice.clone().into());
    assert_eq!(reachable.len(), 1);
    assert_eq!(
        reachable.get(&doc.borrow().doc_id()).unwrap().can(),
        Access::Read
    );
}
