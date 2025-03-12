// use std::collections::HashMap;

// use beelay_core::{
//     keyhive::{Access, AddMemberToGroup, KeyhiveEntityId, MemberAccess},
//     Commit,
// };
// use keyhive_core::principal::public::Public;
// use network::{ConnectedPair, Network};
// use test_utils::init_logging;

mod network;

// #[test]
// fn giving_access_to_peer_enables_reading() {
//     init_logging();
//     let mut network = Network::new();
//     let peer1 = network.create_peer("peer1");
//     let peer2 = network.create_peer("peer2");
//     let peer3 = network.create_peer("peer3");

//     let ConnectedPair {
//         left_to_right: peer1_to_peer2,
//         right_to_left: peer2_to_peer1,
//     } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);
//     let ConnectedPair {
//         right_to_left: peer3_to_peer2,
//         ..
//     } = network.connect_stream(&peer2, &peer3, ConnForwarding::Both);

//     let doc = network
//         .beelay(&peer1)
//         .create_doc_with_contents(Access::Private, "somedoc".into());
//     network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);

//     // Now fetch the doc on peer2, it shouldn't be found because we don't have access
//     let synced_to_2 = network.beelay(&peer2).sync_doc(doc, peer2_to_peer1);
//     assert_eq!(synced_to_2.found, false);

//     // Likewise peer3 should not have access
//     let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
//     assert_eq!(synced_to_3.found, false);

//     // Now give access to peer2
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::Peer(peer2), MemberAccess::Pull)
//         .unwrap();

//     // Syncing from peer2 should now work
//     let synced_to_2 = network.beelay(&peer2).sync_doc(doc, peer2_to_peer1);
//     assert_eq!(synced_to_2.found, true);

//     // But syncing from peer2 to peer3 should fail
//     let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
//     assert_eq!(synced_to_3.found, false);

//     // Now add peer3
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::Peer(peer3), MemberAccess::Pull)
//         .unwrap();

//     // Now the sync should work
//     let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
//     assert_eq!(synced_to_3.found, true);

//     let commits_on_3_before_revocation = network.beelay(&peer3).load_doc(doc).unwrap();

//     // Now, revoking access to peer3 should make the sync fail again
//     network
//         .beelay(&peer1)
//         .remove_member_from_doc(doc, KeyhiveEntityId::Peer(peer3))
//         .unwrap();

//     // Add a new commit on peer1
//     network
//         .beelay(&peer1)
//         .add_commits(
//             doc,
//             vec![Commit::new(vec![], "whooop".into(), [7; 32].into())],
//         )
//         .unwrap();

//     tracing::info!("done uploading");

//     // Now run sync on 3 again
//     let _synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);

//     // Load commits on 3, they should be the same as before the call to add them
//     let commits_on_3_after_revocation = network.beelay(&peer3).load_doc(doc).unwrap();
//     assert_eq!(
//         commits_on_3_before_revocation,
//         commits_on_3_after_revocation
//     );
// }

// #[test]
// fn make_public_then_remove_public_fails_write() {
//     init_logging();
//     let mut network = Network::new();
//     let peer1 = network.create_peer("peer1");
//     let peer2 = network.create_peer("peer2");
//     let peer3 = network.create_peer("peer3");

//     let ConnectedPair {
//         left_to_right: peer1_to_peer2,
//         right_to_left: peer2_to_peer1,
//     } = network.connect_stream(&peer1, &peer2, ConnForwarding::LeftToRight);
//     let ConnectedPair {
//         right_to_left: peer3_to_peer2,
//         ..
//     } = network.connect_stream(&peer2, &peer3, ConnForwarding::RightToLeft);

//     let doc = network
//         .beelay(&peer1)
//         .create_doc_with_contents(Access::Private, "somedoc".into());
//     network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);

//     // Now give access to peer2
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::Peer(peer2), MemberAccess::Pull)
//         .unwrap();

//     // Give write access to public
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::public(), MemberAccess::Write)
//         .unwrap();

//     // Now sync the doc to peer3
//     let synced_to_3 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);
//     assert_eq!(synced_to_3.found, true);

//     // Now revoke public access
//     network
//         .beelay(&peer1)
//         .remove_member_from_doc(doc, KeyhiveEntityId::public())
//         .unwrap();

//     // Make a change on peer3
//     network
//         .beelay(&peer3)
//         .add_commits(
//             doc,
//             vec![Commit::new(vec![], "whooop".into(), [7; 32].into())],
//         )
//         .unwrap();

//     // Now sync the doc to peer2
//     let synced_to_2 = network.beelay(&peer3).sync_doc(doc, peer3_to_peer2);

//     // Now check commits on 2 and 3 are different
//     let commits_on_2 = network.beelay(&peer2).load_doc(doc).unwrap();
//     let commits_on_3 = network.beelay(&peer3).load_doc(doc).unwrap();
//     assert_eq!(commits_on_2.len(), 0); // There is one commit on disk, but it fails decryption
//     assert_eq!(commits_on_3.len(), 1); // There are two commits on disk, but only one can be decrypted
//     assert_ne!(commits_on_2, commits_on_3);
// }

// #[test]
// fn syncing_private_doc_sends_doc_to_server() {
//     init_logging();
//     let mut network = Network::new();
//     let peer1 = network.create_peer("peer1");
//     let peer2 = network.create_peer("peer2");

//     let ConnectedPair {
//         left_to_right: peer1_to_peer2,
//         right_to_left: peer2_to_peer1,
//     } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);

//     let doc = network
//         .beelay(&peer1)
//         .create_doc_with_contents(Access::Private, "somedoc".into());
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::Peer(peer2), MemberAccess::Pull)
//         .unwrap();

//     network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);

//     let doc_on_peer2 = network.beelay(&peer2).load_doc(doc).unwrap();
//     let doc_on_peer1 = network.beelay(&peer1).load_doc(doc).unwrap();

//     // Can't do this anymore because `load_doc` errors on an encrypted doc it
//     // doesn't have access to
//     //assert_eq!(doc_on_peer2, doc_on_peer1);
// }

// #[test]
// fn make_public_then_private_then_public_then_private() {
//     init_logging();
//     let mut network = Network::new();
//     let peer1 = network.create_peer("peer1");
//     let peer2 = network.create_peer("peer2");

//     let ConnectedPair {
//         left_to_right: peer1_to_peer2,
//         right_to_left: peer2_to_peer1,
//     } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);

//     let doc = network
//         .beelay(&peer1)
//         .create_doc_with_contents(Access::Private, "somedoc".into());

//     let access = network.beelay(&peer1).query_access(doc).unwrap();
//     assert_eq!(access.get(&Public.id().0.into()), None);

//     // Give peer2 pull access so we share the auth graph with them
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::Peer(peer2), MemberAccess::Pull)
//         .unwrap();

//     // Make public
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::public(), MemberAccess::Write)
//         .unwrap();

//     // Sync the doc with peer2 just to get beehive to sync
//     network.beelay(&peer1).sync_doc(doc, peer1_to_peer2);

//     let access = network.beelay(&peer1).query_access(doc).unwrap();
//     assert_eq!(
//         access.get(&Public.id().0.into()),
//         Some(&MemberAccess::Write)
//     );
//     let access = network.beelay(&peer2).query_access(doc).unwrap();
//     assert_eq!(
//         access.get(&Public.id().0.into()),
//         Some(&MemberAccess::Write)
//     );

//     // Remove public access
//     network
//         .beelay(&peer1)
//         .remove_member_from_doc(doc, KeyhiveEntityId::public())
//         .unwrap();

//     let access = network.beelay(&peer1).query_access(doc).unwrap();
//     assert_eq!(access.get(&Public.id().0.into()), None,);

//     let access = network.beelay(&peer2).query_access(doc).unwrap();
//     assert_eq!(access.get(&Public.id().0.into()), None,);
// }

// #[test]
// fn add_and_remove_member_notify_of_changed_access() {
//     init_logging();
//     let mut network = Network::new();
//     let peer1 = network.create_peer("peer1");

//     let doc = network
//         .beelay(&peer1)
//         .create_doc_with_contents(Access::Private, "somedoc".into());

//     // now add the public member
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::public(), MemberAccess::Write)
//         .unwrap();

//     let notis = network.beelay(&peer1).pop_notifications();
//     assert_eq!(
//         notis[0],
//         beelay_core::DocEvent::AccessChanged {
//             doc: doc,
//             new_access: HashMap::from_iter([
//                 (Public.id().0.into(), MemberAccess::Write),
//                 (peer1, MemberAccess::Admin),
//             ]),
//         }
//     );
// }

// #[test]
// fn adding_document_to_group_gives_access() {
//     init_logging();

//     let mut network = Network::new();
//     let peer1 = network.create_peer("peer1");
//     let peer2 = network.create_peer("peer2");
//     let ConnectedPair {
//         left_to_right,
//         right_to_left,
//     } = network.connect_stream(&peer1, &peer2, ConnForwarding::Both);

//     // first create a group which contains both peer1 and peer2
//     let group = network.beelay(&peer1).create_group().unwrap();
//     test_utils::add_rewrite(group.to_string(), "THEGROUP");
//     network
//         .beelay(&peer1)
//         .add_member_to_group(AddMemberToGroup {
//             group_id: group,
//             member: beelay_core::KeyhiveEntityId::Peer(peer2.clone()),
//             access: MemberAccess::Admin,
//         })
//         .unwrap();

//     let doc = network
//         .beelay(&peer1)
//         .create_doc_with_contents(Access::Private, "somedoc".into());
//     test_utils::add_rewrite(doc.to_string(), "THE DOCUMENT");
//     network
//         .beelay(&peer1)
//         .add_member_to_doc(doc, KeyhiveEntityId::Group(group), MemberAccess::Read)
//         .unwrap();

//     network
//         .beelay(&peer1)
//         .add_commits(
//             doc.clone(),
//             vec![Commit::new(
//                 vec![[1; 32].into()],
//                 "two".into(),
//                 [2; 32].into(),
//             )],
//         )
//         .unwrap();

//     network.beelay(&peer1).sync_doc(doc, left_to_right);
//     network.beelay(&peer2).sync_doc(doc, right_to_left);

//     let doc_on_peer2 = network.beelay(&peer2).load_doc(doc).unwrap();
//     let doc_on_peer1 = network.beelay(&peer1).load_doc(doc).unwrap();
//     assert_eq!(doc_on_peer1, doc_on_peer2);
// }
