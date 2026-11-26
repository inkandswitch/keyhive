//! Whether a member invited while concurrent CGKA epochs exist can read the
//! content written under each of them.
//!
//! Upstream no longer nudges (edits that force a member to re-key after an add).
//! It relies on the add's invitation wrapping the root secrets of the inviter's
//! nearest update ancestors, and on a later writer rotating, which chains the
//! concurrent epochs through predecessor secrets. An add is only causally
//! after the epochs its inviter had seen, so an epoch concurrent with the add
//! is covered by neither route until somebody who holds it writes.

use crate::{
    cgka::{Cgka, NoImplicitRemoves},
    keys::ShareKeyMap,
    operation::CgkaOperation,
    pcs_key::PcsKey,
    test_utils::{member, Group},
};
use alloc::{sync::Arc, vec, vec::Vec};
use future_form::Local;
use keyhive_crypto::{digest::Digest, signer::memory::MemorySigner};
use rand::{rngs::StdRng, SeedableRng};

/// Everything encrypted under one epoch, named by the update that produced it.
struct Epoch {
    label: &'static str,
    update: Digest<CgkaOperation>,
    secret: PcsKey,
}

#[derive(Clone, Copy)]
enum Inviter {
    /// Alice has applied only her own concurrent update when she invites.
    HoldsOneEpoch,
    /// Alice has applied both concurrent updates when she invites.
    HoldsBothEpochs,
}

/// The labels of the epochs the invitee cannot read once every operation has
/// been delivered to everyone.
async fn unreadable_epochs(inviter: Inviter, later_write: bool) -> Vec<&'static str> {
    let mut rng = StdRng::seed_from_u64(0x5ec0_00e0);
    // 0 = Alice (inviter), 1 = Bob, 2 = Carol (holds everything, may write later).
    let mut group = Group::new(3, &mut rng).await;
    let mut epochs = Vec::new();

    let settled = group.rotate(0, &mut rng).await;
    group.broadcast(&settled);
    epochs.push(Epoch {
        label: "settled",
        update: settled.digest(),
        secret: group.replicas[0]
            .root_secrets
            .get(&settled.digest())
            .unwrap(),
    });

    // Two concurrent updates on top of the settled epoch.
    let by_alice = group.rotate(0, &mut rng).await;
    let by_bob = group.rotate(1, &mut rng).await;
    for (label, op, author) in [("alice", &by_alice, 0), ("bob", &by_bob, 1)] {
        epochs.push(Epoch {
            label,
            update: op.digest(),
            secret: group.replicas[author]
                .root_secrets
                .get(&op.digest())
                .unwrap(),
        });
    }
    group.deliver(&by_alice, &[2]);
    group.deliver(&by_bob, &[2]);
    if let Inviter::HoldsBothEpochs = inviter {
        group.deliver(&by_bob, &[0]);
    }

    let invitee = member(&mut rng);
    let add = group.add(0, invitee.id, invitee.pk).await;
    // Everyone converges on every operation, the add last so it applies in causal order.
    group.broadcast(&by_alice);
    group.broadcast(&by_bob);
    group.broadcast(&add);

    if later_write {
        // Carol writes as `group_secret_for_write` would, rotating because she
        // cannot derive a single root.
        let signer: &MemorySigner = &group.members[2].signer;
        let (_, _, rotation) = group.replicas[2]
            .group_secret_for_write::<Local, _, StdRng>(signer, &mut rng)
            .await
            .expect("carol can write");
        let (op, _) = rotation.expect("concurrent epochs make the writer rotate");
        group.broadcast(&Arc::new(op));
    }

    let mut sks = ShareKeyMap::new();
    sks.insert(invitee.pk, invitee.sk);
    let mut view: Cgka<NoImplicitRemoves> = group.replica_for(invitee.id, sks);

    epochs
        .iter()
        .filter(|e| {
            view.group_secret_from_hashes(&e.secret.digest(), &e.update)
                .is_err()
        })
        .map(|e| e.label)
        .collect()
}

/// (a) No later write. The add is concurrent with Bob's update, so its
/// invitation cannot wrap Bob's epoch. Documents the gap: when this starts
/// failing, the gap is closed and this test should become a plain assertion.
#[tokio::test]
async fn gap_invitee_cannot_read_the_epoch_concurrent_with_the_add_before_any_later_write() {
    assert_eq!(
        unreadable_epochs(Inviter::HoldsOneEpoch, false).await,
        vec!["bob"]
    );
}

/// (b) A later write by a member who can derive both epochs chains them and
/// heals the gap.
#[tokio::test]
async fn a_later_write_by_a_member_holding_both_epochs_heals_the_invitee() {
    assert_eq!(
        unreadable_epochs(Inviter::HoldsOneEpoch, true).await,
        Vec::<&str>::new()
    );
}

/// (c) The inviter holds both epochs, so the invitation wraps both.
#[tokio::test]
async fn an_inviter_holding_both_epochs_covers_the_invitee_without_a_later_write() {
    assert_eq!(
        unreadable_epochs(Inviter::HoldsBothEpochs, false).await,
        Vec::<&str>::new()
    );
}
