use beekem::{cgka::Cgka, id::MemberId};
use future_form::Sendable;
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signer::memory::MemorySigner,
    verifiable::Verifiable,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::sync::Arc;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A fresh member identity and the share key it joins with.
fn member<R: CryptoRng + RngCore>(rng: &mut R) -> (MemberId, ShareKey) {
    let signer = MemorySigner::generate(rng);
    let sk = ShareSecretKey::generate(rng);
    (MemberId::from(signer.verifying_key()), sk.share_key())
}

/// Build a `Cgka` with an owner and `extra` further members.
async fn cgka_with<R: CryptoRng + RngCore>(
    rng: &mut R,
    extra: usize,
) -> Result<(Cgka, MemorySigner, Vec<MemberId>)> {
    let signer = MemorySigner::generate(rng);
    let (owner_id, owner_pk) = member(rng);
    let tree_id = beekem::id::TreeId::from(signer.verifying_key());
    let mut cgka = Cgka::new::<Sendable, _>(tree_id, owner_id, owner_pk, &signer).await?;

    let mut members = Vec::new();
    for _ in 0..extra {
        let (id, pk) = member(rng);
        cgka.add::<Sendable, _>(id, pk, &signer).await?;
        members.push(id);
    }
    Ok((cgka, signer, members))
}

fn ids(cgka: &Cgka) -> Vec<String> {
    let mut v: Vec<String> = cgka.member_ids().map(|m| format!("{m}")).collect();
    v.sort();
    v
}

fn has(list: &[String], id: MemberId) -> bool {
    list.contains(&format!("{id}"))
}

/// Force both replicas to apply everything they have queued, then return their
/// members. Adding a new probe member forces replay.
async fn settle<R: CryptoRng + RngCore>(
    left: &mut Cgka,
    right: &mut Cgka,
    signer: &MemorySigner,
    rng: &mut R,
) -> Result<(Vec<String>, Vec<String>)> {
    let (probe, probe_pk) = member(rng);
    left.add::<Sendable, _>(probe, probe_pk, signer).await?;
    right.add::<Sendable, _>(probe, probe_pk, signer).await?;
    Ok((ids(left), ids(right)))
}

/// Adding a new member while a different member is concurrently removed should
/// not cause the new member to be lost.
#[tokio::test]
async fn a_concurrent_add_and_remove_retains_the_add() -> Result<()> {
    for round in 0..40 {
        let (mut left, signer, members) = cgka_with(&mut OsRng, 3).await?;
        let mut right = left.clone();

        // Left removes an existing member; right concurrently adds a new one.
        let member_to_remove = members[round % members.len()];
        let Some(remove_op) = left
            .remove::<Sendable, _>(member_to_remove, &signer)
            .await?
        else {
            continue;
        };
        let (new_id, new_pk) = member(&mut OsRng);
        let Some(add_op) = right.add::<Sendable, _>(new_id, new_pk, &signer).await? else {
            continue;
        };

        left.merge_concurrent_operation(Arc::new(add_op))?;
        right.merge_concurrent_operation(Arc::new(remove_op))?;

        let (l, r) = settle(&mut left, &mut right, &signer, &mut OsRng).await?;
        assert_eq!(
            l, r,
            "round {round}: replicas disagree after a concurrent add and remove"
        );
        assert!(
            has(&l, new_id),
            "round {round}: the concurrently added member was lost: {l:?}"
        );
        assert!(
            !has(&l, member_to_remove),
            "round {round}: the removed member is still present: {l:?}"
        );
    }
    Ok(())
}

/// Adding multiple new members while a different member is concurrently removed should
/// not cause the new members to be lost.
#[tokio::test]
async fn a_remove_concurrent_with_several_adds_retains_the_adds() -> Result<()> {
    for round in 0..30 {
        let (mut left, signer, members) = cgka_with(&mut OsRng, 4).await?;
        let mut right = left.clone();

        let member_to_remove = members[round % members.len()];
        let Some(remove_op) = left
            .remove::<Sendable, _>(member_to_remove, &signer)
            .await?
        else {
            continue;
        };

        let mut add_ops = Vec::new();
        let mut added = Vec::new();
        for _ in 0..3 {
            let (id, pk) = member(&mut OsRng);
            if let Some(op) = right.add::<Sendable, _>(id, pk, &signer).await? {
                add_ops.push(op);
                added.push(id);
            }
        }

        for op in &add_ops {
            left.merge_concurrent_operation(Arc::new(op.clone()))?;
        }
        right.merge_concurrent_operation(Arc::new(remove_op))?;

        let (l, r) = settle(&mut left, &mut right, &signer, &mut OsRng).await?;
        assert_eq!(
            l, r,
            "round {round}: replicas disagree after a remove concurrent with three adds"
        );
        for id in &added {
            assert!(
                has(&l, *id),
                "round {round}: an added member was lost: {l:?}"
            );
        }
        assert!(
            !has(&l, member_to_remove),
            "round {round}: the removed member survived: {l:?}"
        );
    }
    Ok(())
}

/// One random operation on one replica.
#[derive(Clone, Copy, Debug)]
enum CgkaOp {
    Add,
    Remove(usize),
    Update,
}

/// Build and run one random scenario. Returns a description of the divergence,
/// if any.
///
/// Several replicas branch from a common state, each applies a few operations
/// without seeing the others, then every operation is delivered to every replica
/// and they are made to settle. They must agree.
async fn scenario(seed: u64) -> Result<Option<String>> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(seed);

    let replica_count = rng.gen_range(2..=3);
    let base_members = rng.gen_range(1..=4);
    let trace = std::env::var("BEEKEM_TRACE").is_ok();
    if trace {
        eprintln!("seed {seed}: replicas={replica_count} base_members={base_members}");
    }
    let (base, signer, _) = cgka_with(&mut rng, base_members).await?;
    let members: Vec<MemberId> = base.member_ids().collect();

    let mut replicas: Vec<Cgka> = (0..replica_count).map(|_| base.clone()).collect();
    let mut ops = Vec::new();

    for replica in replicas.iter_mut() {
        for _ in 0..rng.gen_range(1..=3) {
            let op = match rng.gen_range(0..3) {
                0 => CgkaOp::Add,
                1 if !members.is_empty() => CgkaOp::Remove(rng.gen_range(0..members.len())),
                _ => CgkaOp::Update,
            };
            if trace {
                eprintln!("  replica op: {op:?}");
            }
            match op {
                CgkaOp::Add => {
                    let (id, pk) = member(&mut rng);
                    if let Some(o) = replica.add::<Sendable, _>(id, pk, &signer).await? {
                        ops.push(o);
                    }
                }
                CgkaOp::Remove(i) => {
                    if let Ok(Some(o)) = replica.remove::<Sendable, _>(members[i], &signer).await {
                        ops.push(o);
                    }
                }
                CgkaOp::Update => {
                    let sk = ShareSecretKey::generate(&mut rng);
                    if let Ok((_, o)) = replica
                        .update::<Sendable, _, _>(sk.share_key(), sk, &signer, &mut rng)
                        .await
                    {
                        ops.push(o);
                    }
                }
            }
        }
    }

    // Deliver everything to everyone, retrying until nothing more applies.
    for replica in replicas.iter_mut() {
        let mut pending: Vec<_> = ops.clone();
        loop {
            let before = pending.len();
            pending.retain(|op| {
                replica
                    .merge_concurrent_operation(Arc::new(op.clone()))
                    .is_err()
            });
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        if !pending.is_empty() {
            return Ok(None);
        }
    }

    // Adding a new probe member forces replay. This should cause everyone to
    // converge.
    let (probe, probe_pk) = member(&mut rng);
    let mut views = Vec::new();
    for (i, replica) in replicas.iter_mut().enumerate() {
        match replica.add::<Sendable, _>(probe, probe_pk, &signer).await {
            Ok(_) => views.push(ids(replica)),
            Err(e) => {
                return Ok(Some(format!(
                    "replica {i}: adding a member after merging failed with {e:?}"
                )))
            }
        }
    }

    for (i, view) in views.iter().enumerate().skip(1) {
        if view != &views[0] {
            return Ok(Some(format!(
                "replica {i} disagrees with replica 0\n  0: {:?}\n  {i}: {:?}",
                views[0], view
            )));
        }
    }
    Ok(None)
}

#[tokio::test]
async fn replicas_converge_over_random_concurrent_operations() -> Result<()> {
    let (start, end) = match std::env::var("BEEKEM_SEEDS") {
        Ok(v) => {
            let (a, b) = v.split_once("..").expect("start..end");
            (a.parse::<u64>()?, b.parse::<u64>()?)
        }
        Err(_) => (0, 200),
    };

    let mut failures = Vec::new();
    for seed in start..end {
        if let Some(why) = scenario(seed).await? {
            failures.push(format!("--- seed {seed}: {why}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} seeds diverged\n\n{}",
        failures.len(),
        end - start,
        failures
            .iter()
            .take(80)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    Ok(())
}

#[tokio::test]
async fn a_duplicate_remove_should_not_create_an_invalid_state() -> Result<()> {
    let (mut left, signer, members) = cgka_with(&mut OsRng, 2).await?;
    let mut right = left.clone();
    let member_to_remove = members[0];

    // Left: remove a member.
    let rm_left = left
        .remove::<Sendable, _>(member_to_remove, &signer)
        .await?
        .expect("the removed member is present");

    // Right: add someone else, then remove the same member removed above.
    let (extra, extra_pk) = member(&mut OsRng);
    let add_right = right
        .add::<Sendable, _>(extra, extra_pk, &signer)
        .await?
        .expect("a fresh member is added");
    let rm_right = right
        .remove::<Sendable, _>(member_to_remove, &signer)
        .await?
        .expect("the removed member is present here too");

    // Exchange everything, retrying so ordering is not the issue.
    for (replica, incoming) in [
        (&mut left, vec![add_right.clone(), rm_right.clone()]),
        (&mut right, vec![rm_left.clone()]),
    ] {
        let mut pending = incoming;
        loop {
            let before = pending.len();
            pending.retain(|op| {
                replica
                    .merge_concurrent_operation(Arc::new(op.clone()))
                    .is_err()
            });
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        assert!(pending.is_empty(), "an operation could never be applied");
    }

    let (probe, probe_pk) = member(&mut OsRng);
    left.add::<Sendable, _>(probe, probe_pk, &signer)
        .await
        .map_err(|e| format!("left could not add a member afterwards: {e:?}"))?;
    right
        .add::<Sendable, _>(probe, probe_pk, &signer)
        .await
        .map_err(|e| format!("right could not add a member afterwards: {e:?}"))?;

    assert_eq!(ids(&left), ids(&right), "replicas disagree");
    Ok(())
}
