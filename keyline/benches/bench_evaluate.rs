//! Evaluation cost of `MemoryKeyline` on three shapes:
//!
//! - `realistic`: one document, an apex role, three member roles with `n`
//!   humans each, a handful of revocations. What a query costs in the common case.
//! - `club_ladder`: `k` roles each a member of the previous — the quadratic
//!   fact-space shape from `design/keyline/evaluation-notes.md` §7.
//! - `revocation_spree`: one ex-admin revokes `k` certificates; with context
//!   dedup this should scale like one dispute, not `k`.
//!
//! Run with `cargo bench -p keyline --features test_utils`.

use divan::Bencher;
use keyline::{
    access::Access,
    certificate::Certificate,
    delegation::Delegation,
    id::Id,
    keyline::Keyline,
    memory::MemoryKeyline,
    revocation::Revocation,
    test_utils::{cert, id},
};

fn main() {
    divan::main();
}

const DOC: u8 = 1;
const OWNERS: u8 = 2;
const ROLES: [u8; 3] = [3, 4, 5];
const FIRST_HUMAN: u8 = 10;
/// Identities outside the generated population, for one-off certificates.
const LADDER_LEAF: u8 = 250;
const LATE_JOINER: u8 = 251;

fn d(iss: u8, aud: u8, sub: u8, can: Access) -> Certificate {
    Delegation::new(id(iss), id(aud), id(sub), can).into()
}

fn build<I: IntoIterator<Item = Certificate>>(certs: I) -> MemoryKeyline {
    let mut g = MemoryKeyline::new();
    for c in certs {
        g.insert(cert(c));
    }
    g
}

/// Doc rooted at Owners (two admins); three roles supplied into Doc at
/// Edit/Read/Relay, each rooted at Owners, with `n` humans; two revocations.
fn realistic(n: u8) -> MemoryKeyline {
    let mut certs = vec![
        d(DOC, OWNERS, DOC, Access::Admin),
        d(OWNERS, FIRST_HUMAN, OWNERS, Access::Admin),
        d(OWNERS, FIRST_HUMAN + 1, OWNERS, Access::Admin),
    ];
    let mut next = FIRST_HUMAN + 2;
    for (role, level) in ROLES
        .iter()
        .zip([Access::Edit, Access::Read, Access::Relay])
    {
        certs.push(d(FIRST_HUMAN, *role, DOC, level));
        certs.push(d(*role, OWNERS, *role, Access::Admin));
        for _ in 0..n {
            certs.push(d(FIRST_HUMAN, next, *role, Access::Edit));
            next = next.wrapping_add(1);
        }
    }
    let mut g = build(certs);
    // Two cuts: one by an Owner (covers), one by a member (inert).
    let victim = Delegation::new(
        id(FIRST_HUMAN),
        id(FIRST_HUMAN + 3),
        id(ROLES[0]),
        Access::Edit,
    );
    g.insert(cert(Revocation::new(id(FIRST_HUMAN + 1), victim.digest())));
    g.insert(cert(Revocation::new(id(FIRST_HUMAN + 4), victim.digest())));
    g
}

/// Doc → role₁ → role₂ → … → roleₖ, each an Admin member of the previous, with
/// one human at the bottom.
fn club_ladder(k: u8) -> MemoryKeyline {
    let mut certs = vec![d(DOC, OWNERS, DOC, Access::Admin)];
    let mut prev = OWNERS;
    for i in 0..k {
        let role = FIRST_HUMAN + i;
        certs.push(d(role, prev, role, Access::Admin)); // role rooted at prev
        certs.push(d(prev, role, DOC, Access::Admin)); // and supplied into Doc
        prev = role;
    }
    certs.push(d(prev, LADDER_LEAF, prev, Access::Edit));
    build(certs)
}

/// An Owner is booted and then revokes `k` roster certificates; all share one
/// exclusion set.
fn revocation_spree(k: u8) -> MemoryKeyline {
    let mut g = realistic(k);
    let booted = Delegation::new(id(OWNERS), id(FIRST_HUMAN + 1), id(OWNERS), Access::Admin);
    g.insert(cert(Revocation::new(id(FIRST_HUMAN), booted.digest())));
    for i in 0..k {
        let target = Delegation::new(
            id(FIRST_HUMAN),
            id(FIRST_HUMAN + 2 + i),
            id(ROLES[0]),
            Access::Edit,
        );
        g.insert(cert(Revocation::new(id(FIRST_HUMAN + 1), target.digest())));
    }
    g
}

fn doc() -> Id {
    id(DOC)
}

#[divan::bench(args = [10, 30, 60])]
fn realistic_members(bencher: Bencher, n: u8) {
    bencher
        .with_inputs(|| realistic(n))
        .bench_refs(|g| g.members(doc()));
}

#[divan::bench(args = [10, 30, 60])]
fn realistic_effective_access(bencher: Bencher, n: u8) {
    bencher
        .with_inputs(|| realistic(n))
        .bench_refs(|g| g.effective_access(doc(), id(FIRST_HUMAN + 5)));
}

#[divan::bench(args = [10, 30, 60])]
fn realistic_insert(bencher: Bencher, n: u8) {
    bencher
        .with_inputs(|| {
            (
                realistic(n),
                cert(d(FIRST_HUMAN, LATE_JOINER, ROLES[1], Access::Read)),
            )
        })
        .bench_values(|(mut g, c)| g.insert(c));
}

#[divan::bench(args = [4, 8, 16, 32])]
fn club_ladder_members(bencher: Bencher, k: u8) {
    bencher
        .with_inputs(|| club_ladder(k))
        .bench_refs(|g| g.members(doc()));
}

#[divan::bench(args = [4, 8, 16, 32])]
fn revocation_spree_members(bencher: Bencher, k: u8) {
    bencher
        .with_inputs(|| revocation_spree(k))
        .bench_refs(|g| g.members(doc()));
}
