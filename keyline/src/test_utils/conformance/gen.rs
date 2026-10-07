//! Generators for small, mostly grounded certificate sets.
//!
//! Random 32-byte seeds give distinct keys with no relation to one another,
//! so every edge is ungrounded and evaluation never leaves the root. Instead
//! draw from a fixed pool of [`POOL`] deterministic identities, plant a root
//! edge for each subject (at Admin or Edit), and wire the rest at random.
//! Revocations mostly name delegations already in the set, and occasionally
//! one that is absent; a few delegations are re-issued past a revocation, and
//! some re-issues are revoked again. Most sets also get one of four shapes
//! that random wiring rarely produces: a clamped delegation, two covered
//! delegations on each other's avoiding derivation, a three-deep role chain
//! (sometimes with a revocation through its composed reach), or a clamped
//! delegation whose subject is a role.

use crate::{
    delegation::Delegation,
    id::Id,
    power::Power,
    revocation::Revocation,
    test_utils::{id, Statement},
};
use alloc::{collections::BTreeMap, vec::Vec};
use arbitrary::{Arbitrary, Result, Unstructured};
use keyhive_codec::traits::{Decode, Encode};

/// Number of identities in the pool; [`ids`] yields them.
pub const POOL: u8 = 8;

/// Every identity a generated set may mention.
pub fn ids() -> impl Iterator<Item = Id> {
    (1..=POOL).map(id)
}

/// A generated certificate set. Order is generation order; laws that care
/// about order permute it themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSet<W> {
    pub certs: Vec<Statement<W>>,
}

impl<W: Clone + Encode + Decode> CertSet<W> {
    pub fn delegations(&self) -> impl Iterator<Item = &Delegation> {
        self.certs.iter().filter_map(Statement::as_delegation)
    }

    pub fn revocations(&self) -> impl Iterator<Item = &Revocation<W>> {
        self.certs.iter().filter_map(Statement::as_revocation)
    }

    /// The same set with every revocation removed.
    pub fn without_revocations(&self) -> CertSet<W> {
        CertSet {
            certs: self
                .certs
                .iter()
                .filter(|c| c.as_delegation().is_some())
                .cloned()
                .collect(),
        }
    }

    /// The same set in reverse order.
    pub fn reversed(&self) -> CertSet<W> {
        CertSet {
            certs: self.certs.iter().rev().cloned().collect(),
        }
    }

    /// The same set with every `retain` map emptied.
    pub fn without_watermarks(&self) -> CertSet<W> {
        CertSet {
            certs: self
                .certs
                .iter()
                .map(|c| match c {
                    Statement::Revocation(r) => Revocation::new(r.issuer, r.revoke).into(),
                    Statement::Delegation(d) => (*d).into(),
                })
                .collect(),
        }
    }

    /// The same set with one certificate removed.
    pub fn without(&self, index: usize) -> CertSet<W> {
        let mut certs = self.certs.clone();
        certs.remove(index);
        CertSet { certs }
    }

    /// The same set in an order drawn from `seed`: a Fisher–Yates shuffle
    /// over a SplitMix64 stream: an unbiased shuffle for the seed.
    pub fn shuffled(&self, seed: u64) -> CertSet<W> {
        let mut state = seed;
        let mut next = move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut certs = self.certs.clone();
        for i in (1..certs.len()).rev() {
            let bound = u64::try_from(i + 1).expect("set sizes fit in u64");
            let j = usize::try_from(next() % bound).expect("j <= i");
            certs.swap(i, j);
        }
        CertSet { certs }
    }
}

fn pick_id(u: &mut Unstructured<'_>) -> Result<Id> {
    Ok(id(u.int_in_range(1..=POOL)?))
}

/// `N` distinct pool identities, none of them in `not`. A collision would
/// collapse a planted shape into something else.
fn distinct<const N: usize>(u: &mut Unstructured<'_>, not: &[u8]) -> Result<[Id; N]> {
    let mut rest: Vec<u8> = (1..=POOL).filter(|n| !not.contains(n)).collect();
    let mut out = [id(1); N];
    for slot in &mut out {
        *slot = id(rest.swap_remove(u.choose_index(rest.len())?));
    }
    Ok(out)
}

fn pick_power(u: &mut Unstructured<'_>) -> Result<Power> {
    Ok(Power::ALL[u.choose_index(Power::ALL.len())?])
}

/// Retention watermarks over pool subjects, for [`Revocation::retain`].
///
/// Often empty, so both codec paths occur. Evaluation must ignore whatever
/// lands here, and the naive oracle cannot read it at all, so running the
/// oracle laws with a variable-length `W` checks that the evaluator ignores
/// it too.
fn watermarks<'a, W: Arbitrary<'a>>(u: &mut Unstructured<'a>) -> Result<BTreeMap<Id, W>> {
    let mut watermarks = BTreeMap::new();
    for _ in 0..u.int_in_range(0..=2)? {
        watermarks.insert(pick_id(u)?, u.arbitrary()?);
    }

    Ok(watermarks)
}

impl<'a, W: Arbitrary<'a> + Clone + Encode + Decode> Arbitrary<'a> for CertSet<W> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut certs: Vec<Statement<W>> = Vec::new();

        // Root edges: each subject grounds itself to some node, at Admin or,
        // so that nobody holds Admin over the subject, at Edit.
        let subjects = u.int_in_range(1..=3)?;
        let mut root_audience: Vec<u8> = Vec::new();
        for s in 1..=subjects {
            let audience = u.int_in_range(1..=POOL)?;
            root_audience.push(audience);
            let rooting = if u.arbitrary()? {
                Power::Admin
            } else {
                Power::Edit
            };
            certs.push(Delegation::new(id(s), id(audience), id(s), rooting).into());
        }
        // Planted shapes avoid their subject and its root audience, whose
        // independent standing would otherwise mask what the shape tests.
        let clear_of = |s_n: u8| [s_n, root_audience[usize::from(s_n - 1)]];

        // Free-form delegations over any node in the pool as subject, so some
        // land on roles (composition) and some are ungrounded.
        for _ in 0..u.int_in_range(0..=10)? {
            let d = Delegation::new(pick_id(u)?, pick_id(u)?, pick_id(u)?, u.arbitrary()?);
            certs.push(d.into());
        }

        // At most one planted shape per set keeps sets small: evaluation cost
        // grows faster than set size, and the laws evaluate many times per set.
        let shape = u.int_in_range(0..=4)?;

        // Shape 1, clamping: a role `m` supplied into `s`; `k` administers
        // `m`; `e` is a member of `m` and also holds an independent, weaker
        // delegation over `s`; `e` delegates to `f`; `k` revokes that
        // delegation. Random wiring produces this rarely. The levels are chosen
        // so gating and clamping disagree unless another edge masks them: the
        // role route is strictly better than the independent one, the supply
        // is below Admin (else `s` is in `k`'s reach and the delegation is
        // dead), and the delegation asks for at least the role level.
        if shape == 1 {
            let s_n = u.int_in_range(1..=subjects)?;
            let s = id(s_n);
            let [m, k, e, f] = distinct(u, &clear_of(s_n))?;
            let via_role = if u.arbitrary()? {
                Power::Edit
            } else {
                Power::Read
            };
            let independent = if via_role == Power::Edit && u.arbitrary()? {
                Power::Read
            } else {
                Power::Relay
            };
            let grant = Delegation::new(e, f, s, Power::Admin);
            certs.extend::<[Statement<W>; 6]>([
                Delegation::new(s, m, s, via_role).into(),
                Delegation::new(m, k, m, Power::Admin).into(),
                Delegation::new(k, e, m, Power::Admin).into(),
                Delegation::new(s, e, s, independent).into(),
                grant.into(),
                Revocation::new(k, grant.digest()).into(),
            ]);
        }

        // Shape 2, two chained clamps: `e` and `f` each stand through their
        // own role, `e` also holds a weaker direct delegation, and each
        // delegates to the other (and `f` to `g`), each revoked by its issuer's
        // role. Each delegation lies on the other's avoiding derivation, so a
        // cap computed as a greatest fixed point lets them certify each other.
        if shape == 2 {
            let s_n = u.int_in_range(1..=subjects)?;
            let s = id(s_n);
            let [m1, e, m2, f, g] = distinct(u, &clear_of(s_n))?;
            let (h1, h2, h3) = (
                Delegation::new(e, f, s, Power::Admin),
                Delegation::new(f, e, s, Power::Admin),
                Delegation::new(f, g, s, Power::Admin),
            );
            certs.extend::<[Statement<W>; 11]>([
                Delegation::new(s, e, s, Power::Read).into(),
                Delegation::new(s, m1, s, Power::Edit).into(),
                Delegation::new(m1, e, m1, Power::Admin).into(),
                Delegation::new(s, m2, s, Power::Edit).into(),
                Delegation::new(m2, f, m2, Power::Admin).into(),
                h1.into(),
                h2.into(),
                h3.into(),
                Revocation::new(m1, h1.digest()).into(),
                Revocation::new(m2, h2.digest()).into(),
                Revocation::new(m2, h3.digest()).into(),
            ]);
        }

        // Shape 3, a role chain three deep: `r1` is a member of `s`, `r2` of
        // `r1`, `r3` of `r2`, and `p` of `r3`, at random levels. Half the
        // time every hop is Admin, so `s` is in `p`'s reach only through three
        // compositions, and `p` revokes `s`'s root edge.
        if shape == 3 {
            let s_n = u.int_in_range(1..=subjects)?;
            let s = id(s_n);
            let [r1, r2, r3, p] = distinct(u, &clear_of(s_n))?;
            let composed = u.arbitrary::<bool>()?;
            let hop = |u: &mut Unstructured<'a>| {
                if composed {
                    Ok(Power::Admin)
                } else {
                    pick_power(u)
                }
            };
            certs.extend::<[Statement<W>; 4]>([
                Delegation::new(s, r1, s, hop(u)?).into(),
                Delegation::new(r1, r2, r1, hop(u)?).into(),
                Delegation::new(r2, r3, r2, hop(u)?).into(),
                Delegation::new(r3, p, r3, hop(u)?).into(),
            ]);
            if composed {
                let root = certs[usize::from(s_n - 1)]
                    .as_delegation()
                    .expect("the first statements are the root edges")
                    .digest();
                certs.push(Revocation::new(p, root).into());
            }
        }

        // Shape 4, shape 1 inside a role: `g` is supplied into `s`, and inside
        // `g` a member `e` of role `m` (administered by `k`) also holds a weaker
        // direct membership in `g`, delegates to `f` over `g`, and `k` revokes
        // that. `f`'s level over `g`, and so over `s`, is clamped to the direct
        // membership, in a subject that is not the one queried at the root.
        if shape == 4 {
            let s_n = u.int_in_range(1..=subjects)?;
            let s = id(s_n);
            let [g, m, k, e, f] = distinct(u, &clear_of(s_n))?;
            let grant = Delegation::new(e, f, g, Power::Admin);
            certs.extend::<[Statement<W>; 7]>([
                Delegation::new(s, g, s, Power::Edit).into(),
                Delegation::new(g, m, g, Power::Edit).into(),
                Delegation::new(m, k, m, Power::Admin).into(),
                Delegation::new(k, e, m, Power::Admin).into(),
                Delegation::new(g, e, g, Power::Read).into(),
                grant.into(),
                Revocation::new(k, grant.digest()).into(),
            ]);
        }

        // Occasionally, a revocation of a delegation that is not in the set.
        if u.ratio(1, 4)? {
            let absent = Delegation::new(pick_id(u)?, pick_id(u)?, pick_id(u)?, pick_power(u)?);
            certs.push(Revocation::new(pick_id(u)?, absent.digest()).into());
        }

        // Revocations naming delegations already present.
        for _ in 0..u.int_in_range(0..=4)? {
            let dels: Vec<Delegation> = certs
                .iter()
                .filter_map(Statement::as_delegation)
                .copied()
                .collect();
            let target = dels[u.choose_index(dels.len())?];
            // A third of revocations are by the target's issuer and a third by
            // its audience, which random issuers rarely produce.
            let issuer = match u.int_in_range(0..=2)? {
                0 => target.issuer,
                1 => target.audience,
                _ => pick_id(u)?,
            };
            certs.push(
                Revocation::new(issuer, target.digest())
                    .retaining(watermarks(u)?)
                    .into(),
            );
        }

        // Re-issues past a revocation, so heals and `citation` collisions
        // happen, and sometimes a revocation of the re-issue.
        let mut reissues: Vec<Delegation> = Vec::new();
        for _ in 0..u.int_in_range(0..=2)? {
            let revocations: Vec<Revocation<W>> = certs
                .iter()
                .filter_map(Statement::as_revocation)
                .cloned()
                .collect();
            if revocations.is_empty() {
                break;
            }
            let revocation = revocations[u.choose_index(revocations.len())?].clone();
            let Some(target) = certs
                .iter()
                .filter_map(Statement::as_delegation)
                .find(|d| d.digest() == revocation.revoke)
                .copied()
            else {
                continue;
            };
            let reissue = target.reissue(revocation.digest());
            reissues.push(reissue);
            certs.push(reissue.into());
        }
        if !reissues.is_empty() && u.arbitrary()? {
            let target = reissues[u.choose_index(reissues.len())?];
            certs.push(Revocation::new(pick_id(u)?, target.digest()).into());
        }

        Ok(CertSet { certs })
    }
}
