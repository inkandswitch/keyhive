//! Generators for small, mostly grounded certificate sets.
//!
//! Random 32-byte seeds give distinct keys with no relation to one another,
//! so every edge is ungrounded and evaluation never leaves the root. Instead
//! draw from a fixed pool of [`POOL`] deterministic identities, plant a root
//! edge for each subject, and wire the rest at random. Revocations name
//! delegations already in the set; a few are re-issued past a revocation so
//! `cites` collisions and heals both occur.

use crate::{
    power::Power, certificate::Certificate, delegation::Delegation, id::Id,
    revocation::Revocation, test_utils::id,
};
use alloc::vec::Vec;
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
pub struct CertSet<C> {
    pub certs: Vec<Certificate<C>>,
}

impl<C: Clone + Encode + Decode> CertSet<C> {
    pub fn delegations(&self) -> impl Iterator<Item = &Delegation> {
        self.certs.iter().filter_map(Certificate::as_delegation)
    }

    pub fn revocations(&self) -> impl Iterator<Item = &Revocation<C>> {
        self.certs.iter().filter_map(Certificate::as_revocation)
    }

    /// The same set with every revocation removed.
    pub fn without_revocations(&self) -> CertSet<C> {
        CertSet {
            certs: self
                .certs
                .iter()
                .filter(|c| c.as_delegation().is_some())
                .cloned()
                .collect(),
        }
    }

    /// The same set with one certificate removed.
    pub fn without(&self, index: usize) -> CertSet<C> {
        let mut certs = self.certs.clone();
        certs.remove(index);
        CertSet { certs }
    }

    /// Reorder by a permutation given as sort keys, one per certificate.
    pub fn permuted(&self, keys: &[u8]) -> CertSet<C> {
        let mut indexed: Vec<(u8, &Certificate<C>)> = self
            .certs
            .iter()
            .enumerate()
            .map(|(i, c)| (keys.get(i).copied().unwrap_or(0), c))
            .collect();
        indexed.sort_by_key(|(k, _)| *k);
        CertSet {
            certs: indexed.into_iter().map(|(_, c)| c.clone()).collect(),
        }
    }
}

fn pick_id(u: &mut Unstructured<'_>) -> Result<Id> {
    Ok(id(u.int_in_range(1..=POOL)?))
}

impl<'a, C: Arbitrary<'a> + Clone + Encode + Decode> Arbitrary<'a> for CertSet<C> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut certs: Vec<Certificate<C>> = Vec::new();

        // Root edges: each subject grounds itself to some node.
        let subjects = u.int_in_range(1..=3)?;
        for s in 1..=subjects {
            let audience = pick_id(u)?;
            certs.push(Delegation::new(id(s), audience, id(s), Power::Admin).into());
        }

        // Free-form delegations over any node in the pool as subject, so some
        // land on roles (composition) and some are ungrounded.
        for _ in 0..u.int_in_range(0..=10)? {
            let d = Delegation::new(pick_id(u)?, pick_id(u)?, pick_id(u)?, u.arbitrary()?);
            certs.push(d.into());
        }

        // About half the time, plant the shape where clamping bites: a role
        // `m` supplied into `s`; `k` administers `m`; `e` is a member of `m`
        // and also holds an independent, weaker grant over `s`; `e` grants `f`;
        // `k` revokes that grant. Random wiring produces this rarely. The
        // levels are chosen so gating and clamping always disagree: the role
        // route is strictly better than the independent one, the supply is
        // below Admin (else `s` is in `k`'s reach and the grant is simply dead),
        // and the grant asks for at least the role level.
        if u.arbitrary::<bool>()? {
            let s_n = u.int_in_range(1..=subjects)?;
            let s = id(s_n);
            // Four distinct identities other than `s`; a collision would
            // collapse the shape into something else.
            let mut rest: Vec<u8> = (1..=POOL).filter(|n| *n != s_n).collect();
            let mut pick_distinct = |u: &mut Unstructured<'a>| -> Result<Id> {
                let i = u.choose_index(rest.len())?;
                Ok(id(rest.swap_remove(i)))
            };
            let (m, k, e, f) = (
                pick_distinct(u)?,
                pick_distinct(u)?,
                pick_distinct(u)?,
                pick_distinct(u)?,
            );
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
            certs.extend::<[Certificate<C>; 6]>([
                Delegation::new(s, m, s, via_role).into(),
                Delegation::new(m, k, m, Power::Admin).into(),
                Delegation::new(k, e, m, Power::Admin).into(),
                Delegation::new(s, e, s, independent).into(),
                grant.into(),
                Revocation::new(k, grant.digest()).into(),
            ]);
        }

        // Revocations naming delegations already present.
        for _ in 0..u.int_in_range(0..=4)? {
            let dels: Vec<Delegation> = certs
                .iter()
                .filter_map(Certificate::as_delegation)
                .copied()
                .collect();
            let target = dels[u.choose_index(dels.len())?];
            // A third of revocations are by a party to the target (retraction or
            // renunciation), which random revokers rarely produce.
            let revoker = match u.int_in_range(0..=2)? {
                0 => target.issuer,
                1 => target.audience,
                _ => pick_id(u)?,
            };
            certs.push(Revocation::new(revoker, target.digest()).into());
        }

        // Re-issues past a revocation, so heals and `cites` collisions happen.
        for _ in 0..u.int_in_range(0..=2)? {
            let revs: Vec<Revocation<C>> = certs
                .iter()
                .filter_map(Certificate::as_revocation)
                .cloned()
                .collect();
            if revs.is_empty() {
                break;
            }
            let rev = revs[u.choose_index(revs.len())?].clone();
            let Some(target) = certs
                .iter()
                .filter_map(Certificate::as_delegation)
                .find(|d| d.digest() == rev.revokes)
                .copied()
            else {
                continue;
            };
            certs.push(target.reissue(rev.digest()).into());
        }

        Ok(CertSet { certs })
    }
}
