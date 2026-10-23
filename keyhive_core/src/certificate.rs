//! Keyline certificates in `keyhive_core`: signing root edges, finding the
//! routes certificates open, and the errors membership writes share.

use ed25519_dalek::{Signature, VerifyingKey};
use future_form::FutureForm;
use keyhive_codec::{error::DecodeError, traits::Decode};
use keyhive_crypto::{
    identifier::Identifier,
    signed::SigningError,
    signer::sync_signer::SyncSignerBasic,
    verifiable::Verifiable,
    verified::{SignError, Signed, Verified},
};
use keyline::{
    certificate::Certificate, contract::Keyline, delegation::Delegation, power::Power,
    revocation::Revocation,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use core::marker::PhantomData;

/// Signs the root edges of a freshly created subject: an `Admin` delegation
/// from the subject's own key to each creator.
///
/// `signer` is the subject's ephemeral key, which is discarded once the
/// subject exists, so these are the only certificates it ever signs. They
/// never die by cascade: nothing above the subject can lose standing.
pub(crate) fn root_edges<I: IntoIterator<Item = Identifier>>(
    signer: &dyn SyncSignerBasic,
    subject: Identifier,
    creators: I,
) -> Result<Vec<Verified<Delegation>>, CertificateError> {
    let signer = Ephemeral { signer, subject };
    creators
        .into_iter()
        .map(|creator| {
            let edge = Delegation::new(creator, subject, Power::Admin);
            Ok(Verified::sign_sync(&edge, &signer)?)
        })
        .collect()
}

/// Whether `who` has a route to `doc` through `delegation`, issued by
/// `issuer`, in the positive graph.
///
/// The delegation must be grounded (its issuer stands over its subject), and
/// its subject must be `doc` or stand over it. Its audience is then reached
/// at the delegation's subject. A node reached at `X` holds power over `X`,
/// and so over every subject `X` stands over; it (or any of its members)
/// carries the route along a delegation it issues about `Y` when `Y` is `X`
/// or a subject `X` stands over, between `delegation`'s subject and `doc`,
/// reaching that delegation's audience at `Y`. `who` has a route when it is
/// reached, or is a member of a reached node.
///
/// Monotone: more certificates only add routes. This covers both cascades a
/// revocation causes: members of the revoked delegation's audience, and
/// audiences of delegations its audience issued, on any subject the route
/// passes through.
pub(crate) async fn route_through<F: FutureForm, K: Keyline<F>>(
    keyline: &K,
    doc: Identifier,
    issuer: Identifier,
    delegation: &Delegation,
    who: Identifier,
) -> Result<bool, KeylineStorageError<K::Error>>
where
    K::Error: 'static,
{
    let mut standing = Standing::new(keyline);
    let closure = closure_delegations(keyline, doc).await?;
    route_through_with(&mut standing, &closure, doc, issuer, delegation, who).await
}

/// Every delegation in `doc`'s closure, with its issuer.
async fn closure_delegations<F: FutureForm, K: Keyline<F>>(
    keyline: &K,
    doc: Identifier,
) -> Result<Vec<(Identifier, Delegation)>, KeylineStorageError<K::Error>>
where
    K::Error: 'static,
{
    keyline
        .closure(doc)
        .await
        .map_err(KeylineStorageError::new)?
        .value
        .iter()
        .filter_map(|cert| match cert {
            Certificate::Delegation(signed) => Some(decode_stored(signed)),
            Certificate::Revocation(_) => None,
        })
        .collect()
}

/// [`route_through`] with standing remembered across calls and `doc`'s
/// closure delegations already read: for a caller that asks many routes of
/// one store.
async fn route_through_with<F: FutureForm, K: Keyline<F>>(
    standing: &mut Standing<'_, F, K>,
    closure: &[(Identifier, Delegation)],
    doc: Identifier,
    issuer: Identifier,
    delegation: &Delegation,
    who: Identifier,
) -> Result<bool, KeylineStorageError<K::Error>>
where
    K::Error: 'static,
{
    let subject = delegation.subject;
    if !standing.over(subject, issuer).await? || !standing.over(doc, subject).await? {
        return Ok(false);
    }

    // Keep the delegations about subjects between `subject` and `doc`: those
    // the route can pass through. `closure(doc)` holds at least those; a
    // store may return more, so both bounds are checked here.
    let mut edges: Vec<&(Identifier, Delegation)> = Vec::new();
    for edge in closure {
        let d = &edge.1;
        if standing.over(d.subject, subject).await? && standing.over(doc, d.subject).await? {
            edges.push(edge);
        }
    }

    // (node, the subject it is reached at)
    let mut reached: Vec<(Identifier, Identifier)> = vec![(delegation.audience, subject)];
    let mut grew = true;
    while grew {
        grew = false;
        for (edge_issuer, edge) in edges.iter().copied() {
            if reached.contains(&(edge.audience, edge.subject)) {
                continue;
            }
            let mut carried = false;
            for (node, level) in reached.clone() {
                if (node == *edge_issuer || standing.over(node, *edge_issuer).await?)
                    && standing.over(edge.subject, level).await?
                {
                    carried = true;
                    break;
                }
            }
            if carried {
                reached.push((edge.audience, edge.subject));
                grew = true;
            }
        }
    }

    for (node, _) in reached {
        if node == who || standing.over(node, who).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What a principal with positive but no effective standing over `subject`
/// is sent about it: the delegations on its former routes, the revocations of
/// those delegations, and the delegations on each such revoker's routes to
/// `subject`, which show that its revocation covers. Enough for a store
/// holding only these to agree that `audience` once stood over `subject` and
/// no longer does, and nothing about members it never reached.
pub(crate) async fn explanation<F: FutureForm, K: Keyline<F>>(
    keyline: &K,
    subject: Identifier,
    audience: Identifier,
) -> Result<Vec<Certificate<K::RetentionWatermark>>, KeylineStorageError<K::Error>>
where
    K::Error: 'static,
{
    let mut delegations = Vec::new();
    let mut revocations = Vec::new();
    let closure = keyline
        .closure(subject)
        .await
        .map_err(KeylineStorageError::new)?
        .value;
    for cert in closure {
        match &cert {
            Certificate::Delegation(signed) => {
                let (issuer, d) = decode_stored(signed)?;
                delegations.push((issuer, d, signed.digest(), cert));
            }
            Certificate::Revocation(signed) => {
                let (issuer, r): (Identifier, Revocation<K::RetentionWatermark>) =
                    decode_stored(signed)?;
                revocations.push((issuer, r.revoke, cert));
            }
        }
    }

    // One store, one closure: every route below shares the standing it asks
    // and the delegations already decoded.
    let mut standing = Standing::new(keyline);
    let closure: Vec<(Identifier, Delegation)> = delegations
        .iter()
        .map(|(issuer, d, _, _)| (*issuer, *d))
        .collect();

    let mut kept = BTreeMap::new();
    let mut routes = BTreeSet::new();
    for (issuer, d, digest, cert) in &delegations {
        if route_through_with(&mut standing, &closure, subject, *issuer, d, audience).await? {
            routes.insert(*digest);
            kept.insert(cert.id(), cert.clone());
        }
    }
    let mut revokers = BTreeSet::new();
    for (issuer, revoked, cert) in &revocations {
        if routes.contains(revoked) {
            revokers.insert(*issuer);
            kept.insert(cert.id(), cert.clone());
        }
    }
    for revoker in revokers {
        for (issuer, d, _, cert) in &delegations {
            if !kept.contains_key(&cert.id())
                && route_through_with(&mut standing, &closure, subject, *issuer, d, revoker).await?
            {
                kept.insert(cert.id(), cert.clone());
            }
        }
    }
    Ok(kept.into_values().collect())
}

/// Positive standing, asked of a store and remembered: whether `audience` has
/// power over `subject` in the positive graph. Every subject stands over
/// itself.
struct Standing<'a, F: FutureForm, K: Keyline<F>> {
    keyline: &'a K,
    known: BTreeMap<(Identifier, Identifier), bool>,
    _form: PhantomData<F>,
}

impl<'a, F: FutureForm, K: Keyline<F>> Standing<'a, F, K>
where
    K::Error: 'static,
{
    fn new(keyline: &'a K) -> Self {
        Standing {
            keyline,
            known: BTreeMap::new(),
            _form: PhantomData,
        }
    }

    async fn over(
        &mut self,
        subject: Identifier,
        audience: Identifier,
    ) -> Result<bool, KeylineStorageError<K::Error>> {
        if subject == audience {
            return Ok(true);
        }
        if let Some(known) = self.known.get(&(subject, audience)) {
            return Ok(*known);
        }
        let holds = self
            .keyline
            .positive_power(subject, audience)
            .await
            .map_err(KeylineStorageError::new)?
            .value
            .is_some();
        self.known.insert((subject, audience), holds);
        Ok(holds)
    }
}

/// An ephemeral signer paired with its key, which becomes the issuer of each
/// certificate it signs.
struct Ephemeral<'a> {
    signer: &'a dyn SyncSignerBasic,
    subject: Identifier,
}

impl SyncSignerBasic for Ephemeral<'_> {
    fn try_sign_bytes_sync_basic(&self, bytes: &[u8]) -> Result<Signature, SigningError> {
        self.signer.try_sign_bytes_sync_basic(bytes)
    }
}

impl Verifiable for Ephemeral<'_> {
    fn verifying_key(&self) -> VerifyingKey {
        self.subject.verifying_key()
    }
}

/// Why a Keyline certificate could not be made.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// Signing failed, or the signature did not verify.
    #[error(transparent)]
    Sign(#[from] SignError),
}

/// The issuer and payload of a certificate read from a store. A store holds
/// only verified certificates, whose encoding is canonical; bytes that do not
/// decode mean the store returned something else, and are
/// [`KeylineStorageError::Corrupt`].
pub fn decode_stored<T: Decode, E: core::error::Error + 'static>(
    signed: &Signed<T>,
) -> Result<(Identifier, T), KeylineStorageError<E>> {
    let payload = signed
        .encoded()
        .decode()
        .map_err(KeylineStorageError::Corrupt)?;
    Ok((signed.issuer(), payload))
}

/// The `Keyline` store failed: its backend reported an error, or it returned
/// a certificate that does not decode.
///
/// Neither is a bug in this crate. A persistent backend's bytes come from
/// disk or the network, where they can be corrupted, so they are reported
/// rather than trusted. A backend that cannot fail, such as
/// `keyline_memory`'s, has `E = Infallible`, and is `Corrupt` only through a
/// bug of its own.
#[derive(Debug, Error)]
pub enum KeylineStorageError<E: core::error::Error + 'static> {
    /// The backend's own error ([`Keyline::Error`]).
    #[error("the Keyline store failed")]
    Backend(#[source] E),

    /// A certificate read from the store does not decode: the store returned
    /// bytes other than the verified certificate it was given. Retrying reads
    /// the same bytes; the store needs repairing or rebuilding.
    #[error("the Keyline store returned a certificate that does not decode")]
    Corrupt(#[source] DecodeError),
}

impl<E: core::error::Error + 'static> KeylineStorageError<E> {
    /// Wrap a backend's error.
    pub fn new(error: E) -> Self {
        KeylineStorageError::Backend(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use future_form::Sendable;
    use keyhive_crypto::digest::Digest;
    use keyline::{
        certificate::{CertificateId, VerifiedCertificate},
        contract::{CertificateSet, Query, Version},
        revocation::RevocationId,
    };
    use keyline_memory::MemoryKeyline;
    use tokio::runtime::Builder;

    /// Root edges are signed by the subject, name each creator as an `Admin`
    /// audience, and verify.
    #[test]
    fn root_edges_are_admin_from_the_subject() {
        let subject = SigningKey::from_bytes(&[1; 32]);
        let creators: Vec<Identifier> = [[2; 32], [3; 32]]
            .map(|seed| Identifier::from(&SigningKey::from_bytes(&seed)))
            .into();
        let edges = root_edges(&subject, Identifier::from(&subject), creators.clone())
            .expect("valid keys sign");

        let subject_id = Identifier::from(&subject);
        assert_eq!(edges.len(), 2);
        for (edge, creator) in edges.iter().zip(&creators) {
            let d = edge.payload();
            assert_eq!(
                (edge.issuer(), d.subject, d.power),
                (subject_id, subject_id, Power::Admin)
            );
            assert_eq!(d.audience, *creator);
            let reverified = (**edge.signed()).clone().verify().expect("verifies");
            assert_eq!(reverified.digest(), edge.digest());
        }
    }
    /// `route_through` against Keyline's own evaluator, as an independent
    /// oracle. It is bounded on both sides:
    ///
    /// - _Necessity implies a route._ If dropping the delegation lowers `who`'s
    ///   positive power over `doc`, `who` must have a route through it.
    /// - _A route implies standing._ If `who` has a route, it has positive
    ///   power over `doc`.
    ///
    /// The converse of the first does not hold: `who` may keep its power by
    /// another route, so the property does not ask for it. It also checks that
    /// `route_through` is monotone, which CGKA authorization relies on.
    #[test]
    fn route_through_lies_between_necessity_and_standing() {
        use keyline::test_utils::{
            assume_verified,
            conformance::gen::{CertSet, POOL},
            id, Issued,
        };

        let runtime = Builder::new_current_thread()
            .build()
            .expect("a runtime starts");
        bolero::check!()
            .with_arbitrary::<(CertSet<u64>, u8, u8, u8)>()
            .for_each(|(set, pick, doc, who)| {
                let delegations: Vec<Issued<Delegation>> = set.delegations().copied().collect();
                let Some(&through) = delegations.get(usize::from(*pick) % delegations.len().max(1))
                else {
                    return;
                };
                let doc = id(1 + doc % POOL);
                let who = id(1 + who % POOL);
                runtime.block_on(async {
                    let store = |without: Option<Issued<Delegation>>| async move {
                        let keyline = MemoryKeyline::<u64>::new();
                        let certs = set
                            .certs
                            .iter()
                            .filter(|c| without.is_none() || c.as_delegation() != without.as_ref())
                            .cloned()
                            .map(assume_verified)
                            .collect();
                        Keyline::<Sendable>::insert(&keyline, certs)
                            .await
                            .expect("the memory store does not fail");
                        keyline
                    };
                    let full = store(None).await;
                    let without = store(Some(through)).await;
                    let with_d = Keyline::<Sendable>::positive_power(&full, doc, who)
                        .await
                        .expect("the memory store does not fail")
                        .value;
                    let without_d = Keyline::<Sendable>::positive_power(&without, doc, who)
                        .await
                        .expect("the memory store does not fail")
                        .value;
                    let routed = route_through::<Sendable, _>(&full, doc, through.issuer, &through.payload, who)
                        .await
                        .expect("the memory store does not fail");

                    if with_d > without_d {
                        assert!(
                            routed,
                            "{who} needs {through:?} for its standing over {doc}, \
                             but route_through finds no route through it"
                        );
                    }
                    if routed {
                        assert!(
                            with_d.is_some(),
                            "route_through finds a route for {who} to {doc} through {through:?} with no standing"
                        );
                    }

                    // Monotone: a route found among the first half of the
                    // certificates is still there with all of them.
                    let prefix = {
                        let keyline = MemoryKeyline::<u64>::new();
                        let half = set.certs.len() / 2;
                        let certs = set.certs[..half]
                            .iter()
                            .cloned()
                            .map(assume_verified)
                            .collect();
                        Keyline::<Sendable>::insert(&keyline, certs)
                            .await
                            .expect("the memory store does not fail");
                        keyline
                    };
                    if route_through::<Sendable, _>(&prefix, doc, through.issuer, &through.payload, who)
                        .await
                        .expect("the memory store does not fail")
                    {
                        assert!(routed, "a route among fewer certificates is lost among more");
                    }
                });
            });
    }
    /// A route stays between the delegation's subject and the document. Here
    /// the document is itself a member of `outside`, so it stands over
    /// `outside`, but `outside` does not stand over it: mallory, a member of
    /// `outside` only, has no route to the document through its grant to
    /// `readers`.
    #[test]
    fn a_route_does_not_pass_through_a_subject_the_document_stands_over() {
        use keyline::test_utils::{assume_verified, delegation, id};

        let (alice, mallory, doc, readers, outside) = (id(1), id(2), id(3), id(4), id(5));
        let grant = delegation(alice, readers, doc, Power::Read);
        let certs = [
            delegation(doc, alice, doc, Power::Admin),
            delegation(readers, alice, readers, Power::Admin),
            delegation(outside, alice, outside, Power::Admin),
            grant,
            delegation(alice, doc, outside, Power::Read),
            delegation(alice, mallory, outside, Power::Read),
        ];
        let runtime = Builder::new_current_thread()
            .build()
            .expect("a runtime starts");
        runtime.block_on(async {
            let keyline = memory_store(certs.into_iter().map(assume_verified).collect()).await;
            let standing = Keyline::<Sendable>::positive_power(&keyline, doc, mallory)
                .await
                .expect("the memory store does not fail")
                .value;
            assert_eq!(
                standing, None,
                "precondition: mallory has no standing over the document"
            );
            let routed =
                route_through::<Sendable, _>(&keyline, doc, grant.issuer, &grant.payload, mallory)
                    .await
                    .expect("the memory store does not fail");
            assert!(!routed, "mallory is reached only at `outside`");

            // The same with a store whose closure is every certificate it
            // holds: still sufficient, but not exact.
            let wide = WideClosure(keyline);
            let routed =
                route_through::<Sendable, _>(&wide, doc, grant.issuer, &grant.payload, mallory)
                    .await
                    .expect("the memory store does not fail");
            assert!(!routed, "a wider closure adds no route");
        });
    }

    /// A delegation issued by a member of a reached group carries the route:
    /// carol, admitted by bob, a member of `group`, reaches the document only
    /// through alice's grant to `group`.
    #[test]
    fn a_member_of_a_reached_group_carries_the_route() {
        use keyline::test_utils::{assume_verified, delegation, id};

        let (alice, bob, carol, doc, group) = (id(1), id(2), id(3), id(4), id(5));
        let grant = delegation(alice, group, doc, Power::Admin);
        let certs = [
            delegation(doc, alice, doc, Power::Admin),
            delegation(group, bob, group, Power::Admin),
            grant,
            delegation(bob, carol, doc, Power::Read),
        ];
        let runtime = Builder::new_current_thread()
            .build()
            .expect("a runtime starts");
        runtime.block_on(async {
            let keyline = memory_store(certs.into_iter().map(assume_verified).collect()).await;
            let routed =
                route_through::<Sendable, _>(&keyline, doc, grant.issuer, &grant.payload, carol)
                    .await
                    .expect("the memory store does not fail");
            assert!(
                routed,
                "carol's route passes through the grant to the group"
            );
        });
    }

    /// Bytes a store returns that do not decode are a storage error the
    /// caller sees, not a panic: a persistent backend's bytes can be corrupt.
    #[test]
    fn a_stored_certificate_that_does_not_decode_is_reported() {
        use keyhive_codec::encoded::Encoded;
        use keyline::test_utils::id;

        let garbage: Signed<Delegation> = Signed::new(
            id(1),
            Encoded::from_bytes_unchecked(vec![0xff; 3]),
            Signature::from_bytes(&[0; 64]),
        );
        let result = decode_stored::<Delegation, std::convert::Infallible>(&garbage);
        assert!(
            matches!(result, Err(KeylineStorageError::Corrupt(_))),
            "{result:?}"
        );
    }

    /// `MemoryKeyline`, except that `closure` returns every certificate:
    /// what `Keyline::closure` allows, more than what it needs.
    struct WideClosure(MemoryKeyline<u64>);

    impl Keyline<Sendable> for WideClosure {
        type RetentionWatermark = u64;
        type Error = <MemoryKeyline<u64> as Keyline<Sendable>>::Error;

        fn version(&self) -> <Sendable as FutureForm>::Future<'_, Result<Version, Self::Error>> {
            Keyline::<Sendable>::version(&self.0)
        }

        fn insert(
            &self,
            batch: Vec<VerifiedCertificate<u64>>,
        ) -> <Sendable as FutureForm>::Future<'_, Result<Version, Self::Error>> {
            Keyline::<Sendable>::insert(&self.0, batch)
        }

        fn contains(&self, cert: CertificateId) -> Query<'_, Sendable, bool, Self::Error> {
            Keyline::<Sendable>::contains(&self.0, cert)
        }

        fn get(
            &self,
            cert: CertificateId,
        ) -> Query<'_, Sendable, Option<Certificate<u64>>, Self::Error> {
            Keyline::<Sendable>::get(&self.0, cert)
        }

        fn certificates(&self) -> Query<'_, Sendable, Vec<Certificate<u64>>, Self::Error> {
            Keyline::<Sendable>::certificates(&self.0)
        }

        fn revocations_of(
            &self,
            delegation: Digest<Delegation>,
        ) -> Query<'_, Sendable, BTreeSet<Digest<RevocationId>>, Self::Error> {
            Keyline::<Sendable>::revocations_of(&self.0, delegation)
        }

        fn delegations_to(
            &self,
            subject: Identifier,
            audience: Identifier,
        ) -> Query<'_, Sendable, BTreeMap<Digest<Delegation>, (Identifier, Delegation)>, Self::Error>
        {
            Keyline::<Sendable>::delegations_to(&self.0, subject, audience)
        }

        fn effective_power(
            &self,
            subject: Identifier,
            audience: Identifier,
        ) -> Query<'_, Sendable, Option<Power>, Self::Error> {
            Keyline::<Sendable>::effective_power(&self.0, subject, audience)
        }

        fn members(
            &self,
            subject: Identifier,
        ) -> Query<'_, Sendable, BTreeMap<Identifier, Power>, Self::Error> {
            Keyline::<Sendable>::members(&self.0, subject)
        }

        fn members_for_subset(
            &self,
            subset: BTreeSet<CertificateId>,
            subject: Identifier,
        ) -> Query<'_, Sendable, BTreeMap<Identifier, Power>, Self::Error> {
            Keyline::<Sendable>::members_for_subset(&self.0, subset, subject)
        }

        fn subjects(&self) -> Query<'_, Sendable, BTreeSet<Identifier>, Self::Error> {
            Keyline::<Sendable>::subjects(&self.0)
        }

        fn is_live(
            &self,
            delegation: Digest<Delegation>,
        ) -> Query<'_, Sendable, bool, Self::Error> {
            Keyline::<Sendable>::is_live(&self.0, delegation)
        }

        fn positive_power(
            &self,
            subject: Identifier,
            audience: Identifier,
        ) -> Query<'_, Sendable, Option<Power>, Self::Error> {
            Keyline::<Sendable>::positive_power(&self.0, subject, audience)
        }

        fn closure(
            &self,
            _subject: Identifier,
        ) -> Query<'_, Sendable, Vec<Certificate<u64>>, Self::Error> {
            Keyline::<Sendable>::certificates(&self.0)
        }

        fn digest(&self) -> Query<'_, Sendable, Digest<CertificateSet>, Self::Error> {
            Keyline::<Sendable>::digest(&self.0)
        }
    }

    /// The explanation sent to a principal that lost its standing is
    /// sufficient: a store holding only it agrees with the full store that
    /// the principal once stood over the subject (the same positive power) and
    /// no longer does (no effective power). Every pair of identities is
    /// checked against each generated set.
    #[test]
    fn an_explanation_is_sufficient() {
        use keyline::test_utils::{
            assume_verified,
            conformance::gen::{ids, CertSet},
        };

        let runtime = Builder::new_current_thread()
            .build()
            .expect("a runtime starts");
        bolero::check!()
            .with_arbitrary::<CertSet<u64>>()
            .for_each(|set| {
                let verified: BTreeMap<CertificateId, VerifiedCertificate<u64>> = set
                    .certs
                    .iter()
                    .cloned()
                    .map(assume_verified)
                    .map(|cert| (cert.id(), cert))
                    .collect();
                runtime.block_on(async {
                    let full = memory_store(verified.values().cloned().collect()).await;
                    for subject in ids() {
                        for audience in ids().filter(|a| *a != subject) {
                            explanation_agrees(&full, &verified, subject, audience).await;
                        }
                    }
                });
            });
    }

    async fn memory_store(certs: Vec<VerifiedCertificate<u64>>) -> MemoryKeyline<u64> {
        let keyline = MemoryKeyline::<u64>::new();
        Keyline::<Sendable>::insert(&keyline, certs)
            .await
            .expect("the memory store does not fail");
        keyline
    }

    async fn standing(
        keyline: &MemoryKeyline<u64>,
        subject: Identifier,
        audience: Identifier,
    ) -> (Option<Power>, Option<Power>) {
        let positive = Keyline::<Sendable>::positive_power(keyline, subject, audience)
            .await
            .expect("the memory store does not fail")
            .value;
        let effective = Keyline::<Sendable>::effective_power(keyline, subject, audience)
            .await
            .expect("the memory store does not fail")
            .value;
        (positive, effective)
    }

    async fn explanation_agrees(
        full: &MemoryKeyline<u64>,
        verified: &BTreeMap<CertificateId, VerifiedCertificate<u64>>,
        subject: Identifier,
        audience: Identifier,
    ) {
        let expected = standing(full, subject, audience).await;
        if expected.0.is_none() || expected.1.is_some() {
            return;
        }
        let explained = explanation::<Sendable, _>(full, subject, audience)
            .await
            .expect("the memory store does not fail");
        let partial = memory_store(
            explained
                .iter()
                .map(|cert| verified[&cert.id()].clone())
                .collect(),
        )
        .await;
        assert_eq!(
            standing(&partial, subject, audience).await,
            expected,
            "{audience} over {subject}: the explanation disagrees with the full set"
        );
    }
}
