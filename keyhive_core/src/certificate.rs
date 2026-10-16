//! Keyline certificates in `keyhive_core`: signing root edges, finding the
//! routes certificates open, and the errors membership writes share.

use ed25519_dalek::{Signature, VerifyingKey};
use future_form::FutureForm;
use keyhive_codec::traits::Decode;
use keyhive_crypto::{
    id::Id,
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
pub(crate) fn root_edges<I: IntoIterator<Item = Id>>(
    signer: &dyn SyncSignerBasic,
    subject: Id,
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
    doc: Id,
    issuer: Id,
    delegation: &Delegation,
    who: Id,
) -> Result<bool, K::Error> {
    let mut standing = Standing::new(keyline);
    let subject = delegation.subject;
    if !standing.over(subject, issuer).await? || !standing.over(doc, subject).await? {
        return Ok(false);
    }

    // `closure(doc)` holds every delegation about every subject with standing
    // over `doc`; keep those about subjects the route can pass through.
    let mut edges: Vec<(Id, Delegation)> = Vec::new();
    for cert in keyline.closure(doc).await?.value {
        let Certificate::Delegation(signed) = cert else {
            continue;
        };
        let (edge_issuer, d) = decode_stored(&signed);
        if standing.over(d.subject, subject).await? && standing.over(doc, d.subject).await? {
            edges.push((edge_issuer, d));
        }
    }

    // (node, the subject it is reached at)
    let mut reached: Vec<(Id, Id)> = vec![(delegation.audience, subject)];
    loop {
        let mut grew = false;
        for (edge_issuer, edge) in &edges {
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
        if !grew {
            break;
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
    subject: Id,
    audience: Id,
) -> Result<Vec<Certificate<K::RetentionWatermark>>, K::Error> {
    let mut delegations = Vec::new();
    let mut revocations = Vec::new();
    for cert in keyline.closure(subject).await?.value {
        match &cert {
            Certificate::Delegation(signed) => {
                let (issuer, d) = decode_stored(signed);
                delegations.push((issuer, d, signed.digest(), cert));
            }
            Certificate::Revocation(signed) => {
                let (issuer, r): (Id, Revocation<K::RetentionWatermark>) = decode_stored(signed);
                revocations.push((issuer, r.revoke, cert));
            }
        }
    }

    let mut kept = BTreeMap::new();
    let mut routes = BTreeSet::new();
    for (issuer, d, digest, cert) in &delegations {
        if route_through(keyline, subject, *issuer, d, audience).await? {
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
                && route_through(keyline, subject, *issuer, d, revoker).await?
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
    known: BTreeMap<(Id, Id), bool>,
    _form: PhantomData<F>,
}

impl<'a, F: FutureForm, K: Keyline<F>> Standing<'a, F, K> {
    fn new(keyline: &'a K) -> Self {
        Standing {
            keyline,
            known: BTreeMap::new(),
            _form: PhantomData,
        }
    }

    async fn over(&mut self, subject: Id, audience: Id) -> Result<bool, K::Error> {
        if subject == audience {
            return Ok(true);
        }
        if let Some(known) = self.known.get(&(subject, audience)) {
            return Ok(*known);
        }
        let holds = self
            .keyline
            .positive_power(subject, audience)
            .await?
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
    subject: Id,
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
/// only verified certificates, whose encoding is canonical, so this cannot
/// fail.
pub fn decode_stored<T: Decode>(signed: &Signed<T>) -> (Id, T) {
    let payload = signed
        .encoded()
        .decode()
        .expect("a stored certificate decodes: the store verified it");
    (signed.issuer(), payload)
}

/// The `Keyline` store failed: its backend's own storage error `E`
/// ([`Keyline::Error`]). A backend that cannot fail, such as
/// `keyline_memory`'s, has `E = Infallible`, which makes this uninhabited.
#[derive(Debug, Error)]
#[error("the Keyline store failed")]
pub struct KeylineStorageError<E: core::error::Error + 'static>(#[source] E);

impl<E: core::error::Error + 'static> KeylineStorageError<E> {
    /// Wrap a backend's error.
    pub fn new(error: E) -> Self {
        KeylineStorageError(error)
    }

    /// The backend's own error.
    pub fn into_inner(self) -> E {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use future_form::Sendable;
    use keyline::certificate::{CertificateId, VerifiedCertificate};
    use keyline_memory::MemoryKeyline;
    use tokio::runtime::Builder;

    /// Root edges are signed by the subject, name each creator as an `Admin`
    /// audience, and verify.
    #[test]
    fn root_edges_are_admin_from_the_subject() {
        let subject = SigningKey::from_bytes(&[1; 32]);
        let creators: Vec<Id> = [[2; 32], [3; 32]]
            .map(|seed| Id::from(&SigningKey::from_bytes(&seed)))
            .into();
        let edges =
            root_edges(&subject, Id::from(&subject), creators.clone()).expect("valid keys sign");

        let subject_id = Id::from(&subject);
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
        subject: Id,
        audience: Id,
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
        subject: Id,
        audience: Id,
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
