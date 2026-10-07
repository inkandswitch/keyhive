//! Crate-wide invariants that no single module can check.

use keyhive_crypto::domain_separator::Domain;
use keyline::{contract::CertificateSet, delegation::Delegation, revocation::Revocation};

/// The domain context of every signed or hashed type. Each type declares its
/// own next to its definition; any new `impl Domain` belongs in this list,
/// since two types sharing a context could share a valid signature or digest.
const CONTEXTS: [&str; 3] = [
    <Delegation as Domain>::CONTEXT,
    <Revocation<()> as Domain>::CONTEXT,
    <CertificateSet as Domain>::CONTEXT,
];

#[test]
fn domain_contexts_are_distinct() {
    for (i, a) in CONTEXTS.iter().enumerate() {
        for b in &CONTEXTS[i + 1..] {
            assert_ne!(a, b);
        }
    }
}
