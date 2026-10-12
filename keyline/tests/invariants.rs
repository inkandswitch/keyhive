//! Crate-wide invariants that no single module can check.

use keyhive_crypto::domain_separator::Domain;
use keyline::{contract::CertificateSet, delegation::Delegation, revocation::Revocation};

/// The domain context of every signed or hashed type. Each type declares its
/// own next to its definition.
const CONTEXTS: [&str; 3] = [
    <Delegation as Domain>::CONTEXT,
    <Revocation<()> as Domain>::CONTEXT,
    <CertificateSet as Domain>::CONTEXT,
];

#[test]
fn domain_contexts_are_distinct_and_versioned() {
    for (i, a) in CONTEXTS.iter().enumerate() {
        assert!(
            a.starts_with("keyline/v0/"),
            "{a} names the protocol version"
        );
        for b in &CONTEXTS[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// Every `impl Domain` in the crate is in [`CONTEXTS`]: two types sharing a
/// context could share a valid signature or digest, and a type missing from
/// the list would escape the check above.
#[test]
fn every_domain_impl_is_listed() {
    fn count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .expect("source directory is readable")
            .map(|entry| entry.expect("directory entry").path())
            .map(|path| {
                if path.is_dir() {
                    count(&path)
                } else if path.extension().is_some_and(|e| e == "rs") {
                    std::fs::read_to_string(&path)
                        .expect("source file is readable")
                        .lines()
                        .filter(|l| l.trim_start().starts_with("impl") && l.contains("Domain for "))
                        .count()
                } else {
                    0
                }
            })
            .sum()
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert_eq!(count(&src), CONTEXTS.len());
}
