//! Crate-wide invariants that no single module can check.

use keyhive_crypto::signable::{Kind, Kinded};
use keyline::{contract::CertificateSet, delegation::Delegation, revocation::Revocation};
use std::path::Path;

/// The kind of every signed or hashed type. Each type declares its own next
/// to its definition.
const KINDS: [Kind; 3] = [
    <Delegation as Kinded>::KIND,
    <Revocation<()> as Kinded>::KIND,
    <CertificateSet as Kinded>::KIND,
];

#[test]
fn kinds_are_distinct() {
    for (i, a) in KINDS.iter().enumerate() {
        for b in &KINDS[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// Every `impl Kinded` in the crate is in [`KINDS`]: two types sharing a
/// kind could share a valid signature or digest, and a type missing from the
/// list would escape the check above.
#[test]
fn every_kinded_impl_is_listed() {
    fn count(dir: &Path) -> usize {
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
                        .filter(|l| l.trim_start().starts_with("impl") && l.contains("Kinded for "))
                        .count()
                } else {
                    0
                }
            })
            .sum()
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert_eq!(count(&src), KINDS.len());
}
