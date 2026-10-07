//! Keyline's [`Domain`] contexts, one per signed or content-addressed type.
//!
//! All four are listed here so that their distinctness can be read, and is
//! tested, in one place. The version is the protocol version: it changes
//! whenever the meaning of signed bytes does, so a certificate from one
//! version never verifies under another.

use keyhive_crypto::domain_separator::Domain;

use crate::{
    certificate::Certificate, contract::CertificateSet, delegation::Delegation,
    revocation::Revocation,
};

impl Domain for Delegation {
    const CONTEXT: &'static str = "keyline/v0/delegation";
}

impl<W> Domain for Revocation<W> {
    const CONTEXT: &'static str = "keyline/v0/revocation";
}

impl<W> Domain for Certificate<W> {
    const CONTEXT: &'static str = "keyline/v0/certificate";
}

impl<W> Domain for CertificateSet<W> {
    const CONTEXT: &'static str = "keyline/v0/set";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_are_distinct_and_nul_free() {
        let contexts = [
            <Delegation as Domain>::CONTEXT,
            <Revocation<()> as Domain>::CONTEXT,
            <Certificate<()> as Domain>::CONTEXT,
            <CertificateSet<()> as Domain>::CONTEXT,
        ];
        for (i, a) in contexts.iter().enumerate() {
            assert!(!a.contains('\0'), "{a} contains NUL");
            for b in &contexts[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
