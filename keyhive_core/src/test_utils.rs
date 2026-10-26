//! Helpers for tests and benchmarks, in this crate and in the integration suite.
#![doc = include_str!("test_utils/README.md")]

pub mod context;

pub use context::{
    content_ref, decrypt_with_key, with_a_flipped_bit, AddMemberUpdateExt, CausalDecryptionExt,
    DelegationSummary, EventKind, Hive, Instance, KeylineStore, PrekeyOp, TestContext, TestError,
    TestResult,
};

use crate::{
    keyhive::Keyhive, listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore, update::RevokeMemberUpdate,
};
use beekem::operation::{CgkaChange, CitationId};
use keyhive_crypto::{signer::memory::MemorySigner, verified::SignError};
use rand::rngs::OsRng;

pub async fn make_simple_keyhive() -> Result<Hive, SignError> {
    Keyhive::generate(
        MemorySigner::generate(&mut OsRng),
        MemoryCiphertextStore::new(),
        NoListener,
        KeylineStore::new(),
        OsRng,
    )
    .await
}

/// Whether `update` has a CGKA remove citing one of its revocations.
pub fn has_remove_citing_its_revocation(update: &RevokeMemberUpdate<[u8; 32]>) -> bool {
    let revocations: Vec<CitationId> = update
        .revocations()
        .iter()
        .map(|r| CitationId(r.digest().into()))
        .collect();
    update.cgka_ops().iter().any(|op| {
        matches!(op.payload().change, CgkaChange::Remove { .. })
            && op
                .payload()
                .citations()
                .iter()
                .any(|c| revocations.contains(c))
    })
}
