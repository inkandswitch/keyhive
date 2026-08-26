//! Helpers for tests and benchmarks, in this crate and in the integration suite.

pub mod context;

pub use context::{
    content_ref, decrypt_with_key, with_a_flipped_bit, AddMemberUpdateExt, CausalDecryptionExt,
    DelegationSummary, EventKind, Hive, Instance, PrekeyOp, TestContext, TestError, TestResult,
};

use crate::{
    keyhive::Keyhive, listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{signed::SigningError, signer::memory::MemorySigner};
use rand::rngs::OsRng;

pub async fn make_simple_keyhive() -> Result<Hive, SigningError> {
    Keyhive::generate(
        MemorySigner::generate(&mut OsRng),
        MemoryCiphertextStore::new(),
        NoListener,
        rand::rngs::OsRng,
    )
    .await
}
