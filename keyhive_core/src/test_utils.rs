use crate::{
    keyhive::Keyhive, listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore,
};
use future_form::Sendable;
use keyhive_crypto::{signed::SigningError, signer::memory::MemorySigner};
use rand::rngs::OsRng;

pub async fn make_simple_keyhive() -> Result<
    Keyhive<
        Sendable,
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        NoListener,
        OsRng,
    >,
    SigningError,
> {
    let mut csprng = OsRng;
    let sk = MemorySigner::generate(&mut csprng);
    Keyhive::<Sendable, _, _, _, _, _, _>::generate(
        sk,
        MemoryCiphertextStore::new(),
        NoListener,
        csprng,
    )
    .await
}
