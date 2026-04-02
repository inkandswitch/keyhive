use crate::{
    keyhive::{GenerateError, Keyhive},
    listener::no_listener::NoListener,
    store::{ciphertext::memory::MemoryCiphertextStore, secret_key::memory::MemorySecretKeyStore},
};
use future_form::Sendable;
use keyhive_crypto::signer::memory::MemorySigner;
use rand::rngs::OsRng;

pub async fn make_simple_keyhive() -> Result<
    Keyhive<
        Sendable,
        MemorySigner,
        MemorySecretKeyStore,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        NoListener,
        OsRng,
    >,
    GenerateError<MemorySecretKeyStore, Sendable>,
> {
    let mut csprng = OsRng;
    let sk = MemorySigner::generate(&mut csprng);
    Keyhive::<Sendable, _, _, _, _, _, _, _>::generate(
        sk,
        MemorySecretKeyStore::new(),
        MemoryCiphertextStore::new(),
        NoListener,
        csprng,
    )
    .await
}
