use crate::{
    crypto::signer::memory::MemorySigner,
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    principal::active::GenerateActiveError,
    store::{ciphertext::memory::MemoryCiphertextStore, secret_key::memory::MemorySecretKeyStore},
};
use rand::rngs::ThreadRng;
use std::collections::HashMap;

pub async fn make_simple_keyhive() -> Result<
    Keyhive<
        MemorySigner,
        MemorySecretKeyStore<ThreadRng>,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        NoListener,
        ThreadRng,
    >,
    GenerateActiveError<MemorySecretKeyStore<ThreadRng>>,
> {
    let mut csprng = rand::thread_rng();

    Keyhive::generate(
        MemorySigner::generate(&mut csprng),
        MemorySecretKeyStore {
            csprng: rand::thread_rng(),
            keys: HashMap::new(),
        },
        MemoryCiphertextStore::new(),
        NoListener,
        csprng,
    )
    .await
}
