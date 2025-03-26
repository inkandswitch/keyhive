use std::{cell::RefCell, rc::Rc};

use crate::{
    crypto::{signed::SigningError, signer::memory::MemorySigner},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore,
};
use rand::rngs::ThreadRng;

pub async fn make_simple_keyhive() -> Result<
    Keyhive<
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        MemoryCiphertextStore<[u8; 32], Vec<u8>>,
        NoListener,
        ThreadRng,
    >,
    SigningError,
> {
    let mut csprng = rand::thread_rng();
    let sk = MemorySigner::generate(&mut csprng);
    Ok(Keyhive::generate(
        sk,
        Rc::new(RefCell::new(MemoryCiphertextStore::new())),
        NoListener,
        csprng,
    )
    .await?)
}
