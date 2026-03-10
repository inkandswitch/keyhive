use crate::{
    keyhive::Keyhive, listener::no_listener::NoListener,
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{signed::SigningError, signer::memory::MemorySigner};
use rand::rngs::OsRng;

pub async fn make_simple_keyhive() -> Result<
    Keyhive<
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
    Keyhive::generate(sk, MemoryCiphertextStore::new(), NoListener, csprng).await
}
