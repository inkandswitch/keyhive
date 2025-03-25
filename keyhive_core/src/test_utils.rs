use std::collections::HashMap;

use crate::{
    crypto::{encrypted::EncryptedContent, signed::SigningError, signer::memory::MemorySigner},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
};
use rand::rngs::ThreadRng;

pub async fn make_simple_keyhive() -> Result<
    Keyhive<
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        HashMap<[u8; 32], EncryptedContent<Vec<u8>, [u8; 32]>>,
        NoListener,
        ThreadRng,
    >,
    SigningError,
> {
    let mut csprng = rand::thread_rng();
    let sk = MemorySigner::generate(&mut csprng);
    Ok(Keyhive::generate(sk, HashMap::new(), NoListener, csprng).await?)
}
