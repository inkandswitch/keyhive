use crate::{
    crypto::{signed::SigningError, signer::memory::MemorySigner},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
};
use rand::rngs::ThreadRng;

pub async fn make_simple_keyhive(
) -> Result<Keyhive<MemorySigner, [u8; 32], NoListener, ThreadRng>, SigningError> {
    let mut csprng = rand::thread_rng();
    let sk = MemorySigner::generate(&mut csprng);
    Ok(Keyhive::generate(sk, NoListener, csprng).await?)
}
