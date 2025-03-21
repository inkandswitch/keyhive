use crate::{
    content::reference::ContentRef,
    crypto::{signed::SigningError, signer::memory::MemorySigner},
    keyhive::Keyhive,
    listener::no_listener::NoListener,
};
use rand::rngs::ThreadRng;

pub async fn make_simple_keyhive<T: ContentRef>(
) -> Result<Keyhive<MemorySigner, T, NoListener, ThreadRng>, SigningError> {
    let sk = MemorySigner::generate(&mut rand::thread_rng());
    Ok(Keyhive::generate(sk, NoListener, rand::thread_rng()).await?)
}
