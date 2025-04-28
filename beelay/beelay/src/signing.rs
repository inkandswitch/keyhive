use std::future::Future;

use keyhive_core::crypto::verifiable::Verifiable;

mod memory;
pub use memory::MemorySigner;

pub trait Signing: Verifiable {
    type Error: std::error::Error + Send + Sync + 'static;

    fn sign(
        &self,
        message: &[u8],
    ) -> impl Future<Output = Result<ed25519_dalek::Signature, Self::Error>> + Send;
}
