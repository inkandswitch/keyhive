pub trait Verifiable {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}
