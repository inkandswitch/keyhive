pub trait Verifiable {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}

impl Verifiable for ed25519_dalek::SigningKey {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.into()
    }
}
