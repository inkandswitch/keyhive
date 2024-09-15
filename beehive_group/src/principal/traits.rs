// FIXME rename module?

pub trait Verifiable {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;

    fn id(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
}
