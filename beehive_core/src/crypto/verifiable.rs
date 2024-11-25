use super::verifying_key::VerifyingKey;

pub trait Verifiable {
    fn verifying_key(&self) -> VerifyingKey;
}
