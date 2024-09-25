// FIXME rename module?
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub trait Verifiable {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}
