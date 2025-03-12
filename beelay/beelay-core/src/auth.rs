use ed25519_dalek::VerifyingKey;

pub mod audience;
pub mod manager;
pub mod message;
pub(crate) use message::Message;
pub mod offset_seconds;
pub mod signed;
pub(crate) use signed::Signed;
pub mod unix_timestamp;

#[derive(Debug)]
pub(crate) struct Authenticated<T> {
    pub(crate) from: VerifyingKey,
    pub(crate) content: T,
}
