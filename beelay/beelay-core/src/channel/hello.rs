use super::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hello {
    pub client_pk: x25519_dalek::PublicKey,
    pub server_id_hash: Hash<String>,
}

impl From<Hello> for Vec<u8> {
    fn from(hello: Hello) -> Vec<u8> {
        let mut buf = hello.client_pk.as_bytes().to_vec();
        buf.extend(Vec::<u8>::from(hello.server_id_hash));
        buf
    }
}
