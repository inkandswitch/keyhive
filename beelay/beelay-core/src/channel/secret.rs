#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Secret(pub(crate) [u8; 32]);

impl From<Secret> for Vec<u8> {
    fn from(secret: Secret) -> Vec<u8> {
        secret.0.to_vec()
    }
}

impl From<[u8; 32]> for Secret {
    fn from(bytes: [u8; 32]) -> Secret {
        Secret(bytes)
    }
}

impl TryFrom<Vec<u8>> for Secret {
    type Error = <[u8; 32] as TryFrom<Vec<u8>>>::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Secret(bytes.try_into()?))
    }
}
