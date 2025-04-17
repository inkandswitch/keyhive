use ed25519_dalek::VerifyingKey;
use keyhive_core::crypto::verifiable::Verifiable;

use crate::serialization::{parse, Encode, Parse};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DocumentId(VerifyingKey);

impl PartialOrd for DocumentId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DocumentId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl From<DocumentId> for keyhive_core::principal::document::id::DocumentId {
    fn from(value: DocumentId) -> Self {
        let id = keyhive_core::principal::identifier::Identifier::from(value.0);
        keyhive_core::principal::document::id::DocumentId::from(id)
    }
}

impl From<keyhive_core::principal::document::id::DocumentId> for DocumentId {
    fn from(value: keyhive_core::principal::document::id::DocumentId) -> Self {
        DocumentId(value.verifying_key())
    }
}

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for DocumentId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let secret = u.arbitrary::<[u8; 32]>()?;
        let signing_key = ed25519_dalek::SigningKey::from(secret);
        Ok(DocumentId(signing_key.verifying_key()))
    }
}

impl Encode for DocumentId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.as_bytes());
    }
}

impl Parse<'_> for DocumentId {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("DocumentId", |input| {
            let (input, bytes) = parse::arr::<32>(input)?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|e| input.error(format!("invalid verifying key: {}", e)))?;
            Ok((input, DocumentId(key)))
        })
    }
}

impl serde::Serialize for DocumentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as  the bs58 string
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl std::fmt::Display for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bs58::encode(&self.0).with_check().into_string().fmt(f)
    }
}

impl std::fmt::Debug for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DocumentId({})", self)
    }
}

impl From<VerifyingKey> for DocumentId {
    fn from(value: VerifyingKey) -> Self {
        Self(value)
    }
}

impl std::str::FromStr for DocumentId {
    type Err = error::InvalidDocumentId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).with_check(None).into_vec()?;

        if bytes.len() == 32 {
            let mut id = [0; 32];
            id.copy_from_slice(&bytes);
            let key =
                VerifyingKey::from_bytes(&id).map_err(|_| error::InvalidDocumentId::InvalidKey)?;
            Ok(DocumentId(key))
        } else {
            Err(error::InvalidDocumentId::InvalidLength)
        }
    }
}

impl TryFrom<Vec<u8>> for DocumentId {
    type Error = error::InvalidDocumentId;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() == 32 {
            let mut id = [0; 32];
            id.copy_from_slice(&value);
            let key =
                VerifyingKey::from_bytes(&id).map_err(|_| error::InvalidDocumentId::InvalidKey)?;
            Ok(DocumentId(key))
        } else {
            Err(error::InvalidDocumentId::InvalidLength)
        }
    }
}

impl TryFrom<[u8; 32]> for DocumentId {
    type Error = error::InvalidDocumentId;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let key =
            VerifyingKey::from_bytes(&value).map_err(|_| error::InvalidDocumentId::InvalidKey)?;
        Ok(DocumentId(key))
    }
}

impl DocumentId {
    pub fn random<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(rng);
        DocumentId(signing_key.verifying_key())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_key(&self) -> &VerifyingKey {
        &self.0
    }
}

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    pub enum InvalidDocumentId {
        #[error("Invaliddocument Id length")]
        InvalidLength,
        #[error("Invalid document Id encoding: {0}")]
        InvalidEncoding(#[from] bs58::decode::Error),
        #[error("Invalid document Id key")]
        InvalidKey,
    }
}
