use crate::serialization::{hex, parse, Encode, Parse};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct KeyhiveSyncId([u8; 16]);

impl std::str::FromStr for KeyhiveSyncId {
    type Err = error::BadKeyhiveSyncId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(error::BadKeyhiveSyncId::InvalidHex)?;
        if bytes.len() == 16 {
            let mut id = [0; 16];
            id.copy_from_slice(&bytes);
            Ok(Self(id))
        } else {
            Err(error::BadKeyhiveSyncId::InvalidLength)
        }
    }
}

impl std::fmt::Display for KeyhiveSyncId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl std::fmt::Debug for KeyhiveSyncId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl KeyhiveSyncId {
    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl Encode for KeyhiveSyncId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for KeyhiveSyncId {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, id) = parse::arr::<16>(input)?;
        Ok((input, Self(id)))
    }
}

mod error {
    use crate::serialization::hex;

    pub enum BadKeyhiveSyncId {
        InvalidHex(hex::FromHexError),
        InvalidLength,
    }

    impl std::fmt::Display for BadKeyhiveSyncId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InvalidHex(e) => write!(f, "invalid hex: {:?}", e),
                Self::InvalidLength => write!(f, "invalid length"),
            }
        }
    }

    impl std::fmt::Debug for BadKeyhiveSyncId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for BadKeyhiveSyncId {}
}
