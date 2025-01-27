use crate::{
    parse::{self, Parse},
    serialization::{hex, Encode},
};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct SessionId([u8; 16]);

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl SessionId {
    pub(crate) fn new<R: rand::Rng>(rng: &mut R) -> Self {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl Encode for SessionId {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl<'a> Parse<'a> for SessionId {
    fn parse(
        input: crate::parse::Input<'a>,
    ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
        let (input, arr) = parse::arr::<16>(input)?;
        Ok((input, Self(arr)))
    }
}
