use crate::{
    deser::{Encode, Parse},
    parse,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum Audience {
    VerifyingKey([u8; 32]),
    ServiceName([u8; 32]),
}

impl std::fmt::Debug for Audience {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for Audience {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyingKey(vk) => write!(f, "vk:{}", crate::hex::encode(vk)),
            Self::ServiceName(name) => write!(f, "service:{}", crate::hex::encode(name)),
        }
    }
}

impl Audience {
    pub fn service_name<S: AsRef<str>>(service: S) -> Self {
        Self::ServiceName(blake3::hash(service.as_ref().as_bytes()).into())
    }

    pub fn peer(peer: &crate::PeerId) -> Self {
        (*peer.as_key()).into()
    }

    pub fn verifying_key(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self::VerifyingKey(vk.to_bytes())
    }
}

impl Encode for Audience {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::ServiceName(b) => {
                NodeIdTag::ServiceName.encode_into(out);
                out.extend_from_slice(b);
            }
            Self::VerifyingKey(b) => {
                NodeIdTag::VerifyingKey.encode_into(out);
                out.extend_from_slice(b);
            }
        }
    }
}

impl Parse<'_> for Audience {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, tag) = NodeIdTag::parse_in_ctx("tag", input)?;
        let (input, content) = input.parse_in_ctx("content", parse::arr::<32>)?;
        match tag {
            NodeIdTag::ServiceName => Ok((input, Self::ServiceName(content))),
            NodeIdTag::VerifyingKey => Ok((input, Self::VerifyingKey(content))),
        }
    }
}

impl From<&ed25519_dalek::SigningKey> for Audience {
    fn from(sk: &ed25519_dalek::SigningKey) -> Self {
        Self::verifying_key(sk.verifying_key())
    }
}

impl From<ed25519_dalek::VerifyingKey> for Audience {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self::verifying_key(vk)
    }
}

enum NodeIdTag {
    VerifyingKey,
    ServiceName,
}

impl Encode for NodeIdTag {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::VerifyingKey => out.push(0),
            Self::ServiceName => out.push(1),
        }
    }
}

impl Parse<'_> for NodeIdTag {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("NodeIdTag", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => Ok((input, Self::VerifyingKey)),
                1 => Ok((input, Self::ServiceName)),
                other => Err(input.error(format!("invalid node ID type tag: {}", other))),
            }
        })
    }
}
