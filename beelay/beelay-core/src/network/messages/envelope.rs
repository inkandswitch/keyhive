use crate::{
    parse::{self, Parse},
    serialization::{DecodeBytes, Encode, EncodeBytes},
};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Envelope {
    Signed(Box<crate::auth::Signed<crate::auth::Message>>),
    Unsigned(Vec<u8>),
}

impl Encode for Envelope {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Signed(msg) => {
                out.push(0);
                msg.encode_into(out);
            }
            Self::Unsigned(msg) => {
                out.push(1);
                EncodeBytes::from(msg).encode_into(out);
            }
        }
    }
}

impl<'a> Parse<'a> for Envelope {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => {
                let (input, msg) = input
                    .parse_in_ctx("Signed", crate::auth::Signed::<crate::auth::Message>::parse)?;
                Ok((input, Self::Signed(Box::new(msg))))
            }
            1 => {
                let (input, msg) = input.parse_in_ctx("Unsigned", DecodeBytes::parse)?;
                Ok((input, Self::Unsigned(msg.into())))
            }
            other => Err(input.error(format!("unknown message tag: {}", other))),
        }
    }
}
