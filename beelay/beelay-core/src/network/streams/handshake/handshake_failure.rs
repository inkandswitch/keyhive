use crate::{
    parse::{self, Parse},
    serialization::Encode,
    UnixTimestamp,
};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum HandshakeFailure {
    AuthFailed,
    BadTimestamp { receivers_clock: UnixTimestamp },
}

impl std::fmt::Display for HandshakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthFailed => write!(f, "authentication failed"),
            Self::BadTimestamp { receivers_clock: _ } => {
                write!(f, "mismatched clocks")
            }
        }
    }
}

impl Encode for HandshakeFailure {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::AuthFailed => {
                FailureType::Auth.encode_into(out);
            }
            Self::BadTimestamp { receivers_clock } => {
                FailureType::BadTimestamp.encode_into(out);
                receivers_clock.encode_into(out);
            }
        }
    }
}

impl Parse<'_> for HandshakeFailure {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("Failure", |input| {
            let (input, fail_type) = FailureType::parse_in_ctx("tag", input)?;
            match fail_type {
                FailureType::Auth => Ok((input, Self::AuthFailed)),
                FailureType::BadTimestamp => {
                    let (input, receivers_clock) =
                        UnixTimestamp::parse_in_ctx("receivers_clock", input)?;
                    Ok((input, Self::BadTimestamp { receivers_clock }))
                }
            }
        })
    }
}

enum FailureType {
    Auth,
    BadTimestamp,
}

impl Encode for FailureType {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Auth => out.push(0),
            Self::BadTimestamp => out.push(1),
        }
    }
}

impl Parse<'_> for FailureType {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        let result = match tag {
            0 => Self::Auth,
            1 => Self::BadTimestamp,
            other => return Err(input.error(format!("unknown failure type {}", other))),
        };
        Ok((input, result))
    }
}
