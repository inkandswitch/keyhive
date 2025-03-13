use std::fmt;

use crate::{
    parse::{self, Parse},
    serialization::Encode,
    sync::sessions::SessionError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum SessionResponse<R> {
    Ok(R),
    SessionNotFound,
    SessionExpired,
}

impl<R> SessionResponse<R> {
    pub(super) fn fmt_contents<F: Fn(&mut fmt::Formatter, &R) -> fmt::Result>(
        &self,
        formatter: &mut fmt::Formatter,
        f: F,
    ) -> fmt::Result {
        match self {
            SessionResponse::Ok(response) => f(formatter, response),
            SessionResponse::SessionNotFound => write!(formatter, "Session not found"),
            SessionResponse::SessionExpired => write!(formatter, "Session expired"),
        }
    }
}

const OK_CODE: u8 = 1;
const NOT_FOUND_CODE: u8 = 2;
const EXPIRED_CODE: u8 = 3;

impl<R: Encode> Encode for SessionResponse<R> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ok(r) => {
                out.push(OK_CODE);
                r.encode_into(out);
            }
            Self::SessionNotFound => {
                out.push(NOT_FOUND_CODE);
            }
            Self::SessionExpired => {
                out.push(EXPIRED_CODE);
            }
        }
    }
}

impl<'a, R: Parse<'a>> Parse<'a> for SessionResponse<R> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            OK_CODE => {
                let (input, response) = R::parse(input)?;
                Ok((input, SessionResponse::Ok(response)))
            }
            NOT_FOUND_CODE => Ok((input, SessionResponse::SessionNotFound)),
            EXPIRED_CODE => Ok((input, SessionResponse::SessionExpired)),
            other => Err(input.error(format!("unknown success response tag: {}", other))),
        }
    }
}

impl<R> From<Result<R, SessionError>> for SessionResponse<R> {
    fn from(result: Result<R, SessionError>) -> Self {
        match result {
            Ok(response) => SessionResponse::Ok(response),
            Err(SessionError::NotFound) => SessionResponse::SessionNotFound,
            Err(SessionError::Expired) => SessionResponse::SessionExpired,
        }
    }
}
