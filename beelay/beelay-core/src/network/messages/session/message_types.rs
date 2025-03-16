use crate::parse::{self, Parse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionRequestType {
    Begin = 0,
    Sync = 1,
}

impl From<SessionRequestType> for u8 {
    fn from(value: SessionRequestType) -> Self {
        value as u8
    }
}

impl<'a> Parse<'a> for SessionRequestType {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => Ok((input, SessionRequestType::Begin)),
            1 => Ok((input, SessionRequestType::Sync)),
            other => Err(input.error(format!("unexpected SessionRequestType tag: {}", other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionSyncMsgType {
    FetchMembershipSymbols = 0,
    FetchDocSymbols = 1,
    FinishMembership = 2,
    UploadMembershipOps = 3,
    FetchMembershipOps = 4,
    FetchCgkaSymbols = 5,
    FetchCgkaOps = 6,
}

impl From<SessionSyncMsgType> for u8 {
    fn from(value: SessionSyncMsgType) -> Self {
        value as u8
    }
}

impl<'a> Parse<'a> for SessionSyncMsgType {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => Ok((input, SessionSyncMsgType::FetchMembershipSymbols)),
            1 => Ok((input, SessionSyncMsgType::FetchDocSymbols)),
            2 => Ok((input, SessionSyncMsgType::FinishMembership)),
            3 => Ok((input, SessionSyncMsgType::UploadMembershipOps)),
            4 => Ok((input, SessionSyncMsgType::FetchMembershipOps)),
            5 => Ok((input, SessionSyncMsgType::FetchCgkaSymbols)),
            6 => Ok((input, SessionSyncMsgType::FetchCgkaOps)),
            other => Err(input.error(format!("unexpected SessionSyncMsgType tag: {}", other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionResponseType {
    Begin = 0,
    FetchMembershipSymbols = 1,
    FetchDocSymbols = 2,
    FinishMembership = 3,
    UploadMembershipOps = 4,
    FetchMembershipOps = 5,
    FetchCgkaOps = 6,
    FetchCgkaSymbols = 7,
    Expired = 8,
    Error = 9,
}

impl From<SessionResponseType> for u8 {
    fn from(value: SessionResponseType) -> Self {
        value as u8
    }
}

impl<'a> Parse<'a> for SessionResponseType {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => Ok((input, SessionResponseType::Begin)),
            1 => Ok((input, SessionResponseType::FetchMembershipSymbols)),
            2 => Ok((input, SessionResponseType::FetchDocSymbols)),
            3 => Ok((input, SessionResponseType::FinishMembership)),
            4 => Ok((input, SessionResponseType::UploadMembershipOps)),
            5 => Ok((input, SessionResponseType::FetchMembershipOps)),
            6 => Ok((input, SessionResponseType::FetchCgkaOps)),
            7 => Ok((input, SessionResponseType::FetchCgkaSymbols)),
            8 => Ok((input, SessionResponseType::Expired)),
            9 => Ok((input, SessionResponseType::Error)),
            other => Err(input.error(format!("unexpected SessionResponseType tag: {}", other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NextSyncPhaseType {
    Membership = 0,
    Docs = 1,
    Done = 2,
}

impl From<NextSyncPhaseType> for u8 {
    fn from(value: NextSyncPhaseType) -> Self {
        value as u8
    }
}

impl<'a> Parse<'a> for NextSyncPhaseType {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => Ok((input, NextSyncPhaseType::Membership)),
            1 => Ok((input, NextSyncPhaseType::Docs)),
            2 => Ok((input, NextSyncPhaseType::Done)),
            other => Err(input.error(format!("unexpected NextSyncPhaseType tag: {}", other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionMsgType {
    FetchMembershipSymbols,
    FetchDocSymbols,
    FinishMembership,
    UploadMembershipOps,
    FetchMembershipOps,
    FetchCgkaSymbols,
    FetchCgkaOps,
}

impl Into<u8> for SessionMsgType {
    fn into(self) -> u8 {
        match self {
            SessionMsgType::FetchMembershipSymbols => 0,
            SessionMsgType::FetchDocSymbols => 1,
            SessionMsgType::FinishMembership => 2,
            SessionMsgType::UploadMembershipOps => 3,
            SessionMsgType::FetchMembershipOps => 4,
            SessionMsgType::FetchCgkaSymbols => 5,
            SessionMsgType::FetchCgkaOps => 6,
        }
    }
}

impl<'a> Parse<'a> for SessionMsgType {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = parse::u8(input)?;
        match tag {
            0 => Ok((input, SessionMsgType::FetchMembershipSymbols)),
            1 => Ok((input, SessionMsgType::FetchDocSymbols)),
            2 => Ok((input, SessionMsgType::FinishMembership)),
            3 => Ok((input, SessionMsgType::UploadMembershipOps)),
            4 => Ok((input, SessionMsgType::FetchMembershipOps)),
            5 => Ok((input, SessionMsgType::FetchCgkaSymbols)),
            6 => Ok((input, SessionMsgType::FetchCgkaOps)),
            other => Err(input.error(format!("unexpected SessionSyncMsgType tag: {}", other))),
        }
    }
}
