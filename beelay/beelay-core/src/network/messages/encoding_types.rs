use crate::parse;

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(super) enum RequestType {
    UploadCommits,
    UploadBlob,
    FetchMinimalBundles,
    FetchBlob,
    Ping,
    UploadMembershipOps,
    UploadCgkaOps,
    Session,
    SyncNeeded,
}

impl RequestType {
    pub(super) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("RequestType", |input| {
            let (input, byte) = parse::u8(input)?;
            let req_type = RequestType::try_from(byte)
                .map_err(|e| input.error(format!("invalid request type: {}", e)))?;
            Ok((input, req_type))
        })
    }
}

impl TryFrom<u8> for RequestType {
    type Error = error::InvalidRequestType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UploadCommits),
            1 => Ok(Self::FetchMinimalBundles),
            3 => Ok(Self::UploadBlob),
            11 => Ok(Self::Ping),
            12 => Ok(Self::FetchBlob),
            18 => Ok(Self::UploadMembershipOps),
            21 => Ok(Self::UploadCgkaOps),
            24 => Ok(Self::Session),
            25 => Ok(Self::SyncNeeded),

            _ => Err(error::InvalidRequestType(value)),
        }
    }
}

impl From<RequestType> for u8 {
    fn from(req: RequestType) -> u8 {
        match req {
            RequestType::UploadCommits => 0,
            RequestType::FetchMinimalBundles => 1,
            RequestType::UploadBlob => 3,
            RequestType::Ping => 11,
            RequestType::FetchBlob => 12,
            RequestType::UploadMembershipOps => 18,
            RequestType::UploadCgkaOps => 21,
            RequestType::Session => 24,
            RequestType::SyncNeeded => 25,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(super) enum ResponseType {
    Err,
    UploadCommits,
    FetchSedimentree,
    FetchBlob,
    Pong,
    AuthenticationFailed,
    AuthorizationFailed,
    Session,
    SyncNeeded,
    UploadMembershipOps,
    UploadCgkaOps,
    UploadBlob,
}

impl ResponseType {
    pub(super) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("ResponseType", |input| {
            let (input, byte) = parse::u8(input)?;
            let req_type = ResponseType::try_from(byte)
                .map_err(|e| input.error(format!("invalid request type: {:?}", e)))?;
            Ok((input, req_type))
        })
    }
}

impl TryFrom<u8> for ResponseType {
    type Error = error::InvalidResponseType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Err),
            1 => Ok(Self::UploadCommits),
            2 => Ok(Self::FetchSedimentree),
            11 => Ok(Self::Pong),
            12 => Ok(Self::AuthenticationFailed),
            13 => Ok(Self::AuthorizationFailed),
            14 => Ok(Self::FetchBlob),
            20 => Ok(Self::UploadMembershipOps),
            23 => Ok(Self::UploadCgkaOps),
            25 => Ok(Self::UploadBlob),
            27 => Ok(Self::Session),
            28 => Ok(Self::SyncNeeded),

            _ => Err(error::InvalidResponseType(value)),
        }
    }
}

impl From<ResponseType> for u8 {
    fn from(resp: ResponseType) -> Self {
        match resp {
            ResponseType::Err => 0,
            ResponseType::UploadCommits => 1,
            ResponseType::FetchSedimentree => 2,
            ResponseType::Pong => 11,
            ResponseType::AuthenticationFailed => 12,
            ResponseType::AuthorizationFailed => 13,
            ResponseType::FetchBlob => 14,
            ResponseType::UploadMembershipOps => 20,
            ResponseType::UploadCgkaOps => 23,
            ResponseType::UploadBlob => 25,
            ResponseType::Session => 27,
            ResponseType::SyncNeeded => 28,
        }
    }
}

mod error {
    pub struct InvalidMessageDirection(pub(super) u8);

    impl std::fmt::Display for InvalidMessageDirection {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "invalid message direction: {}", self.0)
        }
    }

    impl std::fmt::Debug for InvalidMessageDirection {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "InvalidMessageDirection({})", self.0)
        }
    }

    impl std::error::Error for InvalidMessageDirection {}

    pub struct InvalidRequestType(pub(super) u8);

    impl std::fmt::Display for InvalidRequestType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "invalid request type: {}", self.0)
        }
    }

    impl std::fmt::Debug for InvalidRequestType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "InvalidRequestType({})", self.0)
        }
    }

    impl std::error::Error for InvalidRequestType {}

    pub struct InvalidResponseType(pub(super) u8);

    impl std::fmt::Display for InvalidResponseType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "invalid response type: {}", self.0)
        }
    }

    impl std::fmt::Debug for InvalidResponseType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "InvalidResponseType({})", self.0)
        }
    }

    impl std::error::Error for InvalidResponseType {}
}
