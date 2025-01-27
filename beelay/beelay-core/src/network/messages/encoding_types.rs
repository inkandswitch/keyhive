use crate::parse;

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(super) enum RequestType {
    UploadCommits,
    UploadBlob,
    FetchMinimalBundles,
    FetchBlob,
    Ping,
    BeginSync,
    FetchMembershipSymbols,
    DownloadMembershipOps,
    UploadMembershipOps,
    FetchCgkaSymbols,
    DownloadCgkaOps,
    UploadCgkaOps,
    FetchDocStateSymbols,
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
            15 => Ok(Self::BeginSync),
            16 => Ok(Self::FetchMembershipSymbols),
            17 => Ok(Self::DownloadMembershipOps),
            18 => Ok(Self::UploadMembershipOps),
            19 => Ok(Self::FetchCgkaSymbols),
            20 => Ok(Self::DownloadCgkaOps),
            21 => Ok(Self::UploadCgkaOps),
            22 => Ok(Self::FetchDocStateSymbols),
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
            RequestType::BeginSync => 15,
            RequestType::FetchMembershipSymbols => 16,
            RequestType::DownloadMembershipOps => 17,
            RequestType::UploadMembershipOps => 18,
            RequestType::FetchCgkaSymbols => 19,
            RequestType::DownloadCgkaOps => 20,
            RequestType::UploadCgkaOps => 21,
            RequestType::FetchDocStateSymbols => 22,
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
    BeginSync,
    FetchMembershipSymbols,
    DownloadMembershipOps,
    UploadMembershipOps,
    FetchCgkaSymbols,
    DownloadCgkaOps,
    UploadCgkaOps,
    FetchDocStateSymbols,
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
            17 => Ok(Self::BeginSync),
            18 => Ok(Self::FetchMembershipSymbols),
            19 => Ok(Self::DownloadMembershipOps),
            20 => Ok(Self::UploadMembershipOps),
            21 => Ok(Self::FetchCgkaSymbols),
            22 => Ok(Self::DownloadCgkaOps),
            23 => Ok(Self::UploadCgkaOps),
            24 => Ok(Self::FetchDocStateSymbols),
            25 => Ok(Self::UploadBlob),
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
            ResponseType::BeginSync => 17,
            ResponseType::FetchMembershipSymbols => 18,
            ResponseType::DownloadMembershipOps => 19,
            ResponseType::UploadMembershipOps => 20,
            ResponseType::FetchCgkaSymbols => 21,
            ResponseType::DownloadCgkaOps => 22,
            ResponseType::UploadCgkaOps => 23,
            ResponseType::FetchDocStateSymbols => 24,
            ResponseType::UploadBlob => 25,
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
