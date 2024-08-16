use crate::parse;

pub(super) enum MessageType {
    Request,
    Response,
    Notification,
}

impl MessageType {
    pub(super) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("MessageDirection", |input| {
            let (input, byte) = parse::u8(input)?;
            let msg_type = MessageType::try_from(byte)
                .map_err(|e| input.error(format!("invalid message type: {:?}", e)))?;
            Ok((input, msg_type))
        })
    }
}

impl TryFrom<u8> for MessageType {
    type Error = error::InvalidMessageDirection;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Request),
            1 => Ok(Self::Response),
            3 => Ok(Self::Notification),
            other => Err(error::InvalidMessageDirection(other)),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(msg_type: MessageType) -> u8 {
        match msg_type {
            MessageType::Request => 0,
            MessageType::Response => 1,
            MessageType::Notification => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(super) enum RequestType {
    UploadCommits,
    UploadBlob,
    FetchMinimalBundles,
    FetchBlobPart,
    CreateSnapshot,
    SnapshotSymbols,
    Listen,
}

impl RequestType {
    pub(super) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("RequestType", |input| {
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
            2 => Ok(Self::FetchBlobPart),
            3 => Ok(Self::UploadBlob),
            4 => Ok(Self::CreateSnapshot),
            5 => Ok(Self::SnapshotSymbols),
            6 => Ok(Self::Listen),
            _ => Err(error::InvalidRequestType(value)),
        }
    }
}

impl From<RequestType> for u8 {
    fn from(req: RequestType) -> u8 {
        match req {
            RequestType::UploadCommits => 0,
            RequestType::FetchMinimalBundles => 1,
            RequestType::FetchBlobPart => 2,
            RequestType::UploadBlob => 3,
            RequestType::CreateSnapshot => 4,
            RequestType::SnapshotSymbols => 5,
            RequestType::Listen => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(super) enum ResponseType {
    Err,
    UploadCommits,
    FetchSedimentree,
    FetchBlobPart,
    CreateSnapshot,
    SnapshotSymbols,
}

impl ResponseType {
    pub(super) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("ResponseType", |input| {
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
            3 => Ok(Self::FetchBlobPart),
            4 => Ok(Self::CreateSnapshot),
            5 => Ok(Self::SnapshotSymbols),
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
            ResponseType::FetchBlobPart => 3,
            ResponseType::CreateSnapshot => 4,
            ResponseType::SnapshotSymbols => 5,
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
