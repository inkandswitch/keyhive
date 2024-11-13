use crate::{
    parse, riblt::doc_and_heads::CodedDocAndHeadsSymbol, BlobHash, Commit, CommitCategory,
    CommitHash, DocumentId, Payload, RequestId, SnapshotId,
};

use super::{
    encoding_types::{MessageType, RequestType, ResponseType},
    FetchedSedimentree, Message, Notification, UploadItem,
};

pub use error::DecodeError;

pub(super) fn decode(bytes: &[u8]) -> Result<(Payload, usize), DecodeError> {
    let input = parse::Input::new(bytes);
    let (input, payload) = parse_payload(input)?;
    Ok((payload, input.offset()))
}

pub(crate) fn parse_payload(
    input: parse::Input<'_>,
) -> Result<(parse::Input<'_>, Payload), parse::ParseError> {
    input.with_context("payload", |input| {
        let (input, message_type) = MessageType::parse(input)?;
        let (input, message) = match message_type {
            MessageType::Request => {
                input.with_context("request payload", |input| parse_request(input))
            }
            MessageType::Response => {
                input.with_context("response payload", |input| parse_response(input))
            }
            MessageType::Notification => input.with_context("notification payload", |input| {
                let (input, notification) = Notification::parse(input)?;
                Ok((input, Message::Notification(notification)))
            }),
        }?;
        let payload = Payload::new(message);
        Ok((input, payload))
    })
}

fn parse_request(
    input: parse::Input<'_>,
) -> Result<(parse::Input<'_>, Message), parse::ParseError> {
    let (input, request_id) = RequestId::parse(input)?;
    let (input, req_type) = RequestType::parse(input)?;
    match req_type {
        RequestType::UploadCommits => input.with_context("UploadCommits", |input| {
            let (input, dag) = DocumentId::parse(input)?;
            let (input, category) = CommitCategory::parse(input)?;
            let (input, data) = parse::many(input, UploadItem::parse)?;
            Ok((
                input,
                Message::Request(
                    request_id,
                    super::Request::UploadCommits {
                        doc: dag,
                        data,
                        category,
                    },
                ),
            ))
        }),
        RequestType::FetchMinimalBundles => input.with_context("FetchMinimalBundles", |input| {
            let (input, dag_id) = DocumentId::parse(input)?;
            Ok((
                input,
                Message::Request(request_id, super::Request::FetchSedimentree(dag_id)),
            ))
        }),
        RequestType::FetchBlobPart => input.with_context("FetchBlobPart", |input| {
            let (input, blob) = BlobHash::parse(input)?;
            let (input, offset) = crate::leb128::parse(input)?;
            let (input, length) = crate::leb128::parse(input)?;
            Ok((
                input,
                Message::Request(
                    request_id,
                    super::Request::FetchBlobPart {
                        blob,
                        offset,
                        length,
                    },
                ),
            ))
        }),
        RequestType::UploadBlob => input.with_context("UploadBlob", |input| {
            let (input, data) = parse::slice(input)?;
            Ok((
                input,
                Message::Request(request_id, super::Request::UploadBlob(data.to_vec())),
            ))
        }),
        RequestType::CreateSnapshot => input.with_context("CreateSnapshot", |input| {
            let (input, root_doc) = DocumentId::parse(input)?;
            Ok((
                input,
                Message::Request(request_id, super::Request::CreateSnapshot { root_doc }),
            ))
        }),
        RequestType::SnapshotSymbols => input.with_context("SnapshotSymbols", |input| {
            let (input, snapshot_id) = SnapshotId::parse(input)?;
            Ok((
                input,
                Message::Request(request_id, super::Request::SnapshotSymbols { snapshot_id }),
            ))
        }),
        RequestType::Listen => input.with_context("Listen", |input| {
            let (input, snapshot_id) = SnapshotId::parse(input)?;
            Ok((
                input,
                Message::Request(request_id, super::Request::Listen(snapshot_id)),
            ))
        }),
    }
}

fn parse_response(
    input: parse::Input<'_>,
) -> Result<(parse::Input<'_>, Message), parse::ParseError> {
    let (input, request_id) = RequestId::parse(input)?;
    let (input, resp_type) = ResponseType::parse(input)?;
    let (input, resp) = match resp_type {
        ResponseType::UploadCommits => Ok((input, super::Response::UploadCommits)),
        ResponseType::FetchSedimentree => input.with_context("FetchSedimentree", |input| {
            FetchedSedimentree::parse(input)
                .map(|(input, fetched)| (input, super::Response::FetchSedimentree(fetched)))
        }),
        ResponseType::FetchBlobPart => input.with_context("FetchBlobPart", |input| {
            let (input, data) = parse::slice(input)?;
            Ok((input, super::Response::FetchBlobPart(data.to_vec())))
        }),
        ResponseType::Err => input.with_context("Err", |input| {
            let (input, desc) = parse::str(input)?;
            Ok((input, super::Response::Error(desc.to_string())))
        }),
        ResponseType::CreateSnapshot => input.with_context("CreateSnapshot", |input| {
            let (input, snapshot_id) = SnapshotId::parse(input)?;
            let (input, first_symbols) = parse::many(input, CodedDocAndHeadsSymbol::parse)?;
            Ok((
                input,
                super::Response::CreateSnapshot {
                    snapshot_id,
                    first_symbols,
                },
            ))
        }),
        ResponseType::SnapshotSymbols => input.with_context("SnapshotSymbols", |input| {
            let (input, symbols) = parse::many(input, CodedDocAndHeadsSymbol::parse)?;
            Ok((input, super::Response::SnapshotSymbols(symbols)))
        }),
        ResponseType::Listen => Ok((input, super::Response::Listen)),
    }?;
    Ok((input, Message::Response(request_id, resp)))
}

fn parse_commit(input: parse::Input) -> Result<(parse::Input<'_>, Commit), parse::ParseError> {
    input.with_context("Commit", |input| {
        let (input, parents) = parse::many(input, CommitHash::parse)?;
        let (input, hash) = CommitHash::parse(input)?;
        let (input, content) = parse::slice(input)?;
        Ok((input, Commit::new(parents, content.to_vec(), hash)))
    })
}

mod error {
    use crate::parse;

    pub enum DecodeError {
        NotEnoughInput,
        Invalid(String),
    }

    impl From<parse::ParseError> for DecodeError {
        fn from(err: parse::ParseError) -> Self {
            match err {
                parse::ParseError::NotEnoughInput => Self::NotEnoughInput,
                parse::ParseError::Other { .. } => Self::Invalid(err.to_string()),
            }
        }
    }

    impl std::error::Error for DecodeError {}

    impl std::fmt::Display for DecodeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotEnoughInput => write!(f, "Not enough input"),
                Self::Invalid(err) => write!(f, "Invalid input: {}", err),
            }
        }
    }

    impl std::fmt::Debug for DecodeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotEnoughInput => write!(f, "NotEnoughInput"),
                Self::Invalid(err) => write!(f, "Invalid({})", err),
            }
        }
    }
}
