use crate::{
    deser::Parse, leb128, parse, riblt::doc_and_heads::CodedDocAndHeadsSymbol, BlobHash,
    CommitCategory, DocumentId, SnapshotId,
};

use super::{
    encoding_types::{RequestType, ResponseType},
    FetchedSedimentree, Notification, UploadItem,
};

pub(super) fn parse_request(
    input: parse::Input<'_>,
) -> Result<(parse::Input<'_>, super::Request), parse::ParseError> {
    let (input, req_type) = RequestType::parse(input)?;
    match req_type {
        RequestType::UploadCommits => input.parse_in_ctx("UploadCommits", |input| {
            let (input, doc) = DocumentId::parse_in_ctx("doc", input)?;
            let (input, category) = CommitCategory::parse_in_ctx("category", input)?;
            let (input, data) = Vec::<UploadItem>::parse_in_ctx("data", input)?;
            Ok((
                input,
                super::Request::UploadCommits {
                    doc,
                    data,
                    category,
                },
            ))
        }),
        RequestType::FetchMinimalBundles => input.parse_in_ctx("FetchMinimalBundles", |input| {
            let (input, doc_id) = DocumentId::parse_in_ctx("doc_id", input)?;
            Ok((input, super::Request::FetchSedimentree(doc_id)))
        }),
        RequestType::FetchBlobPart => input.parse_in_ctx("FetchBlobPart", |input| {
            let (input, blob) = BlobHash::parse_in_ctx("blob", input)?;
            let (input, offset) = input.parse_in_ctx("offset", crate::leb128::parse)?;
            let (input, length) = input.parse_in_ctx("length", crate::leb128::parse)?;
            Ok((
                input,
                super::Request::FetchBlobPart {
                    blob,
                    offset,
                    length,
                },
            ))
        }),
        RequestType::UploadBlob => input.parse_in_ctx("UploadBlob", |input| {
            let (input, data) = input.parse_in_ctx("data", parse::slice)?;
            Ok((input, super::Request::UploadBlob(data.to_vec())))
        }),
        RequestType::CreateSnapshot => input.parse_in_ctx("CreateSnapshot", |input| {
            let (input, root_doc) = DocumentId::parse_in_ctx("root_doc", input)?;
            let (input, source_snapshot) = SnapshotId::parse_in_ctx("source_snapshot", input)?;
            Ok((
                input,
                super::Request::CreateSnapshot {
                    root_doc,
                    source_snapshot,
                },
            ))
        }),
        RequestType::SnapshotSymbols => input.parse_in_ctx("SnapshotSymbols", |input| {
            let (input, snapshot_id) = SnapshotId::parse_in_ctx("snapshot_id", input)?;
            Ok((input, super::Request::SnapshotSymbols { snapshot_id }))
        }),
        RequestType::Listen => input.parse_in_ctx("Listen", |input| {
            let (input, snapshot_id) = SnapshotId::parse_in_ctx("snapshot_id", input)?;
            let (input, has_offset) = input.parse_in_ctx("has_offset", parse::bool)?;
            let (input, offset) = if has_offset {
                let (input, offset) = input.parse_in_ctx("offset", leb128::parse)?;
                (input, Some(offset))
            } else {
                (input, None)
            };
            Ok((input, super::Request::Listen(snapshot_id, offset)))
        }),
    }
}

pub(crate) fn parse_response(
    input: parse::Input<'_>,
) -> Result<(parse::Input<'_>, super::Response), parse::ParseError> {
    let (input, resp_type) = input.parse_in_ctx("response_type", ResponseType::parse)?;
    let (input, resp) = match resp_type {
        ResponseType::UploadCommits => Ok((input, super::Response::UploadCommits)),
        ResponseType::FetchSedimentree => input.parse_in_ctx("FetchSedimentree", |input| {
            FetchedSedimentree::parse(input)
                .map(|(input, fetched)| (input, super::Response::FetchSedimentree(fetched)))
        }),
        ResponseType::FetchBlobPart => input.parse_in_ctx("FetchBlobPart", |input| {
            let (input, data) = input.parse_in_ctx("data", parse::slice)?;
            Ok((input, super::Response::FetchBlobPart(data.to_vec())))
        }),
        ResponseType::Err => input.parse_in_ctx("Err", |input| {
            let (input, desc) = input.parse_in_ctx("description", parse::str)?;
            Ok((input, super::Response::Error(desc.to_string())))
        }),
        ResponseType::CreateSnapshot => input.parse_in_ctx("CreateSnapshot", |input| {
            let (input, snapshot_id) = SnapshotId::parse_in_ctx("snapshot_id", input)?;
            let (input, first_symbols) =
                Vec::<CodedDocAndHeadsSymbol>::parse_in_ctx("first_symbols", input)?;
            Ok((
                input,
                super::Response::CreateSnapshot {
                    snapshot_id,
                    first_symbols,
                },
            ))
        }),
        ResponseType::SnapshotSymbols => input.parse_in_ctx("SnapshotSymbols", |input| {
            let (input, symbols) = Vec::<CodedDocAndHeadsSymbol>::parse_in_ctx("symbols", input)?;
            Ok((input, super::Response::SnapshotSymbols(symbols)))
        }),
        ResponseType::Listen => input.parse_in_ctx("Listen", |input| {
            let (input, notifications) = Vec::<Notification>::parse_in_ctx("notifications", input)?;
            let (input, remote_offset) = input.parse_in_ctx("remote_offset", leb128::parse)?;
            Ok((
                input,
                super::Response::Listen {
                    notifications,
                    remote_offset,
                },
            ))
        }),
    }?;
    Ok((input, resp))
}
