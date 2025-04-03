use keyhive_core::{
    cgka::operation::CgkaOperation, crypto::signed::Signed, event::static_event::StaticEvent,
};

use crate::{
    serialization::{parse, Parse},
    BlobHash, CommitHash, DocumentId,
};

use super::{
    encoding_types::{RequestType, ResponseType},
    FetchedSedimentree, UploadItem,
};

pub(super) fn parse_request(
    input: parse::Input<'_>,
) -> Result<(parse::Input<'_>, super::Request), parse::ParseError> {
    let (input, req_type) = RequestType::parse(input)?;
    match req_type {
        RequestType::UploadCommits => input.parse_in_ctx("UploadCommits", |input| {
            let (input, doc) = DocumentId::parse_in_ctx("doc", input)?;
            let (input, data) = Vec::<UploadItem>::parse_in_ctx("data", input)?;
            Ok((input, super::Request::UploadCommits { doc, data }))
        }),
        RequestType::FetchMinimalBundles => input.parse_in_ctx("FetchMinimalBundles", |input| {
            let (input, doc_id) = DocumentId::parse_in_ctx("doc_id", input)?;
            Ok((input, super::Request::FetchSedimentree(doc_id)))
        }),
        RequestType::FetchBlob => input.parse_in_ctx("FetchBlob", |input| {
            let (input, doc_id) = DocumentId::parse_in_ctx("doc_id", input)?;
            let (input, blob) = BlobHash::parse_in_ctx("blob_hash", input)?;
            Ok((input, super::Request::FetchBlob { doc_id, blob }))
        }),
        RequestType::UploadBlob => input.parse_in_ctx("UploadBlob", |input| {
            let (input, data) = input.parse_in_ctx("data", parse::slice)?;
            Ok((input, super::Request::UploadBlob(data.to_vec())))
        }),
        RequestType::Ping => Ok((input, super::Request::Ping)),
        RequestType::Session => {
            let (input, req) = super::session::SessionRequest::parse(input)?;
            Ok((input, super::Request::Session(req)))
        }
        RequestType::SyncNeeded => Ok((input, super::Request::SyncNeeded)),
        RequestType::UploadMembershipOps => input.parse_in_ctx("UploadMembershipOps", |input| {
            let (input, ops) = Vec::<StaticEvent<CommitHash>>::parse(input)?;
            Ok((input, super::Request::UploadMembershipOps { ops }))
        }),
        RequestType::UploadCgkaOps => input.parse_in_ctx("UploadCgkaOps", |input| {
            let (input, ops) = Vec::<Signed<CgkaOperation>>::parse(input)?;
            Ok((input, super::Request::UploadCgkaOps { ops }))
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
        ResponseType::FetchBlob => input.parse_in_ctx("FetchBlob", |input| {
            let (input, is_present) = parse::u8(input)?;
            let (input, data) = if is_present != 0 {
                let (input, data) = input.parse_in_ctx("data", parse::slice)?;
                (input, Some(data))
            } else {
                (input, None)
            };
            Ok((input, super::Response::FetchBlob(data.map(Vec::from))))
        }),
        ResponseType::Err => input.parse_in_ctx("Err", |input| {
            let (input, desc) = input.parse_in_ctx("description", parse::str)?;
            Ok((input, super::Response::Error(desc.to_string())))
        }),
        ResponseType::Pong => Ok((input, super::Response::Pong)),
        ResponseType::AuthenticationFailed => Ok((input, super::Response::AuthenticationFailed)),
        ResponseType::AuthorizationFailed => Ok((input, super::Response::AuthorizationFailed)),
        ResponseType::Session => {
            let (input, resp) = super::session::SessionResponse::parse(input)?;
            Ok((input, super::Response::Session(resp)))
        }
        ResponseType::SyncNeeded => Ok((input, super::Response::SyncNeeded)),
        ResponseType::UploadMembershipOps => Ok((input, super::Response::UploadMembershipOps)),
        ResponseType::UploadCgkaOps => Ok((input, super::Response::UploadCgkaOps)),
        ResponseType::UploadBlob => Ok((input, super::Response::UploadBlob)),
    }?;
    Ok((input, resp))
}
