use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};

use crate::{
    serialization::{leb128, parse, Parse},
    BlobHash, CommitHash, DocumentId,
};

use super::{
    encoding_types::{RequestType, ResponseType},
    riblt, FetchedSedimentree, SessionResponse, UploadItem,
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
        RequestType::BeginSync => {
            input.parse_in_ctx("BeginSync", |input| Ok((input, super::Request::BeginSync)))
        }
        RequestType::FetchMembershipSymbols => {
            input.parse_in_ctx("FetchMembershipSymbols", |input| {
                let (input, session_id) =
                    input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
                let (input, count) = input.parse_in_ctx("count", leb128::parse)?;
                let (input, offset) = input.parse_in_ctx("offset", leb128::parse)?;
                Ok((
                    input,
                    super::Request::FetchMembershipSymbols {
                        session_id,
                        count: count as usize,
                        offset: offset as usize,
                    },
                ))
            })
        }
        RequestType::DownloadMembershipOps => {
            input.parse_in_ctx("DownloadMembershipOps", |input| {
                let (input, session_id) =
                    input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
                let (input, op_hashes) = Vec::<Digest<StaticEvent<CommitHash>>>::parse(input)?;
                Ok((
                    input,
                    super::Request::DownloadMembershipOps {
                        session_id,
                        op_hashes,
                    },
                ))
            })
        }
        RequestType::UploadMembershipOps => input.parse_in_ctx("UploadMembershipOps", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
            let (input, ops) = Vec::<StaticEvent<CommitHash>>::parse(input)?;
            Ok((
                input,
                super::Request::UploadMembershipOps { session_id, ops },
            ))
        }),
        RequestType::FetchCgkaSymbols => input.parse_in_ctx("FetchCgkaSymbols", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
            let (input, doc_id) = DocumentId::parse_in_ctx("doc_id", input)?;
            let (input, count) = input.parse_in_ctx("count", leb128::parse)?;
            let (input, offset) = input.parse_in_ctx("offset", leb128::parse)?;
            Ok((
                input,
                super::Request::FetchCgkaSymbols {
                    session_id,
                    doc_id,
                    count: count as usize,
                    offset: offset as usize,
                },
            ))
        }),
        RequestType::DownloadCgkaOps => input.parse_in_ctx("DownloadCgkaOps", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
            let (input, doc_id) = DocumentId::parse_in_ctx("doc_id", input)?;
            let (input, op_hashes) = Vec::<
                keyhive_core::crypto::digest::Digest<
                    keyhive_core::crypto::signed::Signed<
                        keyhive_core::cgka::operation::CgkaOperation,
                    >,
                >,
            >::parse(input)?;
            Ok((
                input,
                super::Request::DownloadCgkaOps {
                    session_id,
                    doc_id,
                    op_hashes,
                },
            ))
        }),
        RequestType::UploadCgkaOps => input.parse_in_ctx("UploadCgkaOps", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
            let (input, ops) = Vec::<Signed<CgkaOperation>>::parse(input)?;
            Ok((input, super::Request::UploadCgkaOps { session_id, ops }))
        }),
        RequestType::FetchDocStateSymbols => input.parse_in_ctx("FetchDocStateSymbols", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
            let (input, count) = input.parse_in_ctx("count", leb128::parse)?;
            let (input, offset) = input.parse_in_ctx("offset", leb128::parse)?;
            Ok((
                input,
                super::Request::FetchDocStateSymbols {
                    session_id,
                    count: count as usize,
                    offset: offset as usize,
                },
            ))
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
        ResponseType::BeginSync => input.parse_in_ctx("BeginSync", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", crate::sync::SessionId::parse)?;
            let (input, first_symbols) = input.parse_in_ctx(
                "first_symbols",
                Vec::<riblt::CodedSymbol<crate::sync::MembershipSymbol>>::parse,
            )?;
            Ok((
                input,
                super::Response::BeginSync {
                    session_id,
                    first_symbols,
                },
            ))
        }),
        ResponseType::FetchMembershipSymbols => {
            input.parse_in_ctx("FetchMembershipSymbols", |input| {
                let (input, symbols) = SessionResponse::<
                    Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>,
                >::parse(input)?;
                Ok((input, super::Response::FetchMembershipSymbols(symbols)))
            })
        }
        ResponseType::DownloadMembershipOps => {
            input.parse_in_ctx("DownloadMembershipOps", |input| {
                let (input, ops) = SessionResponse::<Vec<StaticEvent<CommitHash>>>::parse(input)?;
                Ok((input, super::Response::DownloadMembershipOps(ops)))
            })
        }
        ResponseType::UploadMembershipOps => Ok((input, super::Response::UploadMembershipOps)),
        ResponseType::FetchCgkaSymbols => input.parse_in_ctx("FetchCgkaSymbols", |input| {
            let (input, symbols) =
                SessionResponse::<Vec<riblt::CodedSymbol<crate::sync::CgkaSymbol>>>::parse(input)?;
            Ok((input, super::Response::FetchCgkaSymbols(symbols)))
        }),
        ResponseType::DownloadCgkaOps => input.parse_in_ctx("DownloadCgkaOps", |input| {
            let (input, ops) = SessionResponse::<
                Vec<
                    keyhive_core::crypto::signed::Signed<
                        keyhive_core::cgka::operation::CgkaOperation,
                    >,
                >,
            >::parse(input)?;
            Ok((input, super::Response::DownloadCgkaOps(ops)))
        }),
        ResponseType::UploadCgkaOps => Ok((input, super::Response::UploadCgkaOps)),
        ResponseType::FetchDocStateSymbols => input.parse_in_ctx("FetchDocStateSymbols", |input| {
            let (input, symbols) = SessionResponse::<
                Vec<riblt::CodedSymbol<crate::sync::DocStateHash>>,
            >::parse(input)?;
            Ok((input, super::Response::FetchDocStateSymbols(symbols)))
        }),
        ResponseType::UploadBlob => Ok((input, super::Response::UploadBlob)),
    }?;
    Ok((input, resp))
}
