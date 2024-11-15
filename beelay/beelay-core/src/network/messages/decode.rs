use ed25519_dalek::VerifyingKey;
use keyhive_core::{
    event::StaticEvent, principal::group::membership_operation::StaticMembershipOperation,
};

use crate::{
    keyhive_sync::{self, OpHash},
    serialization::{leb128, parse, Parse},
    BlobHash, CommitCategory, CommitHash, DocumentId, SnapshotId,
};

use super::{
    encoding_types::{RequestType, ResponseType},
    riblt, FetchedSedimentree, Notification, UploadItem,
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
            let (input, offset) = input.parse_in_ctx("offset", leb128::parse)?;
            let (input, length) = input.parse_in_ctx("length", leb128::parse)?;
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
        RequestType::BeginAuthSync => Ok((input, super::Request::BeginAuthSync)),
        RequestType::KeyhiveSymbols => input.parse_in_ctx("KeyhiveSymbols", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session_id", keyhive_sync::KeyhiveSyncId::parse)?;
            Ok((input, super::Request::KeyhiveSymbols { session_id }))
        }),
        RequestType::RequestKeyhiveOps => input.parse_in_ctx("RequestKeyhiveOps", |input| {
            let (input, session) =
                input.parse_in_ctx("session_id", keyhive_sync::KeyhiveSyncId::parse)?;
            let (input, op_hashes) = input.parse_in_ctx("ops", Vec::<OpHash>::parse)?;
            Ok((
                input,
                super::Request::RequestKeyhiveOps { session, op_hashes },
            ))
        }),
        RequestType::UploadKeyhiveOps => input.parse_in_ctx("UploadKeyhiveOps", |input| {
            let (input, source_session) =
                input.parse_in_ctx("source_session", keyhive_sync::KeyhiveSyncId::parse)?;
            let (input, ops) =
                input.parse_in_ctx("ops", Vec::<StaticMembershipOperation<CommitHash>>::parse)?;
            Ok((
                input,
                super::Request::UploadKeyhiveOps {
                    source_session,
                    ops,
                },
            ))
        }),
        RequestType::Ping => Ok((input, super::Request::Ping)),
        RequestType::RequestKeyhiveOpsForAgent => {
            let (input, key_bytes) = parse::arr::<32>(input)?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_e| input.error("failed to parse key"))?;
            let (input, sync_id) = keyhive_sync::KeyhiveSyncId::parse(input)?;
            Ok((
                input,
                super::Request::RequestKeyhiveOpsForAgent {
                    agent: key.into(),
                    sync_id,
                },
            ))
        }
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
            let (input, first_symbols) = Vec::<
                riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>,
            >::parse_in_ctx("first_symbols", input)?;
            Ok((
                input,
                super::Response::CreateSnapshot {
                    snapshot_id,
                    first_symbols,
                },
            ))
        }),
        ResponseType::SnapshotSymbols => input.parse_in_ctx("SnapshotSymbols", |input| {
            let (input, symbols) = Vec::<
                riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>,
            >::parse_in_ctx("symbols", input)?;
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
        ResponseType::BeginAuthSync => input.parse_in_ctx("BeginAuthSync", |input| {
            let (input, session_id) =
                input.parse_in_ctx("session", keyhive_sync::KeyhiveSyncId::parse)?;
            let (input, first_symbols) =
                input.parse_in_ctx("first_symbols", Vec::<riblt::CodedSymbol<OpHash>>::parse)?;
            Ok((
                input,
                super::Response::BeginAuthSync {
                    session_id,
                    first_symbols,
                },
            ))
        }),
        ResponseType::KeyhiveSymbols => input.parse_in_ctx("KeyhiveSymbols", |input| {
            let (input, symbols) =
                Vec::<riblt::CodedSymbol<OpHash>>::parse_in_ctx("symbols", input)?;
            Ok((input, super::Response::KeyhiveSymbols(symbols)))
        }),
        ResponseType::RequestKeyhiveOps => input.parse_in_ctx("RequestKeyhiveOps", |input| {
            let (input, ops) = Vec::<keyhive_sync::KeyhiveOp>::parse_in_ctx("ops", input)?;
            Ok((input, super::Response::RequestKeyhiveOps(ops)))
        }),
        ResponseType::UploadKeyhiveOps => input.parse_in_ctx("UploadKeyhiveOps", |input| {
            Ok((input, super::Response::UploadKeyhiveOps))
        }),
        ResponseType::Pong => Ok((input, super::Response::Pong)),
        ResponseType::RequestKeyhiveOpsForAgent => {
            input.parse_in_ctx("RequestKeyhiveOpsForAgent", |input| {
                let (input, ops) = Vec::<StaticEvent<CommitHash>>::parse_in_ctx("ops", input)?;
                Ok((input, super::Response::RequestKeyhiveOpsForAgent(ops)))
            })
        }
        ResponseType::AuthenticationFailed => Ok((input, super::Response::AuthenticationFailed)),
        ResponseType::AuthorizationFailed => Ok((input, super::Response::AuthorizationFailed)),
    }?;
    Ok((input, resp))
}
