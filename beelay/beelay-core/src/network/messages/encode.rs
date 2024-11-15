use crate::{
    serialization::{leb128::encode_uleb128, Encode},
    Response,
};

use super::{
    encoding_types::{RequestType, ResponseType},
    Request,
};

pub(super) fn encode_request(buf: &mut Vec<u8>, req: &Request) {
    match req {
        Request::UploadBlob(blob) => {
            buf.push(RequestType::UploadBlob.into());
            encode_uleb128(buf, blob.len() as u64);
            buf.extend_from_slice(blob);
        }
        Request::UploadCommits {
            doc,
            data,
            category,
        } => {
            buf.push(RequestType::UploadCommits.into());
            doc.encode_into(buf);
            category.encode_into(buf);
            encode_uleb128(buf, data.len() as u64);
            for datum in data {
                datum.encode_into(buf);
            }
        }
        Request::FetchSedimentree(doc_id) => {
            buf.push(RequestType::FetchMinimalBundles.into());
            doc_id.encode_into(buf);
        }
        Request::FetchBlobPart {
            blob,
            offset,
            length,
        } => {
            buf.push(RequestType::FetchBlobPart.into());
            blob.encode_into(buf);
            encode_uleb128(buf, *offset);
            encode_uleb128(buf, *length);
        }
        Request::CreateSnapshot {
            root_doc,
            source_snapshot,
        } => {
            buf.push(RequestType::CreateSnapshot.into());
            root_doc.encode_into(buf);
            source_snapshot.encode_into(buf);
        }
        Request::SnapshotSymbols { snapshot_id } => {
            buf.push(RequestType::SnapshotSymbols.into());
            snapshot_id.encode_into(buf);
        }
        Request::Listen(snapshot_id, remote_offset) => {
            buf.push(RequestType::Listen.into());
            snapshot_id.encode_into(buf);
            if let Some(offset) = remote_offset {
                buf.push(1);
                encode_uleb128(buf, *offset);
            } else {
                buf.push(0);
            }
        }
        Request::BeginAuthSync => {
            buf.push(RequestType::BeginAuthSync.into());
        }
        Request::KeyhiveSymbols { session_id } => {
            buf.push(RequestType::KeyhiveSymbols.into());
            session_id.encode_into(buf);
        }
        Request::RequestKeyhiveOps { session, op_hashes } => {
            buf.push(RequestType::RequestKeyhiveOps.into());
            session.encode_into(buf);
            op_hashes.encode_into(buf);
        }
        Request::UploadKeyhiveOps {
            source_session,
            ops,
        } => {
            buf.push(RequestType::UploadKeyhiveOps.into());
            source_session.encode_into(buf);
            ops.encode_into(buf);
        }
        Request::Ping => {
            buf.push(RequestType::Ping.into());
        }
        Request::RequestKeyhiveOpsForAgent { agent, sync_id } => {
            buf.push(RequestType::RequestKeyhiveOpsForAgent.into());
            buf.extend_from_slice(agent.0.as_bytes());
            sync_id.encode_into(buf);
        }
    }
}

pub(crate) fn encode_response(buf: &mut Vec<u8>, resp: &Response) {
    match &resp {
        Response::UploadCommits => {
            buf.push(ResponseType::UploadCommits.into());
        }
        Response::FetchSedimentree(fetched) => {
            buf.push(ResponseType::FetchSedimentree.into());
            fetched.encode_into(buf);
        }
        Response::FetchBlobPart(data) => {
            buf.push(ResponseType::FetchBlobPart.into());
            encode_uleb128(buf, data.len() as u64);
            buf.extend_from_slice(data);
        }
        Response::CreateSnapshot {
            snapshot_id,
            first_symbols,
        } => {
            buf.push(ResponseType::CreateSnapshot.into());
            buf.extend_from_slice(snapshot_id.as_bytes());
            encode_uleb128(buf, first_symbols.len() as u64);
            for symbol in first_symbols {
                symbol.encode_into(buf);
            }
        }
        Response::SnapshotSymbols(symbols) => {
            buf.push(ResponseType::SnapshotSymbols.into());
            encode_uleb128(buf, symbols.len() as u64);
            for symbol in symbols {
                symbol.encode_into(buf);
            }
        }
        Response::Error(desc) => {
            buf.push(ResponseType::Err.into());
            encode_uleb128(buf, desc.len() as u64);
            buf.extend_from_slice(desc.as_bytes());
        }
        Response::Listen {
            notifications,
            remote_offset,
        } => {
            buf.push(ResponseType::Listen.into());
            notifications.encode_into(buf);
            encode_uleb128(buf, *remote_offset);
        }
        Response::BeginAuthSync {
            session_id,
            first_symbols,
        } => {
            buf.push(ResponseType::BeginAuthSync.into());
            session_id.encode_into(buf);
            first_symbols.encode_into(buf);
        }
        Response::KeyhiveSymbols(symbols) => {
            buf.push(ResponseType::KeyhiveSymbols.into());
            symbols.encode_into(buf);
        }
        Response::RequestKeyhiveOps(ops) => {
            buf.push(ResponseType::RequestKeyhiveOps.into());
            ops.encode_into(buf);
        }
        Response::UploadKeyhiveOps => {
            buf.push(ResponseType::UploadKeyhiveOps.into());
        }
        Response::Pong => buf.push(ResponseType::Pong.into()),
        Response::RequestKeyhiveOpsForAgent(ops) => {
            buf.push(ResponseType::RequestKeyhiveOpsForAgent.into());
            ops.encode_into(buf);
        }
        Response::AuthenticationFailed => {
            buf.push(ResponseType::AuthenticationFailed.into());
        }
        Response::AuthorizationFailed => {
            buf.push(ResponseType::AuthorizationFailed.into());
        }
    }
}
