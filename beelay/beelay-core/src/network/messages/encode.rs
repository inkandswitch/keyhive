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
        Request::UploadCommits { doc, data } => {
            buf.push(RequestType::UploadCommits.into());
            doc.encode_into(buf);
            encode_uleb128(buf, data.len() as u64);
            for datum in data {
                datum.encode_into(buf);
            }
        }
        Request::FetchSedimentree(doc_id) => {
            buf.push(RequestType::FetchMinimalBundles.into());
            doc_id.encode_into(buf);
        }
        Request::FetchBlob { doc_id, blob } => {
            buf.push(RequestType::FetchBlob.into());
            doc_id.encode_into(buf);
            blob.encode_into(buf);
        }
        Request::Ping => {
            buf.push(RequestType::Ping.into());
        }
        Request::BeginSync => buf.push(RequestType::BeginSync.into()),
        Request::FetchMembershipSymbols {
            session_id,
            count,
            offset,
        } => {
            buf.push(RequestType::FetchMembershipSymbols.into());
            session_id.encode_into(buf);
            encode_uleb128(buf, *count as u64);
            encode_uleb128(buf, *offset as u64);
        }
        Request::DownloadMembershipOps {
            session_id,
            op_hashes,
        } => {
            buf.push(RequestType::DownloadMembershipOps.into());
            session_id.encode_into(buf);
            op_hashes.encode_into(buf);
        }
        Request::UploadMembershipOps { session_id, ops } => {
            buf.push(RequestType::UploadMembershipOps.into());
            session_id.encode_into(buf);
            ops.encode_into(buf);
        }
        Request::FetchCgkaSymbols {
            session_id,
            doc_id,
            count,
            offset,
        } => {
            buf.push(RequestType::FetchCgkaSymbols.into());
            session_id.encode_into(buf);
            doc_id.encode_into(buf);
            encode_uleb128(buf, *count as u64);
            encode_uleb128(buf, *offset as u64);
        }
        Request::DownloadCgkaOps {
            session_id,
            doc_id,
            op_hashes,
        } => {
            buf.push(RequestType::DownloadCgkaOps.into());
            session_id.encode_into(buf);
            doc_id.encode_into(buf);
            op_hashes.encode_into(buf);
        }
        Request::UploadCgkaOps { session_id, ops } => {
            buf.push(RequestType::UploadCgkaOps.into());
            session_id.encode_into(buf);
            ops.encode_into(buf);
        }
        Request::FetchDocStateSymbols {
            session_id,
            count,
            offset,
        } => {
            buf.push(RequestType::FetchDocStateSymbols.into());
            session_id.encode_into(buf);
            encode_uleb128(buf, *count as u64);
            encode_uleb128(buf, *offset as u64);
        }
    }
}

pub(crate) fn encode_response(buf: &mut Vec<u8>, resp: &Response) {
    match &resp {
        Response::UploadCommits => {
            buf.push(ResponseType::UploadCommits.into());
        }
        Response::UploadBlob => {
            buf.push(ResponseType::UploadBlob.into());
        }
        Response::FetchSedimentree(fetched) => {
            buf.push(ResponseType::FetchSedimentree.into());
            fetched.encode_into(buf);
        }
        Response::FetchBlob(data) => {
            buf.push(ResponseType::FetchBlob.into());
            if let Some(data) = data {
                buf.push(1);
                encode_uleb128(buf, data.len() as u64);
                buf.extend_from_slice(data);
            } else {
                buf.push(0);
            }
        }
        Response::Error(desc) => {
            buf.push(ResponseType::Err.into());
            encode_uleb128(buf, desc.len() as u64);
            buf.extend_from_slice(desc.as_bytes());
        }
        Response::Pong => buf.push(ResponseType::Pong.into()),
        Response::AuthenticationFailed => {
            buf.push(ResponseType::AuthenticationFailed.into());
        }
        Response::AuthorizationFailed => {
            buf.push(ResponseType::AuthorizationFailed.into());
        }
        Response::BeginSync {
            session_id,
            first_symbols,
        } => {
            buf.push(ResponseType::BeginSync.into());
            session_id.encode_into(buf);
            first_symbols.encode_into(buf);
        }
        Response::FetchMembershipSymbols(symbols) => {
            buf.push(ResponseType::FetchMembershipSymbols.into());
            symbols.encode_into(buf);
        }
        Response::DownloadMembershipOps(ops) => {
            buf.push(ResponseType::DownloadMembershipOps.into());
            ops.encode_into(buf);
        }
        Response::UploadMembershipOps => {
            buf.push(ResponseType::UploadMembershipOps.into());
        }
        Response::FetchCgkaSymbols(symbols) => {
            buf.push(ResponseType::FetchCgkaSymbols.into());
            symbols.encode_into(buf);
        }
        Response::DownloadCgkaOps(ops) => {
            buf.push(ResponseType::DownloadCgkaOps.into());
            ops.encode_into(buf);
        }
        Response::UploadCgkaOps => {
            buf.push(ResponseType::UploadCgkaOps.into());
        }
        Response::FetchDocStateSymbols(symbols) => {
            buf.push(ResponseType::FetchDocStateSymbols.into());
            symbols.encode_into(buf);
        }
    }
}
