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
        Request::Session(session_req) => {
            buf.push(RequestType::Session.into());
            session_req.encode_into(buf);
        }
        Request::SyncNeeded => {
            buf.push(RequestType::SyncNeeded.into());
        }
        Request::UploadMembershipOps { ops } => {
            buf.push(RequestType::UploadMembershipOps.into());
            ops.encode_into(buf);
        }
        Request::UploadCgkaOps { ops } => {
            buf.push(RequestType::UploadCgkaOps.into());
            ops.encode_into(buf);
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
        Response::Session(session_resp) => {
            buf.push(ResponseType::Session.into());
            session_resp.encode_into(buf);
        }
        Response::SyncNeeded => buf.push(ResponseType::SyncNeeded.into()),
        Response::UploadMembershipOps => {
            buf.push(ResponseType::UploadMembershipOps.into());
        }
        Response::UploadCgkaOps => {
            buf.push(ResponseType::UploadCgkaOps.into());
        }
    }
}
