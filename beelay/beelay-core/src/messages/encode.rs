use crate::{leb128::encode_uleb128, messages::Request, RequestId, Response};

use super::{
    encoding_types::{MessageType, RequestType, ResponseType},
    Message,
};

pub(super) fn encode(payload: &super::Payload) -> Vec<u8> {
    let mut buf = Vec::new();
    match &payload.0 {
        Message::Request(id, req) => encode_request(&mut buf, *id, req),
        Message::Response(id, res) => encode_response(&mut buf, *id, res),
        Message::Notification(notification) => {
            buf.push(MessageType::Notification.into());
            notification.encode(&mut buf);
        }
    }
    buf
}

fn encode_request(buf: &mut Vec<u8>, id: RequestId, req: &Request) {
    buf.push(MessageType::Request.into());
    buf.extend_from_slice(id.as_bytes());

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
            doc.encode(buf);
            category.encode(buf);
            encode_uleb128(buf, data.len() as u64);
            for datum in data {
                datum.encode(buf);
            }
        }
        Request::FetchSedimentree(doc_id) => {
            buf.push(RequestType::FetchMinimalBundles.into());
            doc_id.encode(buf);
        }
        Request::FetchBlobPart {
            blob,
            offset,
            length,
        } => {
            buf.push(RequestType::FetchBlobPart.into());
            blob.encode(buf);
            encode_uleb128(buf, *offset);
            encode_uleb128(buf, *length);
        }
        Request::CreateSnapshot { root_doc } => {
            buf.push(RequestType::CreateSnapshot.into());
            root_doc.encode(buf);
        }
        Request::SnapshotSymbols { snapshot_id } => {
            buf.push(RequestType::SnapshotSymbols.into());
            snapshot_id.encode(buf);
        }
        Request::Listen(snapshot_id) => {
            buf.push(RequestType::Listen.into());
            snapshot_id.encode(buf);
        }
    }
}

fn encode_response(buf: &mut Vec<u8>, id: RequestId, resp: &Response) {
    buf.push(MessageType::Response.into());
    buf.extend_from_slice(id.as_bytes());

    match &resp {
        Response::UploadCommits => {
            buf.push(ResponseType::UploadCommits.into());
        }
        Response::FetchSedimentree(fetched) => {
            buf.push(ResponseType::FetchSedimentree.into());
            fetched.encode(buf);
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
                symbol.encode(buf);
            }
        }
        Response::SnapshotSymbols(symbols) => {
            buf.push(ResponseType::SnapshotSymbols.into());
            encode_uleb128(buf, symbols.len() as u64);
            for symbol in symbols {
                symbol.encode(buf);
            }
        }
        Response::Error(desc) => {
            buf.push(ResponseType::Err.into());
            encode_uleb128(buf, desc.len() as u64);
            buf.extend_from_slice(desc.as_bytes());
        }
        Response::Listen => {
            buf.push(ResponseType::Listen.into());
        }
    }
}
