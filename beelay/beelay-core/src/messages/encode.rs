use crate::{deser::Encode, leb128::encode_uleb128, messages::Request, Response};

use super::encoding_types::{RequestType, ResponseType};

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
            encode_uleb128(buf, notifications.len() as u64);
            for notification in notifications {
                notification.encode_into(buf);
            }
            encode_uleb128(buf, *remote_offset);
        }
    }
}
