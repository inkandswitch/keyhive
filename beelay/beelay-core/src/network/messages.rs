use crate::{
    keyhive_sync, riblt,
    sedimentree::SedimentreeSummary,
    serialization::{leb128::encode_uleb128, parse, Encode, Parse},
    BlobHash, CommitCategory, CommitHash, DocumentId, SnapshotId,
};

mod decode;
mod encode;
mod encoding_types;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Response {
    Error(String),
    UploadCommits,
    FetchSedimentree(FetchedSedimentree),
    FetchBlobPart(Vec<u8>),
    CreateSnapshot {
        snapshot_id: SnapshotId,
        first_symbols: Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>,
    },
    SnapshotSymbols(Vec<riblt::CodedSymbol<riblt::doc_and_heads::DocAndHeadsSymbol>>),
    Listen {
        notifications: Vec<Notification>,
        remote_offset: u64,
    },
    BeginAuthSync {
        session_id: crate::keyhive_sync::KeyhiveSyncId,
        first_symbols: Vec<riblt::CodedSymbol<crate::keyhive_sync::OpHash>>,
    },
    KeyhiveSymbols(Vec<riblt::CodedSymbol<keyhive_sync::OpHash>>),
    RequestKeyhiveOps(Vec<keyhive_core::event::StaticEvent<CommitHash>>),
    UploadKeyhiveOps,
    Pong,
    AuthenticationFailed,
    AuthorizationFailed,
}

impl Parse<'_> for Response {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        decode::parse_response(input)
    }
}

impl Encode for Response {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode::encode_response(out, self);
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Error(desc) => write!(f, "Error({})", desc),
            Response::UploadCommits => write!(f, "UploadCommits"),
            Response::FetchSedimentree(r) => write!(f, "FetchSedimentree({:?})", r),
            Response::FetchBlobPart(_) => write!(f, "FetchBlobPart"),
            Response::CreateSnapshot {
                snapshot_id,
                first_symbols,
            } => {
                write!(
                    f,
                    "CreateSnapshot(snapshot_id: {:?}, first_symbols: ({} symbols))",
                    snapshot_id,
                    first_symbols.len()
                )
            }
            Response::SnapshotSymbols(symbols) => {
                write!(f, "SnapshotSymbols({} symbols)", symbols.len())
            }
            Response::Listen {
                notifications,
                remote_offset,
            } => {
                write!(
                    f,
                    "Listen({} notifications, new_offset={})",
                    notifications.len(),
                    remote_offset
                )
            }
            Response::BeginAuthSync {
                session_id,
                first_symbols,
            } => {
                write!(
                    f,
                    "BeginAuthSync(session_id: {:?}, first_symbols: ({} symbols))",
                    session_id,
                    first_symbols.len()
                )
            }
            Response::KeyhiveSymbols(symbols) => {
                write!(f, "KeyhiveSymbols({} symbols)", symbols.len())
            }
            Response::RequestKeyhiveOps(hashes) => {
                write!(f, "RequestKeyhiveOps({} ops)", hashes.len())
            }
            Response::UploadKeyhiveOps => write!(f, "UploadKeyhiveOps"),
            Response::Pong => write!(f, "Pong"),
            Response::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Response::AuthorizationFailed => write!(f, "AuthorizationFailed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(serde::Serialize)]
pub(crate) enum FetchedSedimentree {
    NotFound,
    Found(ContentAndLinks),
}

impl Parse<'_> for FetchedSedimentree {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("FetchedSedimentree", |input| {
            let (input, tag) = input.parse_in_ctx("tag", parse::u8)?;
            match tag {
                0 => Ok((input, FetchedSedimentree::NotFound)),
                1 => input.parse_in_ctx("Found", |input| {
                    let (input, content_bundles) =
                        input.parse_in_ctx("content", SedimentreeSummary::parse)?;
                    let (input, index_bundles) =
                        input.parse_in_ctx("links", SedimentreeSummary::parse)?;
                    Ok((
                        input,
                        FetchedSedimentree::Found(ContentAndLinks {
                            links: index_bundles,
                            content: content_bundles,
                        }),
                    ))
                }),
                _ => Err(input.error("unknown tag")),
            }
        })
    }
}

impl Encode for FetchedSedimentree {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            FetchedSedimentree::NotFound => {
                out.push(0);
            }
            FetchedSedimentree::Found(ContentAndLinks { content, links }) => {
                out.push(1);
                content.encode_into(out);
                links.encode_into(out);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(serde::Serialize)]
pub(crate) struct ContentAndLinks {
    pub(crate) content: SedimentreeSummary,
    pub(crate) links: SedimentreeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Request {
    UploadBlob(Vec<u8>),
    UploadCommits {
        doc: DocumentId,
        data: Vec<UploadItem>,
        category: CommitCategory,
    },
    FetchSedimentree(DocumentId),
    FetchBlobPart {
        blob: crate::BlobHash,
        offset: u64,
        length: u64,
    },
    CreateSnapshot {
        root_doc: DocumentId,
        source_snapshot: SnapshotId,
    },
    SnapshotSymbols {
        snapshot_id: SnapshotId,
    },
    Listen(SnapshotId, Option<u64>),
    BeginAuthSync {
        additional_peers: Vec<keyhive_core::principal::identifier::Identifier>,
    },
    KeyhiveSymbols {
        session_id: keyhive_sync::KeyhiveSyncId,
    },
    RequestKeyhiveOps {
        session: keyhive_sync::KeyhiveSyncId,
        op_hashes: Vec<keyhive_sync::OpHash>,
    },
    UploadKeyhiveOps {
        source_session: keyhive_sync::KeyhiveSyncId,
        ops: Vec<keyhive_core::event::StaticEvent<CommitHash>>,
    },
    Ping,
}

impl Parse<'_> for Request {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        decode::parse_request(input)
    }
}

impl Encode for Request {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode::encode_request(out, self);
    }
}

impl From<Request> for Vec<u8> {
    fn from(value: Request) -> Self {
        let mut out = Vec::new();
        encode::encode_request(&mut out, &value);
        out
    }
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::UploadBlob(blob) => write!(f, "UploadBlob({} bytes)", blob.len()),
            Request::UploadCommits { .. } => write!(f, "UploadCommits"),
            Request::FetchSedimentree(doc_id) => write!(f, "FetchSedimentree({})", doc_id),
            Request::FetchBlobPart {
                blob,
                offset,
                length,
            } => write!(f, "FetchBlobPart({:?}, {}, {})", blob, offset, length),
            Request::CreateSnapshot {
                root_doc,
                source_snapshot,
            } => {
                write!(
                    f,
                    "CreateSnapshot(root: {}, source: {})",
                    root_doc, source_snapshot
                )
            }
            Request::SnapshotSymbols { snapshot_id } => {
                write!(f, "SnapshotSymbols({})", snapshot_id)
            }
            Request::Listen(snapshot_id, from_offset) => {
                write!(f, "Listen({}, {:?})", snapshot_id, from_offset)
            }
            Request::BeginAuthSync { additional_peers } => write!(
                f,
                "BeginAuthSync {{ additional_peers: {} }}",
                additional_peers
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Request::KeyhiveSymbols { session_id } => {
                write!(f, "KeyhiveSymbols({})", session_id)
            }
            Request::RequestKeyhiveOps { session, op_hashes } => {
                write!(f, "RequestKeyhiveOps({}, {} ops)", session, op_hashes.len())
            }
            Request::UploadKeyhiveOps {
                source_session: _,
                ops,
            } => {
                write!(f, "UploadKeyhiveOps({} ops)", ops.len())
            }
            Request::Ping => write!(f, "Ping"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct UploadItem {
    pub(crate) blob: BlobRef,
    pub(crate) tree_part: TreePart,
}

impl Parse<'_> for UploadItem {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("UploadItem", |input| {
            let (input, blob) = BlobRef::parse_in_ctx("blob", input)?;
            let (input, tree_part) = TreePart::parse_in_ctx("tree_part", input)?;
            Ok((input, UploadItem { blob, tree_part }))
        })
    }
}

impl Encode for UploadItem {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.blob.encode_into(out);
        self.tree_part.encode_into(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum TreePart {
    Stratum {
        start: CommitHash,
        end: CommitHash,
        checkpoints: Vec<CommitHash>,
        hash: CommitHash,
    },
    Commit {
        hash: CommitHash,
        parents: Vec<CommitHash>,
    },
}

impl Encode for TreePart {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            TreePart::Stratum {
                start,
                end,
                checkpoints,
                hash,
            } => {
                out.push(0);
                start.encode_into(out);
                end.encode_into(out);
                checkpoints.encode_into(out);
                hash.encode_into(out);
            }
            TreePart::Commit { hash, parents } => {
                out.push(1);
                hash.encode_into(out);
                parents.encode_into(out);
            }
        }
    }
}

impl Parse<'_> for TreePart {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("TreePart", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => {
                    let (input, start) = input.parse_in_ctx("start", CommitHash::parse)?;
                    let (input, end) = input.parse_in_ctx("end", CommitHash::parse)?;
                    let (input, checkpoints) =
                        input.parse_in_ctx("checkpoints", Vec::<CommitHash>::parse)?;
                    let (input, hash) = input.parse_in_ctx("hash", CommitHash::parse)?;
                    Ok((
                        input,
                        Self::Stratum {
                            start,
                            end,
                            checkpoints,
                            hash,
                        },
                    ))
                }
                1 => {
                    let (input, hash) = input.parse_in_ctx("hash", CommitHash::parse)?;
                    let (input, parents) =
                        input.parse_in_ctx("parents", Vec::<CommitHash>::parse)?;
                    Ok((input, Self::Commit { hash, parents }))
                }
                other => Err(input.error(format!("invalid tag: {}", other))),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum BlobRef {
    Blob(BlobHash),
    Inline(Vec<u8>),
}

impl Parse<'_> for BlobRef {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("BlobRef", |input| {
            let (input, tag) = input.parse_in_ctx("tag", parse::u8)?;
            match tag {
                0 => input.parse_in_ctx("Blob", |input| {
                    let (input, hash) = input.parse_in_ctx("hash", BlobHash::parse)?;
                    Ok((input, BlobRef::Blob(hash)))
                }),
                1 => input.parse_in_ctx("Inline", |input| {
                    let (input, data) = input.parse_in_ctx("data", parse::slice)?;
                    Ok((input, BlobRef::Inline(data.to_vec())))
                }),
                other => Err(input.error(format!("invalid tag: {}", other))),
            }
        })
    }
}

impl Encode for BlobRef {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            BlobRef::Blob(hash) => {
                out.push(0);
                hash.encode_into(out);
            }
            BlobRef::Inline(data) => {
                out.push(1);
                encode_uleb128(out, data.len() as u64);
                out.extend(data);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct Notification {
    pub(crate) doc: DocumentId,
    pub(crate) data: UploadItem,
}

impl std::fmt::Display for Notification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.data.tree_part {
            TreePart::Commit { .. } => {
                write!(f, "Notification(doc = {}, type=new commit)", &self.doc)
            }
            TreePart::Stratum { .. } => {
                write!(f, "Notification(doc = {}, type=new stratum)", &self.doc)
            }
        }
    }
}

impl Parse<'_> for Notification {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("Notification", |input| {
            let (input, doc_id) = input.parse_in_ctx("doc_id", DocumentId::parse)?;
            let (input, data) = input.parse_in_ctx("data", UploadItem::parse)?;
            Ok((input, Self { doc: doc_id, data }))
        })
    }
}

impl Encode for Notification {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.doc.encode_into(out);
        self.data.encode_into(out);
    }
}

#[cfg(test)]
mod tests {
    use super::{Notification, Request, Response};
    use crate::serialization::{parse, Encode, Parse};

    #[test]
    fn req_encoding_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::Request>()
            .for_each(|req| {
                let encoded = req.encode();
                let input = parse::Input::new(&encoded);
                let (input, decoded) = Request::parse(input).unwrap();
                assert!(input.is_empty());
                assert_eq!(req, &decoded);
            });
    }

    #[test]
    fn resp_encoding_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::Response>()
            .for_each(|resp| {
                let encoded = resp.encode();
                let input = parse::Input::new(&encoded);
                let (input, decoded) = Response::parse(input).unwrap();
                assert!(input.is_empty());
                assert_eq!(resp, &decoded);
            });
    }

    #[test]
    fn notification_encoding_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::Notification>()
            .for_each(|noti| {
                let encoded = noti.encode();
                let input = parse::Input::new(&encoded);
                let (input, decoded) = Notification::parse(input).unwrap();
                assert!(input.is_empty());
                assert_eq!(noti, &decoded);
            });
    }
}
