use crate::{
    leb128::encode_uleb128, parse, riblt::doc_and_heads::CodedDocAndHeadsSymbol,
    sedimentree::SedimentreeSummary, BlobHash, CommitCategory, CommitHash, DocumentId, PeerId,
    RequestId, SnapshotId,
};

mod decode;
mod encode;
mod encoding_types;
pub use decode::DecodeError;
pub mod stream;

#[derive(Debug)]
pub struct Envelope {
    pub(crate) sender: PeerId,
    pub(crate) recipient: PeerId,
    pub(crate) payload: Payload,
}

impl Envelope {
    pub fn new(sender: PeerId, recipient: PeerId, payload: Payload) -> Self {
        Self {
            sender,
            recipient,
            payload,
        }
    }

    pub fn sender(&self) -> &PeerId {
        &self.sender
    }

    pub fn recipient(&self) -> &PeerId {
        &self.recipient
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub(crate) fn take_payload(self) -> Payload {
        self.payload
    }
}

// A wrapper around the message enum so we can keep Message private
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct Payload(Message);

impl Payload {
    pub(crate) fn new(message: Message) -> Self {
        Self(message)
    }

    pub fn encode(&self) -> Vec<u8> {
        encode::encode(self)
    }

    pub(crate) fn into_message(self) -> Message {
        self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Payload {
    type Error = decode::DecodeError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (msg, _) = decode::decode(bytes)?;
        Ok(msg)
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Message {
    Request(RequestId, Request),
    Response(RequestId, Response),
    Notification(Notification),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Request(id, req) => write!(f, "Request(id={}, {})", id, req),
            Message::Response(id, resp) => write!(f, "Response(id={}, {})", id, resp),
            Message::Notification(notification) => write!(f, "Notification({})", notification),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Response {
    Error(String),
    UploadCommits,
    FetchSedimentree(FetchedSedimentree),
    FetchBlobPart(Vec<u8>),
    CreateSnapshot {
        snapshot_id: SnapshotId,
        first_symbols: Vec<CodedDocAndHeadsSymbol>,
    },
    SnapshotSymbols(Vec<CodedDocAndHeadsSymbol>),
    Listen,
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
            Response::Listen => write!(f, "Listen"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(serde::Serialize)]
pub(crate) enum FetchedSedimentree {
    NotFound,
    Found(ContentAndIndex),
}

impl FetchedSedimentree {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("FetchedSedimentree", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => Ok((input, FetchedSedimentree::NotFound)),
                1 => {
                    let (input, content_bundles) = SedimentreeSummary::parse(input)?;
                    let (input, index_bundles) = SedimentreeSummary::parse(input)?;
                    Ok((
                        input,
                        FetchedSedimentree::Found(ContentAndIndex {
                            index: index_bundles,
                            content: content_bundles,
                        }),
                    ))
                }
                _ => Err(input.error("unknown tag")),
            }
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            FetchedSedimentree::NotFound => {
                out.push(0);
            }
            FetchedSedimentree::Found(ContentAndIndex { content, index }) => {
                out.push(1);
                content.encode(out);
                index.encode(out);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(serde::Serialize)]
pub(crate) struct ContentAndIndex {
    pub(crate) content: SedimentreeSummary,
    pub(crate) index: SedimentreeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(serde::Serialize)]
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
    },
    SnapshotSymbols {
        snapshot_id: SnapshotId,
    },
    Listen(SnapshotId),
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
            Request::CreateSnapshot { root_doc } => {
                write!(f, "CreateSnapshot({})", root_doc)
            }
            Request::SnapshotSymbols { snapshot_id } => {
                write!(f, "SnapshotSymbols({})", snapshot_id)
            }
            Request::Listen(snapshot_id) => write!(f, "Listen({})", snapshot_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct UploadItem {
    pub(crate) blob: BlobRef,
    pub(crate) tree_part: TreePart,
}

impl UploadItem {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, blob) = BlobRef::parse(input)?;
        let (input, tree_part) = TreePart::parse(input)?;
        Ok((input, UploadItem { blob, tree_part }))
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        self.blob.encode(buf);
        self.tree_part.encode(buf);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum TreePart {
    Stratum {
        start: CommitHash,
        end: CommitHash,
        checkpoints: Vec<CommitHash>,
    },
    Commit {
        hash: CommitHash,
        parents: Vec<CommitHash>,
    },
}

impl TreePart {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("TreePart", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => {
                    let (input, start) = CommitHash::parse(input)?;
                    let (input, end) = CommitHash::parse(input)?;
                    let (input, checkpoints) = parse::many(input, CommitHash::parse)?;
                    Ok((
                        input,
                        Self::Stratum {
                            start,
                            end,
                            checkpoints,
                        },
                    ))
                }
                1 => {
                    let (input, hash) = CommitHash::parse(input)?;
                    let (input, parents) = parse::many(input, CommitHash::parse)?;
                    Ok((input, Self::Commit { hash, parents }))
                }
                other => Err(input.error(format!("invalid tag: {}", other))),
            }
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            TreePart::Stratum {
                start,
                end,
                checkpoints,
            } => {
                buf.push(0);
                start.encode(buf);
                end.encode(buf);
                encode_uleb128(buf, checkpoints.len() as u64);
                for checkpoint in checkpoints {
                    checkpoint.encode(buf);
                }
            }
            TreePart::Commit { hash, parents } => {
                buf.push(1);
                hash.encode(buf);
                encode_uleb128(buf, parents.len() as u64);
                for parent in parents {
                    parent.encode(buf);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum BlobRef {
    Blob(BlobHash),
    Inline(Vec<u8>),
}

impl BlobRef {
    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("BlobRef", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => {
                    let (input, hash) = BlobHash::parse(input)?;
                    Ok((input, BlobRef::Blob(hash)))
                }
                1 => {
                    let (input, data) = parse::slice(input)?;
                    Ok((input, BlobRef::Inline(data.to_vec())))
                }
                other => Err(input.error(format!("invalid tag: {}", other))),
            }
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            BlobRef::Blob(hash) => {
                out.push(0);
                hash.encode(out);
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
    pub(crate) from_peer: PeerId,
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

impl Notification {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.with_context("Notification", |input| {
            let (input, from_peer) = PeerId::parse(input)?;
            let (input, doc_id) = DocumentId::parse(input)?;
            let (input, data) = UploadItem::parse(input)?;
            Ok((
                input,
                Self {
                    from_peer,
                    doc: doc_id,
                    data,
                },
            ))
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.from_peer.encode(out);
        self.doc.encode(out);
        self.data.encode(out);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn message_encoding_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::Payload>()
            .for_each(|msg| {
                let encoded = super::encode::encode(msg);
                let (decoded, len) = super::decode::decode(&encoded).unwrap();
                assert_eq!(len, encoded.len());
                assert_eq!(msg, &decoded);
            });
    }
}
