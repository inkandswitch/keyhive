use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
    principal::group::membership_operation::StaticMembershipOperation,
};

use crate::{
    riblt,
    sedimentree::{self, SedimentreeSummary},
    serialization::{leb128::encode_uleb128, parse, Encode, Parse},
    BlobHash, CommitHash, DocumentId,
};

mod decode;
mod encode;
mod encoding_types;
mod session_response;
pub(crate) use session_response::SessionResponse;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Response {
    Error(String),
    UploadCommits,
    UploadBlob,
    FetchSedimentree(FetchedSedimentree),
    FetchBlob(Option<Vec<u8>>),
    Pong,
    AuthenticationFailed,
    AuthorizationFailed,
    BeginSync {
        session_id: crate::sync::SessionId,
        first_symbols: Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>,
    },
    FetchMembershipSymbols(SessionResponse<Vec<riblt::CodedSymbol<crate::sync::MembershipSymbol>>>),
    DownloadMembershipOps(SessionResponse<Vec<StaticEvent<CommitHash>>>),
    UploadMembershipOps,
    FetchCgkaSymbols(SessionResponse<Vec<riblt::CodedSymbol<crate::sync::CgkaSymbol>>>),
    DownloadCgkaOps(
        SessionResponse<
            Vec<keyhive_core::crypto::signed::Signed<keyhive_core::cgka::operation::CgkaOperation>>,
        >,
    ),
    UploadCgkaOps,
    FetchDocStateSymbols(SessionResponse<Vec<riblt::CodedSymbol<crate::sync::DocStateHash>>>),
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
            Response::UploadBlob => write!(f, "UploadBlob"),
            Response::FetchSedimentree(r) => write!(f, "FetchSedimentree({:?})", r),
            Response::FetchBlob(b) => {
                write!(f, "FetchBlob(")?;
                if let Some(blob) = b {
                    write!(f, "{} bytes", blob.len())?;
                } else {
                    write!(f, "None")?;
                }
                write!(f, ")")
            }
            Response::Pong => write!(f, "Pong"),
            Response::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Response::AuthorizationFailed => write!(f, "AuthorizationFailed"),
            Response::BeginSync {
                session_id,
                first_symbols,
            } => {
                write!(
                    f,
                    "BeginSync(session_id: {:?}, first_symbols: ({} symbols))",
                    session_id,
                    first_symbols.len()
                )
            }
            Response::FetchMembershipSymbols(s) => {
                write!(f, "FetchMembershipSymbols(")?;
                s.fmt_contents(f, |f, contents| write!(f, "{} symbols", contents.len()))?;
                write!(f, ")")
            }
            Response::DownloadMembershipOps(ops) => {
                write!(f, "DownloadMembershipOps(")?;
                ops.fmt_contents(f, |f, contents| write!(f, "{} ops", contents.len()))?;
                write!(f, ")")
            }
            Response::UploadMembershipOps => write!(f, "UploadMembershipOps"),
            Response::FetchCgkaSymbols(s) => {
                write!(f, "FetchCgkaSymbols(")?;
                s.fmt_contents(f, |f, contents| write!(f, "{} symbols", contents.len()))?;
                write!(f, ")")
            }
            Response::DownloadCgkaOps(ops) => {
                write!(f, "DownloadCgkaOps(")?;
                ops.fmt_contents(f, |f, contents| write!(f, "{} ops", contents.len()))?;
                write!(f, ")")
            }
            Response::UploadCgkaOps => write!(f, "UploadCgkaOps"),
            Response::FetchDocStateSymbols(s) => {
                write!(f, "FetchDocStateSymbols(")?;
                s.fmt_contents(f, |f, contents| write!(f, "{} symbols", contents.len()))?;
                write!(f, ")")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[derive(serde::Serialize)]
pub(crate) enum FetchedSedimentree {
    NotFound,
    Found(SedimentreeSummary),
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
                    Ok((input, FetchedSedimentree::Found(content_bundles)))
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
            FetchedSedimentree::Found(content) => {
                out.push(1);
                content.encode_into(out);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum Request {
    UploadBlob(Vec<u8>),
    UploadCommits {
        doc: DocumentId,
        data: Vec<UploadItem>,
    },
    FetchSedimentree(DocumentId),
    FetchBlob {
        doc_id: DocumentId,
        blob: crate::BlobHash,
    },
    Ping,
    BeginSync,
    FetchMembershipSymbols {
        session_id: crate::sync::SessionId,
        count: usize,
        offset: usize,
    },
    DownloadMembershipOps {
        session_id: crate::sync::SessionId,
        op_hashes: Vec<Digest<StaticEvent<CommitHash>>>,
    },
    UploadMembershipOps {
        session_id: crate::sync::SessionId,
        ops: Vec<StaticEvent<CommitHash>>,
    },
    FetchCgkaSymbols {
        session_id: crate::sync::SessionId,
        doc_id: DocumentId,
        count: usize,
        offset: usize,
    },
    DownloadCgkaOps {
        session_id: crate::sync::SessionId,
        doc_id: DocumentId,
        op_hashes: Vec<
            keyhive_core::crypto::digest::Digest<
                keyhive_core::crypto::signed::Signed<keyhive_core::cgka::operation::CgkaOperation>,
            >,
        >,
    },
    UploadCgkaOps {
        session_id: crate::sync::SessionId,
        ops:
            Vec<keyhive_core::crypto::signed::Signed<keyhive_core::cgka::operation::CgkaOperation>>,
    },
    FetchDocStateSymbols {
        session_id: crate::sync::SessionId,
        count: usize,
        offset: usize,
    },
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
            Request::FetchBlob { doc_id, blob } => write!(f, "FetchBlob({}, {})", doc_id, blob),
            Request::Ping => write!(f, "Ping"),
            Request::BeginSync => write!(f, "BeginSync"),
            Request::FetchMembershipSymbols {
                session_id,
                count,
                offset,
            } => {
                write!(
                    f,
                    "FetchMembershipSymbols({}, {}, {})",
                    session_id, count, offset
                )
            }
            Request::DownloadMembershipOps {
                session_id,
                op_hashes,
            } => {
                write!(
                    f,
                    "DownloadMembershipOps({}, {} hashes)",
                    session_id,
                    op_hashes.len()
                )
            }
            Request::UploadMembershipOps { session_id, ops } => {
                write!(f, "UploadMembershipOps({}, {} ops)", session_id, ops.len())
            }
            Request::FetchCgkaSymbols {
                session_id,
                doc_id,
                count,
                offset,
            } => {
                write!(
                    f,
                    "FetchCgkaSymbols({}, {}, {}, {})",
                    session_id, doc_id, count, offset
                )
            }
            Request::DownloadCgkaOps {
                session_id,
                doc_id,
                op_hashes,
            } => {
                write!(
                    f,
                    "DownloadCgkaOps({}, {}, {} hashes)",
                    session_id,
                    doc_id,
                    op_hashes.len()
                )
            }
            Request::UploadCgkaOps { session_id, ops } => {
                write!(f, "UploadCgkaOps({}, {} ops)", session_id, ops.len())
            }
            Request::FetchDocStateSymbols {
                session_id,
                count,
                offset,
            } => {
                write!(
                    f,
                    "FetchDocStateSymbols({}, {}, {})",
                    session_id, count, offset
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct UploadItem {
    pub(crate) blob: Vec<u8>,
    pub(crate) tree_part: TreePart,
    pub(crate) cgka_op: Option<Signed<CgkaOperation>>,
}

impl UploadItem {
    pub(crate) fn commit(
        commit: &sedimentree::LooseCommit,
        data: Vec<u8>,
        cgka_op: Option<Signed<CgkaOperation>>,
    ) -> Self {
        Self {
            blob: data,
            cgka_op,
            tree_part: TreePart::Commit {
                hash: commit.hash().clone(),
                parents: commit.parents().to_vec(),
            },
        }
    }

    pub(crate) fn stratum(
        stratum: &sedimentree::Stratum,
        data: Vec<u8>,
        cgka_op: Option<Signed<CgkaOperation>>,
    ) -> Self {
        Self {
            blob: data,
            cgka_op,
            tree_part: TreePart::Stratum {
                start: stratum.start().clone(),
                end: stratum.end().clone(),
                checkpoints: stratum.checkpoints().to_vec(),
                hash: stratum.hash().clone(),
            },
        }
    }
}

impl Parse<'_> for UploadItem {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("UploadItem", |input| {
            let (input, blob) = parse::slice(input)?;
            let (input, cgka_op) = Option::<Signed<CgkaOperation>>::parse_in_ctx("cgka_op", input)?;
            let (input, tree_part) = TreePart::parse_in_ctx("tree_part", input)?;
            Ok((
                input,
                UploadItem {
                    blob: blob.to_vec(),
                    cgka_op,
                    tree_part,
                },
            ))
        })
    }
}

impl Encode for UploadItem {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.blob.encode_into(out);
        self.cgka_op.encode_into(out);
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

#[cfg(test)]
mod tests {
    use super::{Request, Response};
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
}
