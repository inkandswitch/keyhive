use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};
use message_types::{NextSyncPhaseType, SessionRequestType};

use crate::{
    riblt::CodedSymbol,
    sync::{server_session::GraphSyncPhase, CgkaSymbol, DocStateHash, MembershipSymbol, SessionId},
    CommitHash, DocumentId,
};

mod message_types;
mod serialization;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum SessionRequest {
    Begin {
        membership_symbols: Vec<CodedSymbol<MembershipSymbol>>,
        doc_symbols: Vec<CodedSymbol<DocStateHash>>,
    },
    Message {
        session_id: SessionId,
        msg: SessionMessage,
    },
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum SessionMessage {
    FetchMembershipSymbols {
        count: u32,
    },
    FetchDocSymbols {
        count: u32,
    },
    FinishMembership {
        local_membership: Vec<CodedSymbol<MembershipSymbol>>,
    },
    FetchMembershipOps(Vec<Digest<StaticEvent<CommitHash>>>),
    UploadMembershipOps(Vec<StaticEvent<CommitHash>>),
    FetchCgkaSymbols {
        doc: DocumentId,
        count: u32,
    },
    FetchCgkaOps(DocumentId, Vec<Digest<Signed<CgkaOperation>>>),
}

impl std::fmt::Debug for SessionMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FetchMembershipSymbols { count } => {
                write!(f, "FetchMembershipSymbols(count: {})", count)
            }
            Self::FetchDocSymbols { count } => write!(f, "FetchDocSymbols(count: {})", count),
            Self::FinishMembership { .. } => write!(f, "FinishMembership"),
            Self::FetchMembershipOps(_) => write!(f, "FetchMembershipOps"),
            Self::UploadMembershipOps(ops) => write!(f, "UploadMembershipOps(ops: {})", ops.len()),
            Self::FetchCgkaSymbols { doc, count } => {
                write!(f, "FetchCgkaSymbols(doc: {}, count: {})", doc, count)
            }
            Self::FetchCgkaOps(doc_id, _) => write!(f, "FetchCgkaOps(doc_id: {})", doc_id),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum SessionResponse {
    Begin {
        id: SessionId,
        next_phase: NextSyncPhase,
    },
    FetchMembershipSymbols(Vec<CodedSymbol<MembershipSymbol>>),
    FetchDocSymbols(Vec<CodedSymbol<DocStateHash>>),
    FinishMembership(NextSyncPhase),
    UploadMembershipOps,
    FetchMembershipOps(Vec<StaticEvent<CommitHash>>),
    FetchCgkaOps(
        Vec<keyhive_core::crypto::signed::Signed<keyhive_core::cgka::operation::CgkaOperation>>,
    ),
    FetchCgkaSymbols(Vec<CodedSymbol<CgkaSymbol>>),
    Expired,
    Error(String),
}

impl std::fmt::Debug for SessionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionResponse::Begin { id, next_phase } => {
                write!(f, "Begin({:?}, {:?})", id, next_phase)
            }
            SessionResponse::FetchMembershipSymbols(symbols) => {
                write!(f, "FetchMembershipSymbols({} symbols)", symbols.len())
            }
            SessionResponse::FetchDocSymbols(symbols) => {
                write!(f, "FetchDocSymbols({} symbols)", symbols.len())
            }
            SessionResponse::FinishMembership(phase) => {
                write!(f, "FinishMembership({:?})", phase)
            }
            SessionResponse::UploadMembershipOps => {
                write!(f, "UploadMembershipOps")
            }
            SessionResponse::FetchMembershipOps(ops) => {
                write!(f, "FetchMembershipOps({} ops)", ops.len())
            }
            SessionResponse::FetchCgkaOps(ops) => {
                write!(f, "FetchCgkaOps({} ops)", ops.len())
            }
            SessionResponse::FetchCgkaSymbols(symbols) => {
                write!(f, "FetchCgkaSymbols({} symbols)", symbols.len())
            }
            SessionResponse::Expired => {
                write!(f, "Expired")
            }
            SessionResponse::Error(error) => {
                write!(f, "Error({})", error)
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum NextSyncPhase {
    Membership(Vec<CodedSymbol<MembershipSymbol>>),
    Docs(Vec<CodedSymbol<DocStateHash>>),
    Done,
}

impl From<GraphSyncPhase> for NextSyncPhase {
    fn from(phase: GraphSyncPhase) -> Self {
        match phase {
            GraphSyncPhase::Membership(symbols) => NextSyncPhase::Membership(symbols),
            GraphSyncPhase::Docs(symbols) => NextSyncPhase::Docs(symbols),
            GraphSyncPhase::Done => NextSyncPhase::Done,
        }
    }
}

impl std::fmt::Debug for NextSyncPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextSyncPhase::Membership(symbols) => {
                write!(f, "Membership({} symbols)", symbols.len())
            }
            NextSyncPhase::Docs(symbols) => {
                write!(f, "Docs({} symbols)", symbols.len())
            }
            NextSyncPhase::Done => {
                write!(f, "Done")
            }
        }
    }
}
