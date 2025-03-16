use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};

use crate::{
    parse::{self, Parse},
    riblt::CodedSymbol,
    serialization::{leb128, Encode},
    sync::{CgkaSymbol, DocStateHash, MembershipSymbol, SessionId},
    CommitHash, DocumentId,
};

use super::{
    message_types::{SessionMsgType, SessionResponseType},
    NextSyncPhase, NextSyncPhaseType, SessionMessage, SessionRequest, SessionRequestType,
    SessionResponse,
};

impl Encode for NextSyncPhase {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            NextSyncPhase::Membership(symbols) => {
                out.push(NextSyncPhaseType::Membership.into());
                symbols.encode_into(out);
            }
            NextSyncPhase::Docs(symbols) => {
                out.push(NextSyncPhaseType::Docs.into());
                symbols.encode_into(out);
            }
            NextSyncPhase::Done => {
                out.push(NextSyncPhaseType::Done.into());
            }
        }
    }
}

impl<'a> Parse<'a> for NextSyncPhase {
    fn parse(
        input: crate::parse::Input<'a>,
    ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
        input.parse_in_ctx("NextSyncPhase", |input| {
            let (input, tag) = NextSyncPhaseType::parse(input)?;
            match tag {
                NextSyncPhaseType::Membership => {
                    let (input, symbols) = Vec::<CodedSymbol<MembershipSymbol>>::parse(input)?;
                    Ok((input, NextSyncPhase::Membership(symbols)))
                }
                NextSyncPhaseType::Docs => {
                    let (input, symbols) = Vec::<CodedSymbol<DocStateHash>>::parse(input)?;
                    Ok((input, NextSyncPhase::Docs(symbols)))
                }
                NextSyncPhaseType::Done => Ok((input, NextSyncPhase::Done)),
            }
        })
    }
}

impl Encode for SessionRequest {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            SessionRequest::Begin {
                membership_symbols,
                doc_symbols,
            } => {
                out.push(SessionRequestType::Begin.into());
                membership_symbols.encode_into(out);
                doc_symbols.encode_into(out);
            }
            SessionRequest::Message { session_id, msg } => {
                out.push(SessionRequestType::Sync.into());
                session_id.encode_into(out);
                msg.encode_into(out);
            }
        }
    }
}

impl<'a> Parse<'a> for SessionRequest {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("SessionRequest", |input| {
            let (input, tag) = SessionRequestType::parse(input)?;
            match tag {
                SessionRequestType::Begin => {
                    let (input, membership_symbols) =
                        Vec::<CodedSymbol<MembershipSymbol>>::parse(input)?;
                    let (input, doc_symbols) = Vec::<CodedSymbol<DocStateHash>>::parse(input)?;
                    Ok((
                        input,
                        SessionRequest::Begin {
                            membership_symbols,
                            doc_symbols,
                        },
                    ))
                }
                SessionRequestType::Sync => {
                    let (input, session_id) = SessionId::parse(input)?;
                    let (input, msg) = SessionMessage::parse(input)?;
                    Ok((input, SessionRequest::Message { session_id, msg }))
                }
            }
        })
    }
}

impl Encode for SessionMessage {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            SessionMessage::FetchMembershipSymbols { count } => {
                out.push(SessionMsgType::FetchMembershipSymbols.into());
                leb128::encode_uleb128(out, *count as u64);
            }
            SessionMessage::FetchDocSymbols { count } => {
                out.push(SessionMsgType::FetchDocSymbols.into());
                leb128::encode_uleb128(out, *count as u64);
            }
            SessionMessage::UploadMembershipOps(ops) => {
                out.push(SessionMsgType::UploadMembershipOps.into());
                ops.encode_into(out);
            }
            SessionMessage::FetchMembershipOps(ops) => {
                out.push(SessionMsgType::FetchMembershipOps.into());
                ops.encode_into(out);
            }
            SessionMessage::FetchCgkaOps(doc_id, ops) => {
                out.push(SessionMsgType::FetchCgkaOps.into());
                doc_id.encode_into(out);
                ops.encode_into(out);
            }
            SessionMessage::FetchCgkaSymbols { doc, count } => {
                out.push(SessionMsgType::FetchCgkaSymbols.into());
                doc.encode_into(out);
                leb128::encode_uleb128(out, *count as u64);
            }
            SessionMessage::FinishMembership { local_membership } => {
                out.push(SessionMsgType::FinishMembership.into());
                local_membership.encode_into(out);
            }
        }
    }
}

impl<'a> Parse<'a> for SessionMessage {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, tag) = SessionMsgType::parse(input)?;
        match tag {
            SessionMsgType::FetchMembershipSymbols => {
                let (input, count) = leb128::parse(input)?;
                Ok((
                    input,
                    SessionMessage::FetchMembershipSymbols {
                        count: count as u32,
                    },
                ))
            }
            SessionMsgType::FetchDocSymbols => {
                let (input, count) = leb128::parse(input)?;
                Ok((
                    input,
                    SessionMessage::FetchDocSymbols {
                        count: count as u32,
                    },
                ))
            }
            SessionMsgType::FinishMembership => {
                let (input, symbols) = Vec::<CodedSymbol<MembershipSymbol>>::parse(input)?;
                Ok((
                    input,
                    SessionMessage::FinishMembership {
                        local_membership: symbols,
                    },
                ))
            }
            SessionMsgType::FetchMembershipOps => {
                let (input, op_hashes) = Vec::<Digest<StaticEvent<CommitHash>>>::parse(input)?;
                Ok((input, SessionMessage::FetchMembershipOps(op_hashes)))
            }
            SessionMsgType::UploadMembershipOps => {
                let (input, ops) = Vec::<StaticEvent<CommitHash>>::parse(input)?;
                Ok((input, SessionMessage::UploadMembershipOps(ops)))
            }
            SessionMsgType::FetchCgkaOps => {
                let (input, doc_id) = DocumentId::parse(input)?;
                let (input, ops) = Vec::<Digest<Signed<CgkaOperation>>>::parse(input)?;
                Ok((input, SessionMessage::FetchCgkaOps(doc_id, ops)))
            }
            SessionMsgType::FetchCgkaSymbols => {
                let (input, doc) = DocumentId::parse(input)?;
                let (input, count) = leb128::parse(input)?;
                Ok((
                    input,
                    SessionMessage::FetchCgkaSymbols {
                        doc,
                        count: count as u32,
                    },
                ))
            }
        }
    }
}

impl Encode for SessionResponse {
    fn encode_into(&self, output: &mut Vec<u8>) {
        match self {
            SessionResponse::Begin { id, next_phase } => {
                output.push(SessionResponseType::Begin.into());
                id.encode_into(output);
                next_phase.encode_into(output);
            }
            SessionResponse::FetchMembershipSymbols(symbols) => {
                output.push(SessionResponseType::FetchMembershipSymbols.into());
                symbols.encode_into(output);
            }
            SessionResponse::UploadMembershipOps => {
                output.push(SessionResponseType::UploadMembershipOps.into());
            }
            SessionResponse::FetchDocSymbols(symbols) => {
                output.push(SessionResponseType::FetchDocSymbols.into());
                symbols.encode_into(output);
            }
            SessionResponse::FinishMembership(phase) => {
                output.push(SessionResponseType::FinishMembership.into());
                phase.encode_into(output);
            }
            SessionResponse::FetchMembershipOps(ops) => {
                output.push(SessionResponseType::FetchMembershipOps.into());
                ops.encode_into(output);
            }
            SessionResponse::FetchCgkaOps(ops) => {
                output.push(SessionResponseType::FetchCgkaOps.into());
                ops.encode_into(output);
            }
            SessionResponse::FetchCgkaSymbols(symbols) => {
                output.push(SessionResponseType::FetchCgkaSymbols.into());
                symbols.encode_into(output);
            }
            SessionResponse::Expired => {
                output.push(SessionResponseType::Expired.into());
            }
            SessionResponse::Error(msg) => {
                output.push(SessionResponseType::Error.into());
                msg.encode_into(output);
            }
        }
    }
}

impl<'a> Parse<'a> for SessionResponse {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("SessionResponse", |input| {
            let (input, tag) = SessionResponseType::parse(input)?;
            match tag {
                SessionResponseType::Begin => {
                    let (input, id) = SessionId::parse(input)?;
                    let (input, next_phase) = NextSyncPhase::parse(input)?;
                    Ok((input, SessionResponse::Begin { id, next_phase }))
                }
                SessionResponseType::FetchMembershipSymbols => {
                    let (input, symbols) = Vec::<CodedSymbol<MembershipSymbol>>::parse(input)?;
                    Ok((input, SessionResponse::FetchMembershipSymbols(symbols)))
                }
                SessionResponseType::FetchDocSymbols => {
                    let (input, symbols) = Vec::<CodedSymbol<DocStateHash>>::parse(input)?;
                    Ok((input, SessionResponse::FetchDocSymbols(symbols)))
                }
                SessionResponseType::FinishMembership => {
                    let (input, phase) = NextSyncPhase::parse(input)?;
                    Ok((input, SessionResponse::FinishMembership(phase)))
                }
                SessionResponseType::UploadMembershipOps => {
                    Ok((input, SessionResponse::UploadMembershipOps))
                }
                SessionResponseType::FetchCgkaSymbols => {
                    let (input, symbols) = Vec::<CodedSymbol<CgkaSymbol>>::parse(input)?;
                    Ok((input, SessionResponse::FetchCgkaSymbols(symbols)))
                }
                SessionResponseType::Error => {
                    let (input, error) = parse::str(input)?;
                    Ok((input, SessionResponse::Error(error.to_string())))
                }
                SessionResponseType::FetchMembershipOps => {
                    let (input, ops) = Vec::<StaticEvent<CommitHash>>::parse(input)?;
                    Ok((input, SessionResponse::FetchMembershipOps(ops)))
                }
                SessionResponseType::FetchCgkaOps => {
                    let (input, ops) = Vec::<Signed<CgkaOperation>>::parse(input)?;
                    Ok((input, SessionResponse::FetchCgkaOps(ops)))
                }
                SessionResponseType::Expired => Ok((input, SessionResponse::Expired)),
            }
        })
    }
}
