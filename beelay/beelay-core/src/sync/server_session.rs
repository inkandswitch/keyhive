use std::collections::HashMap;

use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};

use crate::{riblt, sedimentree, CommitHash, DocumentId, PeerId};

use super::{
    sessions::SessionError, sync_doc, sync_docs, sync_membership, CgkaSymbol, DocStateHash,
    MembershipSymbol, ReachableDocs,
};

pub(crate) struct Session {
    remote_peer: PeerId,
    state: State,
}

enum State {
    Loading,
    Loaded {
        docs: DocsSession,
        membership: MembershipSession,
    },
}

struct MembershipSession {
    encoder: riblt::Encoder<MembershipSymbol>,
    // Store original hash-to-op mapping for direct lookups
    ops: HashMap<
        keyhive_core::crypto::digest::Digest<StaticEvent<CommitHash>>,
        StaticEvent<CommitHash>,
    >,
}

struct DocsSession {
    encoder: riblt::Encoder<sync_docs::DocStateHash>,
    trees: HashMap<
        DocumentId,
        (
            riblt::Encoder<sync_doc::CgkaSymbol>,
            HashMap<Digest<Signed<CgkaOperation>>, Signed<CgkaOperation>>,
            sedimentree::SedimentreeSummary,
        ),
    >,
}

pub(crate) enum GraphSyncPhase {
    Membership(Vec<riblt::CodedSymbol<MembershipSymbol>>),
    Docs(Vec<riblt::CodedSymbol<DocStateHash>>),
    Done,
}

impl DocsSession {
    fn new(reachable: ReachableDocs) -> (Self, riblt::Decoder<DocStateHash>) {
        let mut decoder = riblt::Decoder::new();
        let mut collection_riblt = riblt::Encoder::new();
        for doc_state in reachable.doc_states.values() {
            collection_riblt.add_symbol(&doc_state.hash);
            decoder.add_symbol(&doc_state.hash);
        }

        let mut trees = HashMap::new();
        for (doc_id, doc_state) in reachable.doc_states {
            let mut encoder = riblt::Encoder::new();
            let mut ops = HashMap::new();
            for op in doc_state.cgka_ops.iter() {
                encoder.add_symbol(&CgkaSymbol::from(op));
                ops.insert(Digest::hash(op), op.clone());
            }
            trees.insert(
                doc_id.clone(),
                (encoder, ops, doc_state.sedimentree.clone()),
            );
        }

        (
            DocsSession {
                encoder: collection_riblt,
                trees,
            },
            decoder,
        )
    }
}

impl Session {
    pub(crate) fn new(
        remote_peer: PeerId,
        membership_state: super::MembershipState,
        docs: ReachableDocs,
        remote_membership: Vec<riblt::CodedSymbol<MembershipSymbol>>,
        remote_docs: Vec<riblt::CodedSymbol<DocStateHash>>,
    ) -> (Self, GraphSyncPhase) {
        tracing::trace!("creating new server session");

        let membership_ops = membership_state.into_static_events();

        let mut decoder = riblt::Decoder::new();
        for op in membership_ops.values() {
            decoder.add_symbol(&MembershipSymbol::from(op));
        }
        for op in remote_membership {
            decoder.add_coded_symbol(&op);
            decoder.try_decode().unwrap();
            if decoder.decoded() {
                break;
            }
        }
        let membership_in_sync = decoder.decoded()
            && decoder.get_remote_symbols().is_empty()
            && decoder.get_local_symbols().is_empty();

        // Create the RIBLT session for membership ops
        let mut membership_riblt = riblt::Encoder::new();
        for op in membership_ops.values() {
            membership_riblt.add_symbol(&MembershipSymbol::from(op));
        }

        let (mut doc_session, mut doc_decoder) = DocsSession::new(docs);

        let phase = if membership_in_sync {
            for symbol in remote_docs {
                doc_decoder.add_coded_symbol(&symbol);
                if doc_decoder.decoded() {
                    break;
                }
            }
            let docs_are_in_sync = doc_decoder.decoded()
                && doc_decoder.get_local_symbols().is_empty()
                && doc_decoder.get_remote_symbols().is_empty();
            if !docs_are_in_sync {
                let first_symbols = doc_session.encoder.next_n_symbols(10);
                GraphSyncPhase::Docs(first_symbols)
            } else {
                GraphSyncPhase::Done
            }
        } else {
            let first_symbols = membership_riblt.next_n_symbols(10);
            GraphSyncPhase::Membership(first_symbols)
        };

        (
            Self {
                remote_peer,
                state: State::Loaded {
                    docs: doc_session,
                    membership: MembershipSession {
                        encoder: membership_riblt,
                        ops: membership_ops,
                    },
                },
            },
            phase,
        )
    }

    pub(crate) fn start_reloading(&mut self) {
        self.state = State::Loading;
    }

    pub(crate) fn reload_complete(
        &mut self,
        membership: super::MembershipState,
        docs: ReachableDocs,
        remote_membership: Vec<riblt::CodedSymbol<MembershipSymbol>>,
    ) -> Result<GraphSyncPhase, SessionError> {
        assert!(matches!(self.state, State::Loading));

        let membership_ops = membership.into_static_events();

        // Create a decoder
        let mut decoder = riblt::Decoder::new();
        for op in membership_ops.values() {
            decoder.add_symbol(&MembershipSymbol::from(op));
        }

        for sym in remote_membership {
            decoder.add_coded_symbol(&sym);
            decoder.try_decode().map_err(|e| {
                tracing::warn!(err=?e, "invalid symbol");
                SessionError::InvalidRequest
            })?;
            if decoder.decoded() {
                break;
            }
        }

        // Create the RIBLT session for membership ops
        let mut membership_riblt = riblt::Encoder::new();
        for op in membership_ops.values() {
            membership_riblt.add_symbol(&MembershipSymbol::from(op));
        }

        let (mut docs, _decoder) = DocsSession::new(docs);

        let phase = if decoder.decoded()
            && decoder.get_local_symbols().is_empty()
            && decoder.get_remote_symbols().is_empty()
        {
            let doc_symbols = docs.encoder.next_n_symbols(10);
            GraphSyncPhase::Docs(doc_symbols)
        } else {
            let membership_symbols = membership_riblt.next_n_symbols(10);
            GraphSyncPhase::Membership(membership_symbols)
        };

        self.state = State::Loaded {
            docs,
            membership: MembershipSession {
                encoder: membership_riblt,
                ops: membership_ops,
            },
        };

        Ok(phase)
    }

    pub(crate) fn membership_symbols(
        &mut self,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<sync_membership::MembershipSymbol>>, SessionError> {
        match &mut self.state {
            State::Loading => Err(SessionError::Loading),
            State::Loaded { membership, .. } => Ok(membership.encoder.next_n_symbols(count as u64)),
        }
    }

    pub(crate) fn membership_and_prekey_ops(
        &mut self,
        op_hashes: Vec<keyhive_core::crypto::digest::Digest<StaticEvent<CommitHash>>>,
    ) -> Result<Vec<StaticEvent<CommitHash>>, SessionError> {
        match &mut self.state {
            State::Loading => Err(SessionError::Loading),
            State::Loaded { membership, .. } => Ok(op_hashes
                .into_iter()
                .filter_map(|hash| membership.ops.get(&hash).cloned())
                .collect()),
        }
    }

    pub(crate) fn collection_state_symbols(
        &mut self,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<sync_docs::DocStateHash>>, SessionError> {
        let State::Loaded { docs, .. } = &mut self.state else {
            return Err(SessionError::Loading);
        };
        Ok(docs.encoder.next_n_symbols(count as u64))
    }

    pub(crate) fn doc_cgka_symbols(
        &mut self,
        doc: &DocumentId,
        count: u32,
    ) -> Result<Vec<riblt::CodedSymbol<sync_doc::CgkaSymbol>>, SessionError> {
        let State::Loaded { docs, .. } = &mut self.state else {
            return Err(SessionError::Loading);
        };
        let symbols = if let Some((cgka_session, _, _)) = docs.trees.get_mut(&doc) {
            cgka_session.next_n_symbols(count as u64)
        } else {
            // make an empty session and return the first symbol
            let mut encoder = riblt::Encoder::new();
            encoder.next_n_symbols(1)
        };
        Ok(symbols)
    }

    pub(crate) fn doc_cgka_ops(
        &self,
        doc: &DocumentId,
        op_hashes: Vec<keyhive_core::crypto::digest::Digest<Signed<CgkaOperation>>>,
    ) -> Result<Vec<Signed<CgkaOperation>>, SessionError> {
        let State::Loaded { docs, .. } = &self.state else {
            return Err(SessionError::Loading);
        };
        let ops = if let Some((_, ops, _)) = docs.trees.get(&doc) {
            op_hashes
                .into_iter()
                .filter_map(|h| ops.get(&h).cloned())
                .collect()
        } else {
            Vec::new()
        };
        Ok(ops)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid sequence number")]
    InvalidSequenceNumber,
}

pub(crate) struct MakeSymbols {
    pub(crate) offset: usize,
    pub(crate) count: usize,
}

struct RibltSession<K: riblt::Symbol + Copy> {
    encoder: riblt::Encoder<K>,
    symbols: Vec<riblt::CodedSymbol<K>>,
}

impl<K> RibltSession<K>
where
    K: riblt::Symbol + Copy,
{
    fn new<I, V>(items: I) -> Self
    where
        I: Iterator<Item = V>,
        K: for<'a> From<&'a V> + Eq + std::hash::Hash,
    {
        let mut encoder = riblt::Encoder::new();
        for item in items {
            let symbol = K::from(&item);
            encoder.add_symbol(&symbol);
        }
        Self {
            encoder,
            symbols: Vec::new(),
        }
    }
}

impl<K> RibltSession<K>
where
    K: riblt::Symbol + Copy + Eq + std::hash::Hash,
{
    fn symbols(
        &mut self,
        MakeSymbols { offset, count }: MakeSymbols,
    ) -> Vec<riblt::CodedSymbol<K>> {
        if offset + count >= self.symbols.len() {
            let num_new_symbols_to_make = offset + count - self.symbols.len() + 1;
            self.symbols
                .extend(self.encoder.next_n_symbols(num_new_symbols_to_make as u64));
        }
        assert!(offset + count <= self.symbols.len() - 1);
        self.symbols[offset..offset + count].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use keyhive_core::{
        cgka::operation::CgkaOperation,
        crypto::{digest::Digest, signed::Signed},
    };
    use std::collections::HashSet;

    use crate::{
        riblt,
        sync::{
            server_session::{MakeSymbols, RibltSession},
            CgkaSymbol,
        },
    };

    #[derive(Debug)]
    struct Scenario {
        only_server_ops: Vec<Signed<CgkaOperation>>,
        only_client_ops: Vec<Signed<CgkaOperation>>,
        joint_ops: Vec<Signed<CgkaOperation>>,
    }

    impl<'a> arbitrary::Arbitrary<'a> for Scenario {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let all_ops = Vec::<Signed<CgkaOperation>>::arbitrary(u)?;
            if all_ops.len() == 0 {
                return Ok(Scenario {
                    only_server_ops: vec![],
                    only_client_ops: vec![],
                    joint_ops: vec![],
                });
            }
            let joint_split_idx = u.int_in_range(0..=all_ops.len() - 1)?;
            let (joint, rest) = all_ops.split_at(joint_split_idx);

            if rest.is_empty() {
                return Ok(Scenario {
                    only_server_ops: vec![],
                    only_client_ops: vec![],
                    joint_ops: joint.to_vec(),
                });
            }

            let only_server_idx = u.int_in_range(0..=rest.len() - 1)?;
            let (only_server_ops, only_client_ops) = rest.split_at(only_server_idx);
            Ok(Scenario {
                only_server_ops: only_server_ops.to_vec(),
                only_client_ops: only_client_ops.to_vec(),
                joint_ops: joint.to_vec(),
            })
        }
    }

    // Test that verifies RIBLT convergence with CgkaSymbols
    #[test]
    fn test_cgka_symbol_riblt_convergence() {
        bolero::check!().with_arbitrary::<Scenario>().for_each(
            |Scenario {
                 only_server_ops,
                 only_client_ops,
                 joint_ops,
             }| {
                // Create client and server sessions
                let mut server_session = RibltSession::new(
                    only_server_ops
                        .clone()
                        .into_iter()
                        .chain(joint_ops.clone().into_iter()),
                );

                // Create client decoder
                let mut client_decoder = riblt::Decoder::new();

                for op in only_client_ops.iter().chain(joint_ops) {
                    client_decoder.add_symbol(&CgkaSymbol::from(op));
                }

                // Simulate the RIBLT sync process
                let mut offset = 0;
                let mut iterations = 0;
                let max_iterations = 10; // Prevent infinite loops

                loop {
                    if iterations >= max_iterations {
                        panic!("RIBLT failed to converge after {iterations} iterations");
                    }
                    iterations += 1;

                    // Get symbols from server
                    let symbols = server_session.symbols(MakeSymbols { offset, count: 10 });
                    offset += symbols.len();

                    // Process symbols in client decoder
                    for symbol in symbols {
                        client_decoder.add_coded_symbol(&symbol);
                        client_decoder.try_decode().expect("Failed to decode");
                    }

                    if client_decoder.decoded() {
                        break;
                    }
                }

                // Verify that RIBLT convergence occurred
                assert!(
                    client_decoder.decoded(),
                    "RIBLT failed to converge after {iterations} iterations"
                );

                // Check that we properly identified which ops are on the server but not the client
                let to_download = client_decoder
                    .get_remote_symbols()
                    .into_iter()
                    .map(|s| s.symbol().digest())
                    .collect::<HashSet<_>>();

                let expected_to_download: HashSet<_> =
                    only_server_ops.iter().map(|op| Digest::hash(op)).collect();

                assert_eq!(
                    to_download, expected_to_download,
                    "RIBLT did not correctly identify ops to download"
                );

                // Check that we properly identified which ops are on the client but not the server
                let to_upload = client_decoder
                    .get_local_symbols()
                    .into_iter()
                    .map(|s| s.symbol().digest())
                    .collect::<HashSet<_>>();

                let expected_to_upload: HashSet<_> =
                    only_client_ops.iter().map(|op| Digest::hash(op)).collect();

                assert_eq!(
                    to_upload, expected_to_upload,
                    "RIBLT did not correctly identify ops to upload"
                );
            },
        );
    }
}
