use std::collections::HashMap;

use keyhive_core::{cgka::error::CgkaError, event::static_event::StaticEvent};

use crate::{riblt, sedimentree, CommitHash, DocumentId};

use super::{sync_doc, sync_docs, sync_membership};

pub(crate) struct Session {
    membership_riblt: RibltSession<sync_membership::MembershipSymbol>,
    // Store original hash-to-op mapping for direct lookups
    membership_and_prekey_ops: HashMap<
        keyhive_core::crypto::digest::Digest<StaticEvent<CommitHash>>,
        StaticEvent<CommitHash>,
    >,
    collection_riblt: RibltSession<sync_docs::DocStateHash>,
    trees: HashMap<
        DocumentId,
        (
            RibltSession<sync_doc::CgkaSymbol>,
            sedimentree::SedimentreeSummary,
        ),
    >,
}

impl Session {
    pub(crate) fn new(local_state: super::LocalState) -> Self {
        tracing::trace!(
            num_local_docs = local_state.doc_states.len(),
            "creating new server session"
        );
        // Clone the membership ops for direct lookup
        let membership_ops_clone = local_state.membership_and_prekey_ops.clone();

        // Create the RIBLT session for membership ops
        let membership_riblt =
            RibltSession::new(local_state.membership_and_prekey_ops.into_values());

        let mut trees = HashMap::new();

        for (doc_id, doc_state) in &local_state.doc_states {
            let cgka_riblt_session = RibltSession::new(doc_state.cgka_ops.clone().into_iter());
            trees.insert(
                doc_id.clone(),
                (cgka_riblt_session, doc_state.sedimentree.clone()),
            );
        }
        let collection_riblt =
            RibltSession::new(local_state.doc_states.into_iter().map(|(_, s)| s));
        Self {
            membership_riblt,
            membership_and_prekey_ops: membership_ops_clone,
            collection_riblt,
            trees,
        }
    }

    pub(crate) fn membership_symbols(
        &mut self,
        make_symbols: MakeSymbols,
    ) -> Vec<riblt::CodedSymbol<sync_membership::MembershipSymbol>> {
        self.membership_riblt.symbols(make_symbols)
    }

    pub(crate) fn membership_and_prekey_ops(
        &mut self,
        op_hashes: Vec<keyhive_core::crypto::digest::Digest<StaticEvent<CommitHash>>>,
    ) -> Vec<StaticEvent<CommitHash>> {
        // Look up operations directly from the hash map
        op_hashes
            .into_iter()
            .filter_map(|hash| self.membership_and_prekey_ops.get(&hash).cloned())
            .collect()
    }

    pub(crate) fn collection_state_symbols(
        &mut self,
        make_symbols: MakeSymbols,
    ) -> Vec<riblt::CodedSymbol<sync_docs::DocStateHash>> {
        self.collection_riblt.symbols(make_symbols)
    }

    pub(crate) fn doc_cgka_symbols(
        &mut self,
        doc: &DocumentId,
        make_symbols: MakeSymbols,
    ) -> Vec<riblt::CodedSymbol<sync_doc::CgkaSymbol>> {
        if let Some((cgka_session, _)) = self.trees.get_mut(doc) {
            cgka_session.symbols(make_symbols)
        } else {
            // make an empty session and return the first symbol
            let mut encoder = riblt::Encoder::new();
            encoder.next_n_symbols(1)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    LoadCgkaOps(#[from] CgkaError),
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
