use crate::{
    crypto::{digest::Digest, signer::async_signer::AsyncSigner},
    event::Event,
    listener::membership::MembershipListener,
};
use std::collections::HashMap;

mod hash;
pub use hash::Hash;
use serde::Serialize;
pub mod terminal;

/// A table of events for debugging purposes.
/// This structure can be used to generate a formatted table of events
/// that can be displayed in various output formats (terminal, logs, etc.)
#[derive(Debug, Clone)]
pub struct DebugEventTable {
    pub rows: Vec<DebugEventRow>,
    pub event_counts: HashMap<String, usize>,
}

/// A row in the debug event table, representing a single event.
#[derive(Debug, Clone)]
pub struct DebugEventRow {
    pub index: usize,
    pub event_type: String,
    pub event_hash: Hash,
    pub issuer: Hash,
    pub details: DebugEventDetails,
}

/// Details of an event, containing specific information based on the event type.
#[derive(Debug, Clone)]
pub enum DebugEventDetails {
    PrekeysExpanded {
        share_key: Hash,
    },
    PrekeyRotated {
        old_key: Hash,
        new_key: Hash,
    },
    CgkaOperation {
        op_type: String,
        doc_id: Hash,
        op_details: CgkaOperationDetails,
    },
    Delegated {
        subject: Hash,
        can_access: String,
        delegate: Hash,
        after_revocations_count: usize,
        after_content_count: usize,
    },
    Revoked {
        subject: Hash,
        revoke: Hash,
        has_proof: bool,
        after_content_count: usize,
    },
}

/// Specific details for CGKA operations.
#[derive(Debug, Clone)]
pub enum CgkaOperationDetails {
    Add {
        id: Hash,
        sharekey: Hash,
        leaf_index: u32,
        predecessors: Vec<Hash>,
    },
    Remove {
        id: Hash,
        leaf_index: u32,
        removed_keys: Vec<Hash>,
        predecessors: Vec<Hash>,
    },
    Update {
        id: Hash,
        new_keys: Vec<Hash>,
        path_length: usize,
        predecessors: Vec<Hash>,
    },
}

impl DebugEventTable {
    /// Create a new debug event table from a vector of events.
    pub fn from_events<S, T, L>(events: Vec<Event<S, T, L>>, nicknames: Nicknames) -> Self
    where
        S: AsyncSigner,
        T: std::fmt::Debug + Eq + Clone + std::hash::Hash + PartialOrd + Serialize,
        L: MembershipListener<S, T>,
    {
        if events.is_empty() {
            return Self {
                rows: Vec::new(),
                event_counts: HashMap::new(),
            };
        }

        // Count event types
        let mut event_counts: HashMap<String, usize> = HashMap::new();
        for event in &events {
            let event_type = match event {
                Event::PrekeysExpanded(_) => "PrekeysExpanded",
                Event::PrekeyRotated(_) => "PrekeyRotated",
                Event::CgkaOperation(_) => "CgkaOperation",
                Event::Delegated(_) => "Delegated",
                Event::Revoked(_) => "Revoked",
            };
            *event_counts.entry(event_type.to_string()).or_insert(0) += 1;
        }

        // Create rows for each event
        let mut rows = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            rows.push(DebugEventRow::from_event(idx, event, &nicknames));
        }

        Self { rows, event_counts }
    }
}

impl DebugEventRow {
    /// Create a new debug event row from an event.
    pub fn from_event<S, T, L>(idx: usize, event: &Event<S, T, L>, nicknames: &Nicknames) -> Self
    where
        S: AsyncSigner,
        T: std::fmt::Debug + Eq + Clone + std::hash::Hash + PartialOrd + Serialize,
        L: MembershipListener<S, T>,
    {
        match event {
            Event::PrekeysExpanded(signed) => {
                let payload = signed.payload();
                let event_hash = Hash::new(Digest::hash(signed).raw.as_bytes(), nicknames);
                let issuer = Hash::new(signed.issuer().as_bytes(), nicknames);
                let details = DebugEventDetails::PrekeysExpanded {
                    share_key: Hash::new(payload.share_key.as_bytes(), nicknames),
                };

                Self {
                    index: idx,
                    event_type: "PrekeysExpanded".to_string(),
                    event_hash,
                    issuer,
                    details,
                }
            }
            Event::PrekeyRotated(signed) => {
                let payload = signed.payload();
                let event_hash = Hash::new(Digest::hash(signed).raw.as_bytes(), nicknames);
                let issuer = Hash::new(signed.issuer().as_bytes(), nicknames);
                let details = DebugEventDetails::PrekeyRotated {
                    old_key: Hash::new(payload.old.as_bytes(), nicknames),
                    new_key: Hash::new(payload.new.as_bytes(), nicknames),
                };

                Self {
                    index: idx,
                    event_type: "PrekeyRotated".to_string(),
                    event_hash,
                    issuer,
                    details,
                }
            }
            Event::CgkaOperation(signed) => {
                let payload = signed.payload();
                let event_hash = Hash::new(Digest::hash(signed).raw.as_bytes(), nicknames);
                let issuer = Hash::new(signed.issuer().as_bytes(), nicknames);
                let doc_id = Hash::new(payload.doc_id().as_bytes(), nicknames);

                let (op_type, op_details) = match payload {
                    crate::cgka::operation::CgkaOperation::Add {
                        added_id,
                        pk,
                        leaf_index,
                        predecessors,
                        ..
                    } => {
                        let op_details = CgkaOperationDetails::Add {
                            id: Hash::new(added_id.as_bytes(), nicknames),
                            sharekey: Hash::new(pk.as_bytes(), nicknames),
                            leaf_index: *leaf_index,
                            predecessors: predecessors
                                .iter()
                                .map(|predecessor| Hash::new(predecessor.as_slice(), nicknames))
                                .collect(),
                        };
                        ("Add", op_details)
                    }
                    crate::cgka::operation::CgkaOperation::Remove {
                        id,
                        leaf_idx,
                        removed_keys,
                        predecessors,
                        ..
                    } => {
                        let op_details = CgkaOperationDetails::Remove {
                            id: Hash::new(id.as_bytes(), nicknames),
                            leaf_index: *leaf_idx,
                            removed_keys: removed_keys
                                .iter()
                                .map(|key| Hash::new(key.as_bytes(), nicknames))
                                .collect(),
                            predecessors: predecessors
                                .iter()
                                .map(|predecessor| Hash::new(predecessor.as_slice(), nicknames))
                                .collect(),
                        };
                        ("Remove", op_details)
                    }
                    crate::cgka::operation::CgkaOperation::Update {
                        id,
                        new_path,
                        predecessors,
                        ..
                    } => {
                        let new_keys = match &new_path.leaf_pk {
                            crate::cgka::keys::NodeKey::ShareKey(share_key) => {
                                vec![Hash::new(share_key.as_bytes(), nicknames)]
                            }
                            crate::cgka::keys::NodeKey::ConflictKeys(conflict_keys) => {
                                // For conflict keys, we'll just use the first one for display purposes
                                conflict_keys
                                    .iter()
                                    .map(|k| Hash::new(k.as_bytes(), nicknames))
                                    .collect()
                            }
                        };
                        let op_details = CgkaOperationDetails::Update {
                            id: Hash::new(id.as_bytes(), nicknames),
                            new_keys,
                            path_length: new_path.path.len(),
                            predecessors: predecessors
                                .iter()
                                .map(|predecessor| Hash::new(predecessor.as_slice(), nicknames))
                                .collect(),
                        };
                        ("Update", op_details)
                    }
                };

                let details = DebugEventDetails::CgkaOperation {
                    op_type: op_type.to_string(),
                    doc_id,
                    op_details,
                };

                Self {
                    index: idx,
                    event_type: "CgkaOperation".to_string(),
                    event_hash,
                    issuer,
                    details,
                }
            }
            Event::Delegated(signed) => {
                let payload = signed.payload();
                let event_hash = Hash::new(Digest::hash(signed).raw.as_bytes(), nicknames);
                let issuer = Hash::new(signed.issuer().as_bytes(), nicknames);
                let subject = if let Some(proof) = &payload.proof {
                    Hash::new(proof.subject_id().as_bytes(), nicknames)
                } else {
                    Hash::new(signed.issuer().as_bytes(), nicknames)
                };
                let details = DebugEventDetails::Delegated {
                    subject,
                    can_access: format!("{:?}", payload.can),
                    delegate: Hash::new(payload.delegate.id().as_bytes(), nicknames),
                    after_revocations_count: payload.after_revocations.len(),
                    after_content_count: payload.after_content.len(),
                };

                Self {
                    index: idx,
                    event_type: "Delegated".to_string(),
                    event_hash,
                    issuer,
                    details,
                }
            }
            Event::Revoked(signed) => {
                let payload = signed.payload();
                let event_hash = Hash::new(Digest::hash(signed).raw.as_bytes(), nicknames);
                let issuer = Hash::new(signed.issuer().as_bytes(), nicknames);
                let subject = if let Some(proof) = &payload.proof {
                    Hash::new(proof.subject_id().as_bytes(), nicknames)
                } else {
                    Hash::new(signed.issuer().as_bytes(), nicknames)
                };
                let details = DebugEventDetails::Revoked {
                    subject,
                    revoke: Hash::new(Digest::hash(&payload.revoke).as_slice(), nicknames),
                    has_proof: payload.proof.is_some(),
                    after_content_count: payload.after_content.len(),
                };

                Self {
                    index: idx,
                    event_type: "Revoked".to_string(),
                    event_hash,
                    issuer,
                    details,
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Nicknames {
    names: HashMap<Vec<u8>, String>,
}

impl Nicknames {
    pub fn with_nickname<S: AsRef<str>>(mut self, original: &[u8], nickname: S) -> Self {
        self.names
            .insert(original.to_vec(), nickname.as_ref().to_string());
        self
    }
}
