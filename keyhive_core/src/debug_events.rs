use crate::{
    content::heads::ContentHeads,
    crypto::digest::Digest,
    event::Event,
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use keyhive_codec::traits::StreamDecode;
use keyhive_crypto::content::reference::ContentRef;
use keyline::{delegation::Delegation, revocation::Revocation};
use std::collections::HashMap;

mod hash;
pub use hash::Hash;
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
        reissued: bool,
    },
    Revoked {
        revoke: Hash,
        retain_count: usize,
    },

    /// A certificate whose payload did not decode.
    Undecodable,
}

/// Specific details for CGKA operations.
#[derive(Debug, Clone)]
pub enum CgkaOperationDetails {
    Add {
        id: Hash,
        share_key: Hash,
        leaf_index: u32,
        inviter_share_key: Option<Hash>,
        invited_updates: Vec<Hash>,
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
    pub fn from_events<T: ContentRef + StreamDecode>(
        events: Vec<Event<T>>,
        nicknames: Nicknames,
    ) -> Self {
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
    /// A row for a certificate whose payload does not decode. The store
    /// verified it, so this does not happen; a row says so rather than panic.
    fn undecodable(idx: usize, event_type: &str, event_hash: Hash) -> Self {
        Self {
            index: idx,
            event_type: event_type.to_string(),
            issuer: event_hash.clone(),
            event_hash,
            details: DebugEventDetails::Undecodable,
        }
    }

    pub fn from_event<T: ContentRef + StreamDecode>(
        idx: usize,
        event: &Event<T>,
        nicknames: &Nicknames,
    ) -> Self {
        match event {
            Event::PrekeysExpanded(signed) => {
                let event_hash = Hash::new(signed.digest().as_slice(), nicknames);
                let Ok(payload) = signed.encoded().decode() else {
                    return Self::undecodable(idx, "PrekeysExpanded", event_hash);
                };
                let payload: AddKeyOp = payload;
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
                let event_hash = Hash::new(signed.digest().as_slice(), nicknames);
                let Ok(payload) = signed.encoded().decode() else {
                    return Self::undecodable(idx, "PrekeyRotated", event_hash);
                };
                let payload: RotateKeyOp = payload;
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
                    CgkaOperation::Add {
                        added_id,
                        pk,
                        leaf_index,
                        invitation,
                        predecessors,
                        ..
                    } => {
                        let op_details = CgkaOperationDetails::Add {
                            id: Hash::new(added_id.as_bytes(), nicknames),
                            share_key: Hash::new(pk.as_bytes(), nicknames),
                            leaf_index: *leaf_index,
                            inviter_share_key: invitation
                                .as_ref()
                                .map(|i| Hash::new(i.inviter_pk.as_bytes(), nicknames)),
                            invited_updates: invitation
                                .iter()
                                .flat_map(|i| &i.ancestor_secrets)
                                .map(|invited| {
                                    Hash::new(invited.update_op_hash.as_slice(), nicknames)
                                })
                                .collect(),
                            predecessors: predecessors
                                .iter()
                                .map(|predecessor| Hash::new(predecessor.as_slice(), nicknames))
                                .collect(),
                        };
                        ("Add", op_details)
                    }
                    CgkaOperation::Remove {
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
                    CgkaOperation::Update {
                        id,
                        new_path,
                        predecessors,
                        ..
                    } => {
                        let new_keys = match &new_path.leaf_pk {
                            beekem::keys::NodeKey::ShareKey(share_key) => {
                                vec![Hash::new(share_key.as_bytes(), nicknames)]
                            }
                            beekem::keys::NodeKey::ConflictKeys(conflict_keys) => conflict_keys
                                .iter()
                                .map(|k| Hash::new(k.as_bytes(), nicknames))
                                .collect(),
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
                let event_hash = Hash::new(signed.digest().as_slice(), nicknames);
                let Ok(d) = signed.encoded().decode() else {
                    return Self::undecodable(idx, "Delegated", event_hash);
                };
                let d: Delegation = d;
                Self {
                    index: idx,
                    event_type: "Delegated".to_string(),
                    event_hash,
                    issuer: Hash::new(signed.issuer().as_bytes(), nicknames),
                    details: DebugEventDetails::Delegated {
                        subject: Hash::new(d.subject.as_bytes(), nicknames),
                        can_access: format!("{:?}", d.power),
                        delegate: Hash::new(d.audience.as_bytes(), nicknames),
                        reissued: d.citation.is_some(),
                    },
                }
            }
            Event::Revoked(signed) => {
                let event_hash = Hash::new(signed.digest().as_slice(), nicknames);
                let Ok(r) = signed.encoded().decode() else {
                    return Self::undecodable(idx, "Revoked", event_hash);
                };
                let r: Revocation<ContentHeads<T>> = r;
                Self {
                    index: idx,
                    event_type: "Revoked".to_string(),
                    event_hash,
                    issuer: Hash::new(signed.issuer().as_bytes(), nicknames),
                    details: DebugEventDetails::Revoked {
                        revoke: Hash::new(r.revoke.as_slice(), nicknames),
                        retain_count: r.retain.len(),
                    },
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
