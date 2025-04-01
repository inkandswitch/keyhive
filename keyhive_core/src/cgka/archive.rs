use std::collections::HashMap;

use derivative::Derivative;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{application_secret::PcsKey, digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{document::id::DocumentId, individual::id::IndividualId},
    util::content_addressed_map::CaMap,
};

use super::{
    beekem::BeeKem,
    keys::ShareKeyMap,
    operation::{CgkaOperation, CgkaOperationGraph},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Derivative)]
pub struct CgkaArchive {
    pub(crate) doc_id: DocumentId,
    pub(crate) viewer_id: IndividualId,
    pub(crate) viewer_sks: ShareKeyMap,
    pub(crate) tree: BeeKem,
    pub(crate) ops_graph: CgkaOperationGraph,
    pub(crate) pending_ops_for_structural_change: bool,
    pub(crate) pcs_keys: CaMap<PcsKey>,
    pub(crate) pcs_key_ops: HashMap<Digest<PcsKey>, Digest<Signed<CgkaOperation>>>,
    pub(crate) original_member: (IndividualId, ShareKey),
    pub(crate) init_add_op: Signed<CgkaOperation>,
}

impl CgkaArchive {
    pub fn doc_id(&self) -> DocumentId {
        self.doc_id
    }

    pub fn viewer_id(&self) -> IndividualId {
        self.viewer_id
    }

    pub fn viewer_sks(&self) -> &ShareKeyMap {
        &self.viewer_sks
    }

    pub fn pending_ops_for_structural_change(&self) -> bool {
        self.pending_ops_for_structural_change
    }

    pub fn pcs_keys(&self) -> &CaMap<PcsKey> {
        &self.pcs_keys
    }

    pub fn pcs_key_ops(&self) -> &HashMap<Digest<PcsKey>, Digest<Signed<CgkaOperation>>> {
        &self.pcs_key_ops
    }

    pub fn original_member(&self) -> (IndividualId, ShareKey) {
        self.original_member
    }

    pub fn init_add_op(&self) -> &Signed<CgkaOperation> {
        &self.init_add_op
    }
}
