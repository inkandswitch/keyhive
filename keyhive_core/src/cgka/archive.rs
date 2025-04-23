use serde::{Deserialize, Serialize};

use crate::{
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{document::id::DocumentId, individual::id::IndividualId},
};

use super::{
    beekem::BeeKem,
    operation::{CgkaOperation, CgkaOperationGraph},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgkaArchive {
    pub(crate) doc_id: DocumentId,
    pub(crate) owner_id: IndividualId,
    pub(crate) tree: BeeKem,
    pub(crate) ops_graph: CgkaOperationGraph,
    pub(crate) pending_ops_for_structural_change: bool,
    pub(crate) pcs_keys: Vec<ShareKey>,
    pub(crate) original_member: (IndividualId, ShareKey),
    pub(crate) init_add_op: Signed<CgkaOperation>,
    pub(crate) pcs_key_ops: Vec<(ShareKey, Digest<Signed<CgkaOperation>>)>,
}
