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
