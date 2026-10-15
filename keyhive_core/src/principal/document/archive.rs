use keyhive_crypto::content::reference::ContentRef;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// What a document holds that cannot be recomputed: its content heads. Its
/// tree is rebuilt from the operation store, its membership is Keyline's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentArchive<T: ContentRef> {
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
}
