use beelay_core::{DocumentId, PeerId};

// FIXME use MemberedId
pub(crate) enum Membered {
    Group(PeerId),
    Document(DocumentId),
}
