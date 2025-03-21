use beelay_core::{DocumentId, PeerId};

pub(crate) enum Membered {
    Group(PeerId),
    Document(DocumentId),
}
