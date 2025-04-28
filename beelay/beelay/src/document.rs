use super::{CommitOrBundle, DocumentId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Document {
    id: DocumentId,
    contents: Vec<CommitOrBundle>,
}

impl Document {
    pub fn id(&self) -> DocumentId {
        self.id
    }

    pub fn data(&self) -> &[CommitOrBundle] {
        &self.contents
    }
}
