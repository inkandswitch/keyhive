use crate::{access::Access, principal::identifier::Identifier};

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject {0}")]
    InvalidSubject(Box<Identifier>),

    #[error("escalation: wanted {wanted}, but only {held} is justified")]
    Escalation { wanted: Access, held: Access },

    #[error("Invalid proof chain")]
    InvalidProofChain,
}
