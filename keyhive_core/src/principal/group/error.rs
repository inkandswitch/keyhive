use crate::access::Access;
use keyhive_crypto::identifier::Identifier;

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject {0}")]
    InvalidSubject(Box<Identifier>),

    #[error("Escalation: wanted {wanted}, but only {held} is justified")]
    Escalation { wanted: Access, held: Access },

    #[error("Invalid proof chain")]
    InvalidProofChain,
}
