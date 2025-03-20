use crate::{access::Access, principal::identifier::Identifier};

#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error("Invalid subject {0}")]
    InvalidSubject(Box<Identifier>),

    #[error("Escelation: claims {claimed}, but the proof has {proof}")]
    Escelation { claimed: Access, proof: Access },

    #[error("Invalid proof chain")]
    InvalidProofChain,
}
