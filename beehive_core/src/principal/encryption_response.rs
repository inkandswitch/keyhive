use crate::{
    cgka::operation::CgkaOperation, content::reference::ContentRef,
    crypto::encrypted::EncryptedContent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResponse<T: ContentRef> {
    pub ciphertext: EncryptedContent<Vec<u8>, T>,
    pub cgka_op: Option<CgkaOperation>,
}
