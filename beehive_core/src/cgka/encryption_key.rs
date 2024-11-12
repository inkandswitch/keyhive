use serde::{Deserialize, Serialize};

use crate::{
    content::reference::ContentRef,
    crypto::{
        digest::Digest, separable::Separable, share_key::ShareSecretKey, siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::identifier::Identifier,
};

use super::{error::CgkaError, keys::ShareKeyMap, BeeKem};

const STATIC_CONTEXT: &str = "/automerge/beehive/beekem/app_secret/";
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplicationSecretWithAddress<T: ContentRef> {
    pub app_secret: SymmetricKey,
    pub address: EncryptionKeyAddress<T>,
}

// TODO: Rename
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct EncryptionKeyAddress<T: ContentRef> {
    pub writer_id: Identifier,
    // FIXME: Can we get this elsewhere rather than in this struct?
    pub content_ref: T,
    // FIXME: What should we really use here? Can we get this elsewhere than
    // from this struct?
    pub pred_ref: T,
    pub nonce: Siv,
    pub pcs_key_hash: Digest<PcsKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PcsKey(ShareSecretKey);

impl PcsKey {
    pub(crate) fn new(
        owner_id: Identifier,
        owner_sks: &mut ShareKeyMap,
        tree: &BeeKem,
    ) -> Result<Self, CgkaError> {
        let key = tree.decrypt_tree_secret(owner_id, owner_sks)?;
        Ok(Self(key))
    }

    pub(crate) fn derive_application_secret<T: ContentRef>(
        &self,
        content_ref: &T,
        // FIXME: What type should we really use here?
        pred_ref: &T,
    ) -> SymmetricKey {
        let pcs_hash = Digest::hash(&self.0);
        let content_ref_hash = Digest::hash(content_ref);
        let pred_ref_hash = Digest::hash(pred_ref);
        // FIXME: We could also use the writer id instead of the content ref hash.
        let mut app_secret_context =
            format!("epoch:{pcs_hash}/pred:{pred_ref_hash}/content:{content_ref_hash}")
                .into_bytes();
        let mut key_material = self.0.clone().as_slice().to_vec();
        key_material.append(&mut app_secret_context);
        let app_secret_bytes = blake3::derive_key(STATIC_CONTEXT, key_material.as_slice());
        SymmetricKey::derive_from_bytes(&app_secret_bytes)
    }
}

impl From<PcsKey> for SymmetricKey {
    fn from(pcs_key: PcsKey) -> SymmetricKey {
        SymmetricKey::derive_from_bytes(pcs_key.0.as_slice())
    }
}
