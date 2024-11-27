use serde::{Deserialize, Serialize};

use crate::{
    content::reference::ContentRef,
    crypto::{
        digest::Digest, encrypted::Encrypted, separable::Separable, share_key::ShareSecretKey,
        siv::Siv, symmetric_key::SymmetricKey,
    },
};

const STATIC_CONTEXT: &str = "/automerge/beehive/beekem/app_secret/";
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplicationSecret<Cr: ContentRef> {
    key: SymmetricKey,
    pcs_key_hash: Digest<PcsKey>,
    nonce: Siv,
    content_ref: Digest<Cr>,
    pred_ref: Digest<Vec<Cr>>,
}

impl<Cr: ContentRef> ApplicationSecret<Cr> {
    pub fn new(
        key: SymmetricKey,
        pcs_key_hash: Digest<PcsKey>,
        nonce: Siv,
        content_ref: Digest<Cr>,
        pred_ref: Digest<Vec<Cr>>,
    ) -> Self {
        Self {
            key,
            pcs_key_hash,
            nonce,
            content_ref,
            pred_ref,
        }
    }

    pub fn key(&self) -> SymmetricKey {
        self.key
    }

    pub fn try_encrypt<T>(
        &self,
        plaintext: &[u8],
    ) -> Result<Encrypted<T, Cr>, chacha20poly1305::Error> {
        let mut ciphertext = plaintext.to_vec();
        self.key.try_encrypt(self.nonce, &mut ciphertext)?;
        Ok(Encrypted::new(
            self.nonce,
            ciphertext,
            self.pcs_key_hash,
            self.content_ref,
            self.pred_ref,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PcsKey(ShareSecretKey);

impl PcsKey {
    pub fn new(share_secret_key: ShareSecretKey) -> Self {
        Self(share_secret_key)
    }

    pub(crate) fn derive_application_secret<Cr: ContentRef>(
        &self,
        nonce: &Siv,
        content_ref: &Digest<Cr>,
        pred_ref: &Digest<Vec<Cr>>,
    ) -> ApplicationSecret<Cr> {
        let pcs_hash = Digest::hash(&self.0);
        let mut app_secret_context =
            format!("epoch:{pcs_hash}/pred:{pred_ref}/content:{content_ref}").into_bytes();
        let mut key_material = self.0.clone().as_slice().to_vec();
        key_material.append(&mut app_secret_context);
        let app_secret_bytes = blake3::derive_key(STATIC_CONTEXT, key_material.as_slice());
        let symmetric_key = SymmetricKey::derive_from_bytes(&app_secret_bytes);
        ApplicationSecret::new(
            symmetric_key,
            Digest::hash(self),
            *nonce,
            *content_ref,
            *pred_ref,
        )
    }
}

impl From<PcsKey> for SymmetricKey {
    fn from(pcs_key: PcsKey) -> SymmetricKey {
        SymmetricKey::derive_from_bytes(pcs_key.0.as_slice())
    }
}
