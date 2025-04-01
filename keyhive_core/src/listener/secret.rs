//! Listener for changes to local secrets.
//!
//! <div class="warning">
//!
//! DO NOT use this trait to move secrets between devices. These are local secrets.
//!
//! </div>

use crate::{
    crypto::share_key::{ShareKey, ShareSecretKey},
    principal::document::id::DocumentId,
};

// FIXME docs
#[allow(async_fn_in_trait)]
pub trait SecretListener: Sized + Clone {
    async fn on_active_prekey_pair(&self, new_public_key: ShareKey, new_secret_key: ShareSecretKey);

    async fn on_doc_sharing_secret(
        &self,
        doc_id: DocumentId,
        new_public_key: ShareKey,
        new_secret_key: ShareSecretKey,
    );
}
