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
use serde::{Deserialize, Serialize};

// FIXME docs
#[allow(async_fn_in_trait)]
pub trait SecretListener: Sized + Clone {
    /// React to new prekeys.
    async fn on_new_sharing_secret(
        &self,
        subject: Subject,
        new_public_key: &ShareKey,
        new_secret_key: &ShareSecretKey,
    );
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Subject {
    CurrentActiveAgent,
    DocumentId(DocumentId),
}
