//! The (plaintext) container for causal encryption: a block's payload and
//! its ancestors' keys, as opening the block gives them.

use crate::{
    encrypted::{ContentDecryptError, EncryptedContent},
    reference::ContentRef,
};
use derivative::Derivative;
use keyhive_codec::{error::DecodeError, traits::Decode};
use keyhive_crypto::{identifier::Identifier, symmetric_key::SymmetricKey};
use std::collections::HashMap;
use thiserror::Error;
#[cfg_attr(all(doc, feature = "mermaid_docs"), aquamarine::aquamarine)]
/// A container for an arbitrary payload and the references and keys of its ancestors.
///
/// This is the core primitive of [causal encryption]. In the diagram below, each large block represents
/// an [`Envelope`], which are decrypted in turn by their successors.
///
/// ```mermaid
/// flowchart
///     subgraph genesis["oUz 🔓"]
///       a[New Doc]
///     end
///
///     subgraph block1["g6z 🔓"]
///       op1[Op 1]
///
///       subgraph block1ancestors[Ancestors]
///         subgraph block1ancestor1[Ancestor 1]
///           pointer1_1["Pointer #️⃣"]
///           key1_1["Key 🔑"]
///         end
///       end
///     end
///
///     pointer1_1 --> genesis
///
///     subgraph block2["Xa2 🔓"]
///         op2[Op 2]
///         op3[Op 3]
///         op4[Op 4]
///
///       subgraph block2ancestors[Ancestors]
///         subgraph block2ancestor1[Ancestor 1]
///           pointer2_1["Pointer #️⃣"]
///           key2_1["Key 🔑"]
///         end
///       end
///     end
///
///     pointer2_1 --> genesis
///
///     subgraph block3["e9j 🔓"]
///       op5[Op 5]
///       op6[Op 6]
///
///       subgraph block3ancestors[Ancestors]
///         subgraph block3ancestor1[Ancestor 1]
///           pointer3_1["Pointer #️⃣"]
///           key3_1["Key 🔑"]
///         end
///
///         subgraph block3ancestor2[Ancestor 2]
///           pointer3_2["Pointer #️⃣"]
///           key3_2["Key 🔑"]
///         end
///       end
///     end
///
///     pointer3_1 --> block1
///     pointer3_2 --> block2
///
///     subgraph head[Read Capability]
///       pointer_head["Pointer #️⃣"]
///       key_head["Key 🔑"]
///     end
///
///     pointer_head --> block3
/// ```
///
/// [causal encryption]: https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
pub struct Envelope<C: ContentRef, T> {
    /// The plaintext payload.
    pub plaintext: T,

    /// Any ancestors that this envelope depends on.
    #[derivative(
        PartialOrd(compare_with = "crate::util::partial_eq::hash_map_keys"),
        Hash(hash_with = "crate::util::hasher::hash_map_keys")
    )]
    pub ancestors: HashMap<C, SymmetricKey>,
}

impl<C: ContentRef, T: Decode> Envelope<C, T> {
    /// Open `encrypted` with its key, for the document `doc_id`: the ancestors
    /// from their own section, then the body, decoded as `T`.
    pub fn open<P>(
        encrypted: &EncryptedContent<P, C>,
        key: SymmetricKey,
        doc_id: Identifier,
    ) -> Result<Self, OpenEnvelopeError> {
        let ancestors = encrypted.try_decrypt_ancestors(key, doc_id)?;
        let body = encrypted.try_decrypt(key, doc_id)?;
        Ok(Envelope {
            plaintext: T::decode(&body).map_err(OpenEnvelopeError::Payload)?,
            ancestors: ancestors.into_iter().collect(),
        })
    }
}

/// Why [`Envelope::open`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenEnvelopeError {
    /// A section did not decrypt, or the ancestors section is malformed.
    #[error(transparent)]
    Decrypt(#[from] ContentDecryptError),

    /// The body decrypted, but is not a `T`.
    #[error("the payload does not decode: {0}")]
    Payload(DecodeError),
}
