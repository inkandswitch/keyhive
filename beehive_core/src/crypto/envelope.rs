//! The (plaintext) container for causal encryption.

use super::{digest::Digest, read_capability::ReadCap, symmetric_key::SymmetricKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg_attr(all(doc, feature = "mermaid_docs"), aquamarine::aquamarine)]
/// A container for an arbitrary payload and the [`ReadCap`]s required to identify and decrypt its ancestors.
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
///     subgraph head[Read Capabilty]
///       pointer_head["Pointer #️⃣"]
///       key_head["Key 🔑"]
///     end
///
///     pointer_head --> block3
/// ```
///
/// [causal encryption]: https://github.com/inkandswitch/beehive/blob/main/design/causal_encryption.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Envelope<T: Serialize> {
    /// The plaintext payload.
    pub plaintext: T,

    /// Any ancestors that this envelope depends on.
    pub ancestors: BTreeMap<Digest<T>, SymmetricKey>,
}

impl<T: Serialize> Envelope<T> {
    pub fn ancestor_read_caps(&self) -> Vec<ReadCap<Digest<T>>> {
        self.ancestors
            .iter()
            .map(|(id, key)| ReadCap { id: *id, key: *key })
            .collect()
    }
}
