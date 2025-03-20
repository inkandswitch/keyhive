//! The (plaintext) container for causal encryption.

use super::{read_capability::ReadCap, symmetric_key::SymmetricKey};
use crate::content::reference::ContentRef;
use derivative::Derivative;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, HashMap},
    hash::{DefaultHasher, Hasher},
};
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
/// [causal encryption]: https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md
#[derive(Debug, Clone, PartialEq, Eq, Derivative, Serialize, Deserialize)]
pub struct Envelope<C: ContentRef + DeserializeOwned, T: Serialize> {
    /// The plaintext payload.
    pub plaintext: T,

    /// Any ancestors that this envelope depends on.
    #[serde(
        serialize_with = "ordered_map_serializer",
        deserialize_with = "ordered_map_deserializer"
    )]
    #[derivative(
        PartialOrd(compare_with = "crate::util::partial_eq::hash_map_keys"),
        Hash(hash_with = "crate::util::hasher::hash_map_keys")
    )]
    pub ancestors: HashMap<C, SymmetricKey>,
}

impl<T: Serialize, C: ContentRef + DeserializeOwned> Envelope<C, T> {
    /// Extract the [read capabilities][ReadCap] for the ancestors of this envelope.
    pub fn ancestor_read_caps(&self) -> Vec<ReadCap<C>> {
        self.ancestors
            .iter()
            .map(|(id, key)| ReadCap {
                id: id.clone(),
                key: *key,
            })
            .collect()
    }
}

fn ordered_map_serializer<S, K: ContentRef, V: Serialize>(
    map: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = map
        .iter()
        .map(|(k, v)| {
            let mut hasher = DefaultHasher::new();
            (*k).hash(&mut hasher);
            (hasher.finish(), (k, v))
        })
        .collect();
    ordered.serialize(serializer)
}

fn ordered_map_deserializer<'de, D, K: ContentRef + Deserialize<'de>, V: Deserialize<'de>>(
    deserializer: D,
) -> Result<HashMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ordered: BTreeMap<u64, (K, V)> = Deserialize::deserialize(deserializer)?;
    Ok(ordered.into_iter().map(|(_, (k, v))| (k, v)).collect())
}
