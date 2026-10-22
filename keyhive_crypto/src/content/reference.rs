use core::{fmt::Debug, hash::Hash};
use keyhive_codec::traits::{Encode, StreamDecode};
use serde::Serialize;

/// A reference to a piece of content, such as an Automerge change hash.
///
/// It is part of an encrypted block's header and of the causal envelopes that
/// carry ancestors' keys, so it has a canonical, self-delimiting encoding.
pub trait ContentRef:
    Debug + Serialize + Clone + Eq + PartialOrd + Hash + Encode + StreamDecode
{
}

impl<T: Debug + Serialize + Clone + Eq + PartialOrd + Hash + Encode + StreamDecode> ContentRef
    for T
{
}
