use core::{fmt::Debug, hash::Hash};
use keyhive_codec::traits::{Encode, StreamDecode};

/// A reference to a piece of content, such as an Automerge change hash.
///
/// It is part of an encrypted block's header and of the causal envelopes that
/// contain ancestors' keys, so it has a canonical, self-delimiting encoding.
pub trait ContentRef: Debug + Clone + Eq + PartialOrd + Hash + Encode + StreamDecode {}

impl<T: Debug + Clone + Eq + PartialOrd + Hash + Encode + StreamDecode> ContentRef for T {}
