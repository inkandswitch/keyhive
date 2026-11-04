//! Serializable representation of an [`Active`][super::Active] individual.

use crate::principal::individual::IndividualState;
use keyhive_codec::{
    error::DecodeError,
    prefixed::encode_len,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    secret::{write_secret, Sink},
    share_key::{ShareKey, ShareSecretKey},
};
use std::{
    collections::BTreeMap,
    fmt,
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ActiveArchive {
    pub(crate) key_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`IndividualState`] representation (how others see it).
    pub(crate) individual: IndividualState,
}

impl Debug for ActiveArchive {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // NOTE this pattern ensures that all fields are used
        let Self {
            key_pairs,
            individual,
        } = self;
        f.debug_struct("ActiveArchive")
            .field("key_pairs", &key_pairs.keys())
            .field("individual", &individual)
            .finish()
    }
}

impl Hash for ActiveArchive {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NOTE this pattern ensures that all fields are used
        let Self {
            key_pairs,
            individual,
        } = self;
        key_pairs.keys().collect::<Vec<_>>().hash(state);
        individual.hash(state);
    }
}

impl PartialEq for ActiveArchive {
    fn eq(&self, other: &Self) -> bool {
        // NOTE this pattern ensures that all fields are used
        let Self {
            key_pairs,
            individual,
        } = self;
        *key_pairs == other.key_pairs && *individual == other.individual
    }
}

impl Eq for ActiveArchive {}

/// `key_pairs ‖ individual`, the key pairs as a count and then ascending by
/// key. Decoding refuses a secret that is not its key's, as importing them
/// does.
///
/// `out` is not wiped and may reallocate, so this leaves copies of the secret
/// keys. To store them, use [`Archive::encode_zeroizing`](crate::archive::Archive::encode_zeroizing)
/// or [`encode_key_pairs`].
impl Encode for ActiveArchive {
    fn encode_into(&self, out: &mut Vec<u8>) {
        write_key_pairs(&self.key_pairs, out);
        self.individual.encode_into(out);
    }
}

impl Decode for ActiveArchive {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for ActiveArchive {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (key_pairs, rest) = BTreeMap::<ShareKey, ShareSecretKey>::decode_next(bytes)?;
        if key_pairs.iter().any(|(pk, sk)| sk.share_key() != *pk) {
            return Err(DecodeError::InvalidField("key_pairs"));
        }
        let (individual, rest) = IndividualState::decode_next(rest)?;
        Ok((
            ActiveArchive {
                key_pairs,
                individual,
            },
            rest,
        ))
    }
}

/// Encode `key_pairs`, `count ‖ ( share_key ‖ secret )*`, into a buffer that
/// is wiped when dropped and never grows, so it leaves no copy of a secret.
pub fn encode_key_pairs(key_pairs: &BTreeMap<ShareKey, ShareSecretKey>) -> Zeroizing<Vec<u8>> {
    write_secret(key_pairs_len(key_pairs), |out| {
        write_key_pairs(key_pairs, out)
    })
}

/// `count ‖ ( share_key ‖ secret )*`, ascending by key: the map's
/// [`Encode`] layout. The archive and the prekey export write the key pairs
/// only through this, into a `Vec` to encode and into a wiped buffer to store.
/// The generic map encoding gives the same bytes, and a test checks that.
pub(crate) fn write_key_pairs<S: Sink>(
    key_pairs: &BTreeMap<ShareKey, ShareSecretKey>,
    out: &mut S,
) {
    let mut count = Vec::new();
    encode_len(key_pairs.len(), &mut count);
    out.put(&count);
    for (pk, sk) in key_pairs {
        out.put(pk.encode().as_bytes());
        out.put(sk.as_slice());
    }
}

/// The length of `key_pairs`' encoding, found without writing a secret.
pub(crate) fn key_pairs_len(key_pairs: &BTreeMap<ShareKey, ShareSecretKey>) -> usize {
    /// A share key and its secret, 32 bytes each.
    const KEY_PAIR_LEN: usize = 64;

    let mut count = Vec::new();
    encode_len(key_pairs.len(), &mut count);
    count.len() + key_pairs.len() * KEY_PAIR_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestContext, TestResult};

    /// An active individual's archive, with its key pairs and its prekey
    /// operations, decodes to itself, and the key pairs lead its encoding.
    #[tokio::test]
    async fn an_active_archive_round_trips() -> TestResult<()> {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let active = alice.into_archive().await?.active;
        assert!(
            !active.key_pairs.is_empty(),
            "precondition: the archive holds key pairs"
        );

        let bytes = active.encode().into_bytes();
        assert!(bytes.starts_with(&encode_key_pairs(&active.key_pairs)));
        assert_eq!(ActiveArchive::decode(&bytes).as_ref(), Ok(&active));
        Ok(())
    }

    /// The wiped encoding is the key pairs' encoding, byte for byte, as the
    /// generic map encoding writes it, and it decodes back to them.
    #[test]
    fn key_pairs_encode_the_same_into_a_wiped_buffer() {
        bolero::check!()
            .with_arbitrary::<Vec<[u8; 32]>>()
            .for_each(|secrets| {
                let key_pairs: BTreeMap<_, _> = secrets
                    .iter()
                    .map(|bytes| {
                        let secret = ShareSecretKey::force_from_bytes(*bytes);
                        (secret.share_key(), secret)
                    })
                    .collect();
                let wiped = encode_key_pairs(&key_pairs);
                assert_eq!(wiped.as_slice(), key_pairs.encode().as_bytes());
                assert_eq!(
                    BTreeMap::<ShareKey, ShareSecretKey>::decode(wiped.as_slice()).as_ref(),
                    Ok(&key_pairs)
                );
            });
    }
}
