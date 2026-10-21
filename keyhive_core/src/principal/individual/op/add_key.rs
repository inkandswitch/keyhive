use dupe::Dupe;
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    share_key::ShareKey,
    signable::{Kind, Kinded},
};

/// Add a new key to the prekeys.
///
/// Encoded as its share key (32 bytes), and signed under
/// [`Kind::ADD_KEY`].
#[derive(Debug, Clone, Copy, Dupe, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct AddKeyOp {
    /// The key to add.
    pub share_key: ShareKey,
}

impl AddKeyOp {
    #[cfg(any(test, feature = "test_utils"))]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self {
            share_key: ShareKey::generate(csprng),
        }
    }
}

impl Kinded for AddKeyOp {
    const KIND: Kind = Kind::ADD_KEY;
    const VERSION: u8 = 0;
}

impl Encode for AddKeyOp {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.share_key.encode_into(out);
    }
}

impl Decode for AddKeyOp {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for AddKeyOp {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (share_key, rest) = ShareKey::decode_next(bytes)?;
        Ok((AddKeyOp { share_key }, rest))
    }
}
