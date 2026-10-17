use dupe::Dupe;
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    share_key::ShareKey,
    signable::{Kind, Kinded},
};

/// Retire a prekey and replace it with a new one.
///
/// Encoded as `old ‖ new` (64 bytes), and signed under
/// [`Kind::ROTATE_KEY`]. Decoding refuses `old == new`: replacing a key with
/// itself would retire it, leaving one fewer prekey than it claims.
#[derive(Debug, Clone, Copy, Dupe, PartialEq, Eq, Hash)]
pub struct RotateKeyOp {
    /// The prekey to remove.
    pub old: ShareKey,

    /// The prekey that replaces the old one.
    pub new: ShareKey,
}

impl Kinded for RotateKeyOp {
    const KIND: Kind = Kind::ROTATE_KEY;
    const VERSION: u8 = 0;
}

impl Encode for RotateKeyOp {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.old.encode_into(out);
        self.new.encode_into(out);
    }
}

impl Decode for RotateKeyOp {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for RotateKeyOp {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (old, rest) = ShareKey::decode_next(bytes)?;
        let (new, rest) = ShareKey::decode_next(rest)?;
        if new == old {
            return Err(DecodeError::InvalidField("new"));
        }
        Ok((RotateKeyOp { old, new }, rest))
    }
}

/// Only rotations that decode: `old != new`.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for RotateKeyOp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let (old, new) = u.arbitrary()?;
        if old == new {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        Ok(RotateKeyOp { old, new })
    }
}
