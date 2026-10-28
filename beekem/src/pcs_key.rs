//! The root secrets of a BeeKEM tree, which are the CGKA
//! group secrets.

use keyhive_crypto::{
    context::Context,
    digest::Digest,
    share_key::ShareSecretKey,
    signable::{Kind, Kinded},
    symmetric_key::SymmetricKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A key used to derive application secrets. Wiped when dropped, through its
/// [`ShareSecretKey`]; equality takes constant time.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PcsKey(pub ShareSecretKey);

impl PcsKey {
    /// Lift a `ShareSecretKey` into a `PcsKey`.
    pub fn new(share_secret_key: ShareSecretKey) -> Self {
        Self(share_secret_key)
    }

    /// A root secret decrypted from an invitation or a predecessor secret.
    /// Returns `None` unless `decrypted_secret` is 32 bytes.
    pub(crate) fn from_decrypted_secret(decrypted_secret: &[u8]) -> Option<Self> {
        ShareSecretKey::try_from_slice(decrypted_secret).map(Self::new)
    }

    /// The digest of this key.
    pub fn digest(&self) -> Digest<PcsKey> {
        Digest::of_bytes(self.0.as_slice())
    }

    /// Derive the key for encrypting the root secrets of an update's predecessors.
    pub(crate) fn derive_predecessor_secrets_key(&self) -> SymmetricKey {
        Context::CGKA_PREDECESSOR_SECRETS_KEY
            .derive_key(self.0.as_slice())
            .into()
    }
}

/// A PCS key is never signed or sent, only hashed. The digest is included
/// in each block's header so a reader can find the key that block's key came
/// from.
impl Kinded for PcsKey {
    const KIND: Kind = Kind::PCS_KEY;
    const VERSION: u8 = 0;
}

impl From<ShareSecretKey> for PcsKey {
    fn from(share_secret_key: ShareSecretKey) -> PcsKey {
        PcsKey(share_secret_key)
    }
}

// Fails to compile unless the key wipes itself when dropped and has a
// destructor, which a `Copy` type cannot have.
const _: () = assert!(core::mem::needs_drop::<PcsKey>());
const _: fn() = || {
    fn wiped_on_drop<T: ZeroizeOnDrop>() {}
    wiped_on_drop::<PcsKey>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn pcs_key() -> PcsKey {
        PcsKey::new(ShareSecretKey::force_from_bytes([1; 32]))
    }

    /// Checked with `b3sum --derive-key` under `CGKA_PREDECESSOR_SECRETS_KEY`
    /// over the root secret `[1; 32]`: one derivation.
    #[test]
    fn the_predecessor_secrets_key_is_one_derivation_from_the_root() {
        assert_eq!(
            pcs_key().derive_predecessor_secrets_key(),
            SymmetricKey::from(
                *blake3::Hash::from_hex(
                    "bd12f7975b80d7ca658430f18000b51ad68e568c109306adb0ba23b4a7501665"
                )
                .expect("hex")
                .as_bytes()
            )
        );
    }
}
