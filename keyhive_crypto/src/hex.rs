//! Helpers for working with hexadecimal

use alloc::string::String;
use core::{fmt::Write, iter::Iterator};

/// Convert some bytes to their hexidecimal representation.
///
/// This does not include the `0x` prefix. It is mainly helpful in implementing
/// [`core::fmt::LowerHex`] on the way to implement [`core::fmt::Display`].
pub fn bytes_as_hex<'a, I: Iterator<Item = &'a u8>>(
    mut byte_iter: I,
    f: &mut core::fmt::Formatter<'_>,
) -> core::fmt::Result {
    if f.alternate() {
        write!(f, "0x")?;
    }

    byte_iter.try_fold((), |_, byte| write!(f, "{:02x}", byte))
}

pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut buf = String::new();
    write!(&mut buf, "0x").expect("writing to a string should not fail");
    bytes
        .iter()
        .try_fold((), |_, byte| write!(&mut buf, "{:02x}", byte))
        .expect("writing to a string should not fail");
    buf
}

pub trait ToHexString {
    fn to_hex_string(&self) -> String;
}

impl ToHexString for ed25519_dalek::VerifyingKey {
    fn to_hex_string(&self) -> String {
        bytes_to_hex_string(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_bytes_as_hex() {
        #[derive(Debug)]
        struct Test;

        impl core::fmt::LowerHex for Test {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let bytes = [0x00, 0x01, 0x02, 0x03, 0xff];
                bytes_as_hex(bytes.iter(), f)
            }
        }

        assert_eq!(format!("{:?}", Test), "Test");
        assert_eq!(format!("{:x}", Test), "00010203ff");
        assert_eq!(format!("{:#x}", Test), "0x00010203ff");
    }
}
