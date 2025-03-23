//! Helpers for working with hexadecimal

use std::{fmt::Write, iter::Iterator};

/// Convert some bytes to their hexidecimal representation.
///
/// This does not include the `0x` prefix. It is mainly helpful in implementing
/// [`std::fmt::LowerHex`] on the way to implement [`std::fmt::Display`].
pub(crate) fn bytes_as_hex<'a, I: Iterator<Item = &'a u8>>(
    mut byte_iter: I,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    if f.alternate() {
        write!(f, "0x")?;
    }

    byte_iter.try_fold((), |_, byte| write!(f, "{:02x}", byte))
}

pub(crate) fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut buf = String::new();
    write!(&mut buf, "0x").expect("writing to a string should not fail");
    bytes
        .iter()
        .try_fold((), |_, byte| write!(&mut buf, "{:02x}", byte))
        .expect("writing to a string should not fail");
    buf
}

pub(crate) trait ToHexString {
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

    #[test]
    fn test_bytes_as_hex() {
        #[derive(Debug)]
        struct Test;

        impl std::fmt::LowerHex for Test {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let bytes = [0x00, 0x01, 0x02, 0x03, 0xff];
                bytes_as_hex(bytes.iter(), f)
            }
        }

        assert_eq!(format!("{:?}", Test), "Test");
        assert_eq!(format!("{:x}", Test), "00010203ff");
        assert_eq!(format!("{:#x}", Test), "0x00010203ff");
    }
}
