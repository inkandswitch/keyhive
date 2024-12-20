//! Helpers for working with hexadecimal

use std::iter::Iterator;

/// Convert some bytes to their hexidecimal representation.
///
/// This does not include the `0x` prefix. It is mainly helpful in implementing
/// [`std::fmt::LowerHex`] on the way to implement [`std::fmt::Display`].
pub fn bytes_as_hex<'a, I: Iterator<Item = &'a u8>>(
    byte_iter: I,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    if f.alternate() {
        write!(f, "0x")?;
    }

    byte_iter.fold(Ok(()), |_, byte| write!(f, "{:02x}", byte))
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
