use crate::parse;

pub(crate) fn encode_uleb128(buf: &mut Vec<u8>, mut val: u64) -> usize {
    let mut bytes_written = 0;
    loop {
        let mut byte = low_bits_of_u64(val);
        val >>= 7;
        if val != 0 {
            // More bytes to come, so set the continuation bit.
            byte |= CONTINUATION_BIT;
        }

        buf.push(byte);
        bytes_written += 1;

        if val == 0 {
            return bytes_written;
        }
    }
}

pub(crate) fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, u64), parse::ParseError> {
    let mut res = 0;
    let mut shift = 0;
    let mut input = input;

    loop {
        let (i, byte) = parse::u8(input)?;
        input = i;
        res |= ((byte & 0x7F) as u64) << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            if shift > 64 && byte > 1 {
                return Err(input.error("LEB128 value too large"));
            } else if shift > 7 && byte == 0 {
                return Err(input.error("LEB128 value is overlong"));
            }
            return Ok((input, res));
        } else if shift > 64 {
            return Err(input.error("LEB128 value too large"));
        }
    }
}

const CONTINUATION_BIT: u8 = 1 << 7;

#[inline]
fn low_bits_of_byte(byte: u8) -> u8 {
    byte & !CONTINUATION_BIT
}

#[inline]
fn low_bits_of_u64(val: u64) -> u8 {
    let byte = val & (u8::MAX as u64);
    low_bits_of_byte(byte as u8)
}

pub(crate) mod signed {
    use crate::parse;

    pub fn encode(buf: &mut Vec<u8>, mut val: i64) {
        loop {
            let mut byte = val as u8;
            // Keep the sign bit for testing
            val >>= 6;
            let done = val == 0 || val == -1;
            if done {
                byte &= !super::CONTINUATION_BIT;
            } else {
                // Remove the sign bit
                val >>= 1;
                // More bytes to come, so set the continuation bit.
                byte |= super::CONTINUATION_BIT;
            }

            buf.push(byte);

            if done {
                return;
            }
        }
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, i64), parse::ParseError> {
        let mut res = 0;
        let mut shift = 0;

        let mut input = input;
        let mut prev = 0;
        loop {
            let (i, byte) = parse::u8(input)?;
            input = i;
            res |= ((byte & 0x7F) as i64) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                if shift > 64 && byte != 0 && byte != 0x7f {
                    // the 10th byte (if present) must contain only the sign-extended sign bit
                    return Err(input.error("LEB128 value too large"));
                } else if shift > 7
                    && ((byte == 0 && prev & 0x40 == 0) || (byte == 0x7f && prev & 0x40 > 0))
                {
                    // overlong if the sign bit of penultimate byte has been extended
                    return Err(input.error("LEB128 value is overlong"));
                } else if shift < 64 && byte & 0x40 > 0 {
                    // sign extend negative numbers
                    res |= -1 << shift;
                }
                return Ok((input, res));
            } else if shift > 64 {
                return Err(input.error("LEB128 value too large"));
            }
            prev = byte;
        }
    }
}
