use super::{leb128, parse, Encode, Parse};

pub(crate) struct EncodeBytes<'a>(&'a [u8]);

impl<'a> Encode for EncodeBytes<'a> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        leb128::encode_uleb128(out, self.0.len() as u64);
        out.extend_from_slice(self.0);
    }
}

impl<'a> From<&'a [u8]> for EncodeBytes<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

impl<'a> From<&'a Vec<u8>> for EncodeBytes<'a> {
    fn from(value: &'a Vec<u8>) -> Self {
        Self(value.as_slice())
    }
}

impl<'a> Parse<'a> for EncodeBytes<'a> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, bytes) = parse::slice(input)?;
        Ok((input, Self(bytes)))
    }
}
