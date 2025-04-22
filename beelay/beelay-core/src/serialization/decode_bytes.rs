use super::{parse, Parse};

pub(crate) struct DecodeBytes(#[allow(dead_code)] Vec<u8>);

impl<'a> Parse<'a> for DecodeBytes {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, slice) = parse::slice(input)?;
        Ok((input, Self(slice.to_vec())))
    }
}

impl From<DecodeBytes> for Vec<u8> {
    fn from(value: DecodeBytes) -> Self {
        value.0
    }
}
