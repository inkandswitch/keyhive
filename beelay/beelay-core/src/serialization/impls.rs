use super::{
    encode::Encode,
    leb128,
    parse::{self, Parse},
};

impl Encode for u8 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl<'a> Parse<'a> for u8 {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        parse::u8(input)
    }
}

impl Encode for String {
    fn encode_into(&self, out: &mut Vec<u8>) {
        leb128::encode_uleb128(out, self.len() as u64);
        out.extend_from_slice(self.as_bytes());
    }
}

impl<'a> Parse<'a> for String {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, bytes) = parse::slice(input)?;
        let string = std::str::from_utf8(bytes)
            .map_err(|e| input.error(format!("invalid string: {}", e)))?;
        Ok((input, string.to_string()))
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        leb128::encode_uleb128(out, self.len() as u64);
        for item in self {
            item.encode_into(out);
        }
    }
}

impl<'a, T: Parse<'a>> Parse<'a> for Vec<T> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, len) = leb128::parse(input)?;
        let mut items = Vec::with_capacity(len as usize);
        let mut input = input;
        for _ in 0..len {
            let (new_input, item) = T::parse(input)?;
            items.push(item);
            input = new_input;
        }
        Ok((input, items))
    }
}

impl Encode for &str {
    fn encode_into(&self, out: &mut Vec<u8>) {
        leb128::encode_uleb128(out, self.len() as u64);
        out.extend_from_slice(self.as_bytes());
    }
}

impl<'a> Parse<'a> for &'a str {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, bytes) = parse::slice(input)?;
        let string = std::str::from_utf8(bytes)
            .map_err(|e| input.error(format!("invalid string: {}", e)))?;
        Ok((input, string))
    }
}

impl<T: Encode> Encode for Box<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        T::encode_into(self.as_ref(), out);
    }
}

impl<'a, T: Parse<'a>> Parse<'a> for Box<T> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, item) = T::parse(input)?;
        Ok((input, Box::new(item)))
    }
}
