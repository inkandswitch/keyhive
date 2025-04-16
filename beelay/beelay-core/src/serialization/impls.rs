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

impl<'a, T: Parse<'a>> Parse<'a> for Option<T> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, present) = parse::u8(input)?;
        if present != 1 {
            return Ok((input, None));
        }
        let (input, item) = T::parse(input)?;
        Ok((input, Some(item)))
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Some(item) => {
                out.push(1);
                item.encode_into(out);
            }
            None => out.push(0),
        }
    }
}

mod keyhive {
    use keyhive_core::{
        cgka::operation::CgkaOperation, crypto::signed::Signed, event::static_event::StaticEvent,
    };
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;

    use crate::{
        parse::{self, Parse},
        serialization::{leb128, Encode},
        CommitHash,
    };

    impl<T: Serialize + Debug> Encode for Signed<T> {
        fn encode_into(&self, out: &mut Vec<u8>) {
            let serialized = bincode::serialize(&self).unwrap();
            leb128::encode_uleb128(out, serialized.len() as u64);
            out.extend_from_slice(&serialized);
        }
    }

    impl<'a, T: Deserialize<'a> + Serialize + Debug> Parse<'a> for Signed<T> {
        fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
            let (input, bytes) = parse::slice(input)?;
            let signed = bincode::deserialize(bytes)
                .map_err(|e| input.error(format!("invalid signed data: {}", e)))?;
            Ok((input, signed))
        }
    }

    impl Encode for CgkaOperation {
        fn encode_into(&self, out: &mut Vec<u8>) {
            let serialized = bincode::serialize(&self).unwrap();
            leb128::encode_uleb128(out, serialized.len() as u64);
            out.extend_from_slice(&serialized);
        }
    }

    impl<'a> Parse<'a> for CgkaOperation {
        fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
            let (input, bytes) = parse::slice(input)?;
            let operation = bincode::deserialize(bytes)
                .map_err(|e| input.error(format!("invalid operation: {}", e)))?;
            Ok((input, operation))
        }
    }

    // impl Encode for StaticEvent<CommitHash> {
    //     fn encode_into(&self, out: &mut Vec<u8>) {
    //         let serialized = bincode::serialize(&self).unwrap();
    //         leb128::encode_uleb128(out, serialized.len() as u64);
    //         out.extend_from_slice(&serialized);
    //     }
    // }

    // impl<'a> Parse<'a> for StaticEvent<CommitHash> {
    //     fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
    //         let (input, arr) = parse::slice(input)?;
    //         let result = bincode::deserialize(arr)
    //             .map_err(|e| input.error(format!("invalid event: {}", e)))?;
    //         Ok((input, result))
    //     }
    // }
}
