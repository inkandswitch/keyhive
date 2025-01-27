pub(crate) use error::{NotEnoughInput, ParseError};

use super::leb128;

pub(crate) trait Parse<'a>: Sized {
    fn parse(input: Input<'a>) -> Result<(Input<'a>, Self), ParseError>;
    fn parse_in_ctx(ctx: &'static str, input: Input<'a>) -> Result<(Input<'a>, Self), ParseError> {
        input.parse_in_ctx(ctx, Self::parse)
    }
}

#[derive(Clone)]
pub(crate) struct Input<'a> {
    // This field is used for more detailed error messages in debug builds
    #[cfg(debug_assertions)]
    context: Vec<&'static str>,
    data: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            #[cfg(debug_assertions)]
            context: Vec::new(),
        }
    }

    fn read(self, len: usize) -> Option<(Self, &'a [u8])> {
        if len > self.data.len() {
            return None;
        }
        let (read, rest) = self.data.split_at(len);
        Some((
            Self {
                data: rest,
                #[cfg(debug_assertions)]
                context: self.context,
                offset: self.offset + len,
            },
            read,
        ))
    }

    pub(crate) fn parse_in_ctx<
        T,
        F: FnOnce(Input<'a>) -> Result<(Input<'a>, T), error::ParseError>,
    >(
        #[allow(unused_mut)] mut self,
        #[allow(unused_variables)] context: &'static str,
        f: F,
    ) -> Result<(Input<'a>, T), error::ParseError> {
        #[cfg(debug_assertions)]
        {
            self.context.push(context);
            let (mut input, result) = f(self)?;
            input.context.pop();
            Ok((input, result))
        }
        #[cfg(not(debug_assertions))]
        f(self)
    }

    pub(crate) fn error<S: AsRef<str>>(&self, msg: S) -> error::ParseError {
        error::ParseError::Other {
            #[cfg(debug_assertions)]
            context: self.context.clone(),
            error: msg.as_ref().to_string(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }
}

pub(crate) fn u8(input: Input<'_>) -> Result<(Input<'_>, u8), error::ParseError> {
    if let Some((input, data)) = input.read(1) {
        Ok((input, data[0]))
    } else {
        Err(error::ParseError::NotEnoughInput)
    }
}

pub(crate) fn u64_be(input: Input<'_>) -> Result<(Input<'_>, u64), error::ParseError> {
    if let Some((input, data)) = input.read(8) {
        Ok((input, u64::from_be_bytes(data.try_into().unwrap())))
    } else {
        Err(error::ParseError::NotEnoughInput)
    }
}

#[allow(dead_code)]
pub(crate) fn bool(input: Input<'_>) -> Result<(Input<'_>, bool), error::ParseError> {
    let (input, data) = u8(input)?;
    Ok((input, data != 0))
}

pub(crate) fn slice(input: Input<'_>) -> Result<(Input<'_>, &'_ [u8]), error::ParseError> {
    let (input, len) = input.parse_in_ctx("slice length", leb128::parse)?;
    let (input, data) = input
        .read(len as usize)
        .ok_or(error::ParseError::NotEnoughInput)?;
    // .ok_or::<E>(error::NotEnoughInput.into())?;
    Ok((input, data))
}

pub(crate) fn str(input: Input<'_>) -> Result<(Input<'_>, &'_ str), error::ParseError> {
    let (input, data) = slice(input)?;
    let result =
        std::str::from_utf8(data).map_err(|e| input.error(format!("invalid string: {}", e)))?;
    Ok((input, result))
}

pub(crate) fn arr<const N: usize>(
    input: Input<'_>,
) -> Result<(Input<'_>, [u8; N]), error::ParseError> {
    let mut res = [0; N];

    let (input, bytes) = input.read(N).ok_or(error::ParseError::NotEnoughInput)?;

    res.copy_from_slice(bytes);
    Ok((input, res))
}

pub(crate) mod error {
    pub struct NotEnoughInput;

    impl std::fmt::Display for NotEnoughInput {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "not enough input")
        }
    }

    impl std::fmt::Debug for NotEnoughInput {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for NotEnoughInput {}

    pub enum ParseError {
        NotEnoughInput,
        Other {
            #[cfg(debug_assertions)]
            context: Vec<&'static str>,
            error: String,
        },
    }

    impl std::fmt::Display for ParseError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ParseError::NotEnoughInput => write!(f, "not enough input"),
                #[cfg(debug_assertions)]
                ParseError::Other { context, error } => {
                    write!(f, "error: {}", error)?;
                    for ctx in context {
                        write!(f, "\n  in {}", ctx)?;
                    }
                    Ok(())
                }
                #[cfg(not(debug_assertions))]
                ParseError::Other { error } => {
                    write!(f, "error: {}", error)
                }
            }
        }
    }

    impl std::fmt::Debug for ParseError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for ParseError {}
}
