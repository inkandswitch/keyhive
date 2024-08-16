pub(crate) use error::{NotEnoughInput, ParseError};

#[derive(Clone)]
pub(super) struct Input<'a> {
    context: Vec<String>,
    data: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
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
                context: self.context,
                offset: self.offset + len,
            },
            read,
        ))
    }

    pub(crate) fn with_context<
        S: AsRef<str>,
        T,
        F: for<'b> Fn(Input<'b>) -> Result<(Input<'b>, T), error::ParseError>,
    >(
        mut self,
        context: S,
        f: F,
    ) -> Result<(Input<'a>, T), error::ParseError> {
        self.context.push(context.as_ref().to_string());
        let (mut input, result) = f(self)?;
        input.context.pop();
        Ok((input, result))
    }

    pub(crate) fn error<S: AsRef<str>>(&self, msg: S) -> error::ParseError {
        error::ParseError::Other {
            context: self.context.clone(),
            error: msg.as_ref().to_string(),
        }
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }
}

pub(super) fn u8(input: Input<'_>) -> Result<(Input<'_>, u8), error::ParseError> {
    if let Some((input, data)) = input.read(1) {
        Ok((input, data[0]))
    } else {
        Err(error::ParseError::NotEnoughInput)
    }
}

#[allow(dead_code)]
pub(super) fn bool(input: Input<'_>) -> Result<(Input<'_>, bool), error::ParseError> {
    let (input, data) = u8(input)?;
    Ok((input, data != 0))
}

pub(super) fn slice(input: Input<'_>) -> Result<(Input<'_>, &'_ [u8]), error::ParseError> {
    let (input, len) = input.with_context("slice length", crate::leb128::parse)?;
    let (input, data) = input
        .read(len as usize)
        .ok_or(error::ParseError::NotEnoughInput)?;
    // .ok_or::<E>(error::NotEnoughInput.into())?;
    Ok((input, data))
}

pub(super) fn str(input: Input<'_>) -> Result<(Input<'_>, &'_ str), error::ParseError> {
    let (input, data) = slice(input)?;
    let result =
        std::str::from_utf8(data).map_err(|e| input.error(format!("invalid string: {}", e)))?;
    Ok((input, result))
}

pub(super) fn many<F: for<'b> Fn(Input<'b>) -> Result<(Input<'b>, T), error::ParseError>, T>(
    input: Input<'_>,
    f: F,
) -> Result<(Input<'_>, Vec<T>), error::ParseError> {
    let mut res = Vec::new();
    let (mut input, count) = input.with_context("number of items", crate::leb128::parse)?;

    for elem in 0..count {
        let (i, v) = input.with_context(format!("element {}", elem), &f)?;
        // let (i, v) = f(input)?;
        input = i;
        res.push(v);
    }

    Ok((input, res))
}

pub(super) fn arr<const N: usize>(
    input: Input<'_>,
) -> Result<(Input<'_>, [u8; N]), error::ParseError> {
    let mut res = [0; N];

    let (input, bytes) = input.read(N).ok_or(error::ParseError::NotEnoughInput)?;

    res.copy_from_slice(bytes);
    Ok((input, res))
}

pub(super) mod error {
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
        Other { context: Vec<String>, error: String },
    }

    impl std::fmt::Display for ParseError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ParseError::NotEnoughInput => write!(f, "not enough input"),
                ParseError::Other { context, error } => {
                    write!(f, "error: {}", error)?;
                    for ctx in context {
                        write!(f, "\n  in {}", ctx)?;
                    }
                    Ok(())
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
