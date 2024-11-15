use crate::serialization::{parse, Encode, Parse};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum CommitCategory {
    Content,
    Links,
}

impl std::fmt::Display for CommitCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CommitCategory::Content => write!(f, "content"),
            CommitCategory::Links => write!(f, "links"),
        }
    }
}

impl Encode for CommitCategory {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            CommitCategory::Content => out.push(0),
            CommitCategory::Links => out.push(1),
        }
    }
}

impl Parse<'_> for CommitCategory {
    fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, CommitCategory), parse::ParseError> {
        input.parse_in_ctx("CommitCategory", |input| {
            let (input, cat) = parse::u8(input)?;
            match cat {
                0 => Ok((input, CommitCategory::Content)),
                1 => Ok((input, CommitCategory::Links)),
                other => Err(input.error(format!("invalid commit category {}", other))),
            }
        })
    }
}
