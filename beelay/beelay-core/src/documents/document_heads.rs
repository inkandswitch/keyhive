#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct DocumentHeads(Vec<crate::CommitHash>);

impl DocumentHeads {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for DocumentHeads {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[")?;
        for (idx, hash) in self.0.iter().enumerate() {
            if idx > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", hash)?;
        }
        write!(f, "]")
    }
}

impl<'a> IntoIterator for &'a DocumentHeads {
    type Item = &'a crate::CommitHash;
    type IntoIter = std::slice::Iter<'a, crate::CommitHash>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
