use super::CommitHash;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Commit {
    parents: Vec<CommitHash>,
    contents: Vec<u8>,
    hash: CommitHash,
}

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for Commit {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let parents = Vec::<CommitHash>::arbitrary(u)?;
        let contents = Vec::<u8>::arbitrary(u)?;
        let hash = [u8::arbitrary(u)?; 32];
        Ok(Commit::new(parents, contents, hash.into()))
    }
}

impl Commit {
    pub fn new(parents: Vec<CommitHash>, contents: Vec<u8>, hash: CommitHash) -> Self {
        Commit {
            parents,
            hash,
            contents,
        }
    }

    pub fn parents(&self) -> &[CommitHash] {
        &self.parents
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn hash(&self) -> CommitHash {
        self.hash
    }
}
