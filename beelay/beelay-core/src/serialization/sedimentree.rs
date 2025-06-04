use crate::documents::{IntoCommitHashes, IntoSedimentreeDigests};

use super::{parse, Encode, Parse};

impl Encode for sedimentree::StratumMeta {
    fn encode_into(&self, out: &mut Vec<u8>) {
        crate::CommitHash::from(self.start()).encode_into(out);
        crate::CommitHash::from(self.end()).encode_into(out);
        crate::blob::BlobMeta::from(self.blob()).encode_into(out);
    }
}
impl Parse<'_> for sedimentree::StratumMeta {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("StratumMeta", |input| {
            let (input, start) = crate::CommitHash::parse_in_ctx("start", input)?;
            let (input, end) = crate::CommitHash::parse_in_ctx("end", input)?;
            let (input, blob) = crate::blob::BlobMeta::parse_in_ctx("blob", input)?;
            Ok((
                input,
                sedimentree::StratumMeta::new(start.into(), end.into(), blob.into()),
            ))
        })
    }
}

impl Encode for sedimentree::LooseCommit {
    fn encode_into(&self, out: &mut Vec<u8>) {
        crate::CommitHash::from(self.hash()).encode_into(out);
        self.parents().to_commit_hashes().encode_into(out);
        crate::blob::BlobMeta::from(*self.blob()).encode_into(out);
    }
}

impl Parse<'_> for sedimentree::LooseCommit {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("LooseCommit", |input| {
            let (input, hash) = crate::CommitHash::parse_in_ctx("hash", input)?;
            let (input, parents) = Vec::<crate::CommitHash>::parse_in_ctx("parents", input)?;
            let (input, blob) = crate::blob::BlobMeta::parse_in_ctx("blob", input)?;
            Ok((
                input,
                sedimentree::LooseCommit::new(
                    hash.into(),
                    parents.as_slice().to_sedimentree_digests(),
                    blob.into(),
                ),
            ))
        })
    }
}

impl Encode for sedimentree::Stratum {
    fn encode_into(&self, out: &mut Vec<u8>) {
        crate::CommitHash::from(self.meta().start()).encode_into(out);
        crate::CommitHash::from(self.meta().end()).encode_into(out);
        crate::blob::BlobMeta::from(self.meta().blob()).encode_into(out);
        self.checkpoints().to_commit_hashes().encode_into(out);
        crate::CommitHash::from(self.hash()).encode_into(out);
    }
}

impl Parse<'_> for sedimentree::Stratum {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("Stratum", |input| {
            let (input, start) = crate::CommitHash::parse_in_ctx("start", input)?;
            let (input, end) = crate::CommitHash::parse_in_ctx("end", input)?;
            let (input, blob) = crate::blob::BlobMeta::parse_in_ctx("blob", input)?;
            let (input, checkpoints) =
                Vec::<crate::CommitHash>::parse_in_ctx("checkpoints", input)?;
            let (input, hash) = crate::CommitHash::parse_in_ctx("hash", input)?;
            Ok((
                input,
                sedimentree::Stratum::from_raw(
                    sedimentree::StratumMeta::new(start.into(), end.into(), blob.into()),
                    checkpoints.as_slice().to_sedimentree_digests(),
                    hash.into(),
                ),
            ))
        })
    }
}

impl Encode for sedimentree::SedimentreeSummary {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.strata()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .encode_into(out);
        self.commits()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .encode_into(out);
    }
}

impl Parse<'_> for sedimentree::SedimentreeSummary {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("SedimentreeSummary", |input| {
            let (input, strata) = Vec::<sedimentree::StratumMeta>::parse_in_ctx("strata", input)?;
            let (input, commits) = Vec::<sedimentree::LooseCommit>::parse_in_ctx("commits", input)?;
            Ok((
                input,
                sedimentree::SedimentreeSummary::from_raw(
                    strata.into_iter().collect(),
                    commits.into_iter().collect(),
                ),
            ))
        })
    }
}
