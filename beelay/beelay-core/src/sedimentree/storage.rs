use futures::StreamExt;

use crate::{
    blob::BlobMeta, effects::TaskEffects, parse, Commit, CommitBundle, CommitOrBundle, StorageKey,
};

use super::{Diff, LooseCommit, Sedimentree, Stratum};

pub(crate) async fn load<R: rand::Rng>(
    effects: TaskEffects<R>,
    path: StorageKey,
) -> Option<Sedimentree> {
    let strata = {
        let effects = effects.clone();
        let path = path.with_subcomponent("strata");
        async move {
            let raw = effects.load_range(path).await;
            if raw.is_empty() {
                return None;
            }
            let mut result = Vec::new();
            for (key, bytes) in raw {
                match Stratum::parse(parse::Input::new(&bytes)) {
                    Ok((input, stratum)) => {
                        if !input.is_empty() {
                            tracing::warn!(%key, "leftoever input when parsing stratum");
                        }
                        result.push(stratum);
                    }
                    Err(e) => {
                        tracing::warn!(err=?e, %key, "error loading stratum")
                    }
                }
            }
            Some(result)
        }
    };
    let commits = async move {
        let raw = effects
            .load_range(path.with_subcomponent("loose_commits"))
            .await;
        if raw.is_empty() {
            return None;
        }
        let mut result = Vec::new();
        for (key, bytes) in raw {
            tracing::trace!(%key, "loading loose commit");
            match LooseCommit::parse(parse::Input::new(&bytes)) {
                Ok((input, commit)) => {
                    if !input.is_empty() {
                        tracing::warn!(%key, "leftoever input when parsing loose commit");
                    }
                    result.push(commit);
                }
                Err(e) => {
                    tracing::warn!(err=?e, %key, "error loading loose commit");
                }
            }
        }
        Some(result)
    };
    let (stratum, commits) = futures::future::join(strata, commits).await;
    match (stratum, commits) {
        (None, None) => None,
        (maybe_stratum, maybe_commits) => Some(Sedimentree::new(
            maybe_stratum.unwrap_or_default(),
            maybe_commits.unwrap_or_default(),
        )),
    }
}

pub(crate) async fn update<R: rand::Rng>(
    effects: TaskEffects<R>,
    path: StorageKey,
    original: Option<&Sedimentree>,
    new: &Sedimentree,
) {
    let (new_strata, new_commits) = original
        .map(|o| {
            let Diff {
                left_missing_strata: _deleted_strata,
                left_missing_commits: _deleted_commits,
                right_missing_strata: new_strata,
                right_missing_commits: new_commits,
            } = o.diff(new);
            (new_strata, new_commits)
        })
        .unwrap_or_else(|| (new.strata.iter().collect(), new.commits.iter().collect()));

    let save_strata = {
        let effects = effects.clone();
        let path = path.clone();
        new_strata.into_iter().map(move |s| {
            let effects = effects.clone();
            let path = path.clone();
            async move {
                let key = strata_path(&path, s);
                let mut data = Vec::new();
                s.encode(&mut data);
                effects.put(key, data).await;
            }
        })
    };

    let save_commits = new_commits.into_iter().map(move |c| {
        let effects = effects.clone();
        let path = path.clone();
        async move {
            let key = commit_path(&path, c);
            let mut data = Vec::new();
            c.encode(&mut data);
            effects.put(key, data).await;
        }
    });

    futures::future::join(
        futures::future::join_all(save_strata),
        futures::future::join_all(save_commits),
    )
    .await;
}

pub(crate) fn data<R: rand::Rng>(
    effects: TaskEffects<R>,
    tree: Sedimentree,
) -> impl futures::Stream<Item = CommitOrBundle> {
    let items = tree.into_items().map(|item| {
        let effects = effects.clone();
        async move {
            match item {
                super::CommitOrStratum::Commit(c) => {
                    let data = effects.load(StorageKey::blob(c.blob().hash())).await?;
                    Some(CommitOrBundle::Commit(Commit::new(
                        c.parents().to_vec(),
                        data,
                        c.hash(),
                    )))
                }
                super::CommitOrStratum::Stratum(s) => {
                    let data = effects.load(StorageKey::blob(s.meta().blob().hash())).await;
                    let data = data?;
                    Some(CommitOrBundle::Bundle(
                        CommitBundle::builder()
                            .start(s.start())
                            .end(s.end())
                            .bundled_commits(data)
                            .checkpoints(s.checkpoints().to_vec())
                            .build(),
                    ))
                }
            }
        }
    });
    futures::stream::FuturesUnordered::from_iter(items).filter_map(futures::future::ready)
}

pub(crate) async fn write_loose_commit<R: rand::Rng>(
    effects: TaskEffects<R>,
    path: StorageKey,
    commit: &LooseCommit,
) {
    let key = commit_path(&path, commit);
    let mut data = Vec::new();
    commit.encode(&mut data);
    effects.put(key, data).await;
}

pub(crate) async fn write_bundle<R: rand::Rng>(
    effects: TaskEffects<R>,
    path: StorageKey,
    bundle: CommitBundle,
) {
    let blob = BlobMeta::new(bundle.bundled_commits());
    effects
        .put(
            StorageKey::blob(blob.hash()),
            bundle.bundled_commits().to_vec(),
        )
        .await;
    let stratum = Stratum::new(
        bundle.start(),
        bundle.end(),
        bundle.checkpoints().to_vec(),
        blob,
    );
    let key = strata_path(&path, &stratum);
    let mut stratum_bytes = Vec::new();
    stratum.encode(&mut stratum_bytes);
    effects.put(key, stratum_bytes).await;
}

fn strata_path(prefix: &StorageKey, s: &Stratum) -> StorageKey {
    let stratum_name = format!("{}-{}", s.start(), s.end());
    prefix
        .with_subcomponent("strata")
        .with_subcomponent(stratum_name)
}

fn commit_path(prefix: &StorageKey, c: &LooseCommit) -> StorageKey {
    prefix
        .with_subcomponent("loose_commits")
        .with_subcomponent(c.hash().to_string())
}
