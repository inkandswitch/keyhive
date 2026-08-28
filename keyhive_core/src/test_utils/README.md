# Writing tests with the `TestContext` harness

The `TestContext` harness provides the following to help in writing tests:

* Creates keyhives and introduces them to each other.
* Moves events between them in a controlled order (simulating sync scenarios).
* Remembers which name goes with which identifier, so assertions can say `"bob"`.
* Provides helper functions to simplify tests, reduce repetition, and prevent subtle
  bugs in test setup.
* Chooses a content ref for encrypted content, and remembers which document it's
associated with.

`TestContext` uses the `Instance` type to represent a `Keyhive` instance for a
keyhive identity. `Instance` derefs to `Keyhive`, so you can still call the Keyhive
API directly (e.g., `alice.add_member(..)`). A single keyhive identity can have
several instances, and they share its signing key and its identifier.

## Example test

```rust
use keyhive_core::{
    access::Access::Read,
    test_utils::{TestContext, TestResult as Result},
};

#[tokio::test]
async fn a_reader_reads_what_a_member_wrote() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice.add_member(bob.id(), design_doc, Read, &[]).await?;
    let ct = ctx.encrypt(&alice, design_doc, b"hello world").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
        b"hello world".to_vec()
    );
    Ok(())
}
```

## Creating identities, groups and documents

* `ctx.individual(name)` creates an identity with one instance running.
* `ctx.new_keyhive_instance_for(&of, name)` creates a new instance of an existing
  identity, sharing its signing key. Cloning an `Instance` does not do this.
* `ctx.group(&creator, name)` creates a named `Group` and returns a `GroupId`.
* `ctx.doc(&creator, name)` creates a named `Document` and returns a `DocumentId`.
* `ctx.rebuild_from_archive(&archive, name)` builds a new `Keyhive` instance from the
  `Archive`, with a fresh ciphertext store. The signing key is the one the context
  holds for the archive's own identity.
* `ctx.adopt(hive, name)` takes a `Hive` the test built itself and registers it with
  the context, for an instance the context would not produce, such as a peer holding
  a particular signing key.

Every instance learns every other instance's contact card, so a `NotSynced` is about
events rather than introductions.

## Simulating syncing events

* `sync_all_unsent()` delivers every outstanding event to every keyhive instance.
  This will be the most common way to sync events in tests.
* `ctx.sync(&from, &to)` sends everything `to` is entitled to in one direction.
* `ctx.sync_as_public(&from, &to)` sends what a public reader may see.
* `ctx.sync_without(&from, &to, kind)` withholds one `EventKind` from what it
  delivers (e.g., to simulate a case where no CGKA ops were received yet).
* `ctx.sync_in_batches(..)` delivers in partial batches.
* `ctx.sync_shuffled(..)` delivers in a random order (replicable via a seed).
* `sync_all_unsent_within(rounds)` is like `sync_all_unsent` but puts the specified
  limit on how many times to run the settling loop.

## Checking test errors for failure assertions

The `TestContext` has one unified error vocabulary for failure reasons we want to
assert on. To match, you can use `map_err`:

```text
match bob.add_member(carol.id(), design_doc, Read, &[]).await.map_err(TestError::from) {
    Err(TestError::NoAuthority) => {}
    other => panic!("expected no authority, got {other:?}"),
}
```

## Writing content

`ctx.encrypt` and its siblings are here for two reasons:

* They choose the content ref so tests do not need to invent one and risk reusing
  one.
* They record which document each piece of content went into.
  `ctx.encrypt_after(&alice, design_doc, ..)` can therefore refuse a predecessor
  belonging to a different document with the `WrongDocument` test error, rather than
  leaving it to surface later as a failing decryption.

Decryption does not benefit in this way. Decrypt via the Keyhive API:
`bob.try_decrypt_content(design_doc, &ct)`.

Causal decryption is the exception, because the walk reads ancestors out of the
instance's own ciphertext store. So a reader has to be given the content first:
`ctx.give_content(&bob, &ct)`, once per piece of content.

## Guidelines for writing tests with `TestContext`

* Call `sync_all_unsent()` before checking anything about an instance other than
  the one that did the work, and before an instance delegates to a resource it did
  not create.
* Check one rule per test. If a test could fail for two unrelated reasons, split it.
* Name a test after the rule it checks, so `a_reader_cannot_delegate_edit_or_above`
  rather than `test_add_member_3`.
* Test the invariants keyhive must respect from the user of the `Keyhive` APIs
  perspective. Lower-level details belong in unit tests in the module that owns them.
