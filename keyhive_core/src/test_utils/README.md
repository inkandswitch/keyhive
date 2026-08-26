# Writing tests with the `TextContext` harness

The `TestContext` harness provides the following to assist in writing tests:

* Creates keyhives and introduces them to each other.
* Moves events between them in a controlled order (simulating sync scenarios).
* Chooses a content ref for a piece of content.
* Remembers which name goes with which identifier, so assertions can say `"bob"`.
* Provides helper functions to simplify tests, reduce repetition, and prevent subtle bugs in
test setup.

`TestContext` uses the `Instance` type to represent a `Keyhive` instance for a keyhive
identity. `Instance` derefs to `Keyhive`, so you can still call the Keyhive API directly
(e.g., `alice.add_member(..)`). Each instance has an `InstanceId`. A single keyhive identity
can correspond to multiple `InstanceId`s.

## Example test

```rust
use keyhive_core::access::Access::Read;
use keyhive_core::keyhive::RelevantDocs;
use keyhive_core::test_utils::{TestContext, TestResult as Result};

#[tokio::test]
async fn a_reader_reads_what_a_member_wrote() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;

    alice
        .add_member(bob.id(), design_doc, Read, RelevantDocs::Reachable)
        .await?;
    let ct = ctx.encrypt(&alice, design_doc, b"hello").await?;
    ctx.sync_all_unsent().await?;

    assert_eq!(
        bob.try_decrypt_content(design_doc, &ct).await?,
        b"hello".to_vec()
    );
    Ok(())
}
```

## The cast

* `ctx.individual(name)` creates an identity with one instance running.
* `ctx.new_keyhive_instance_for(&of, name)` creates a new instance of an existing identity,
  sharing its signing key. Cloning an `Instance` does not do this. Every field of `Keyhive`
  is shared, so a clone is the same keyhive under a second name.
* `ctx.group(&creator, name)` creates a named `Group` and returns a `GroupId`.
* `ctx.doc(&creator, name)` creates a named `Document` and returns a `DocumentId`.
* `ctx.rebuild_from_archive(&archive, name)` uses the named identity's signing key to build
  `Keyhive` instance with a fresh ciphertext store from the `Archive`.
* `ctx.adopt(hive, name)` takes a `Hive` the test built itself and treats it as one of the
  cast, for an instance the context would not produce, such as a peer holding a particular
  signing key.

Every instance learns every other instance's contact card, so a `NotSynced` is about events
rather than introductions.

## Guidelines for writing tests with `TestContext`

Call `sync_all_unsent()` before checking anything about an instance other than the one that
did the work, and before an instance delegates over a resource it did not create.

Check one rule per test. If a test could fail for two unrelated reasons, split it.

Name a test after the rule it checks, so `a_reader_cannot_delegate_edit_or_above` rather than
`test_add_member_3`.

Test the invariants keyhive must respect from the user of the `Keyhive` API's perspective.
Lower-level details belong in unit tests in the module that owns them.
