# Writing tests using the testing facade

## 1. Why a testing facade?

`keyhive_core/tests/facade/mod.rs` defines a testing facade that higher-level tests can
use instead of calling the `Keyhive` API directly. It serves a number of purposes:

* Makes higher-level tests easier to read and write by providing a reusable API that abstracts away managing the details of setting up keyhives, syncing state, and checking properties, as well as abstracting away complicated signatures when their details are not important.
* Ensures tests clearly express the concepts we care about in the context of the test.
* Avoids coupling tests with lower-level details when those details are not what we care about.
* Makes it easy to rely on the higher-level test suite for checking regressions when implementing significant architectural changes. If the tests are unnecessarily coupled to lower-level details, then we would need to also change the tests themselves, making them unreliable indicators of regressions.

## 2. The testing facade API

You start a test by creating a `TestContext` via `TestContext::new()`. The context manages the lower-level details of the `keyhive` API, state, and property checking.

Once you have a context, you can use it to create entities:

* `ctx.individual(name) -> TestIndividual`: Creates a keyhive identity.
* `ctx.group(creator: &TestIndividual, name) -> TestGroup`
* `ctx.doc(creator: &TestIndividual, name) -> TestDocument`

These test objects have a `name()` method for use in assertion messages.

You can then delegate and revoke access:

* `ctx.delegate(issuer: &TestIndividual, audience: &impl TestAgent, resource: &impl TestMembered, level)`:  `issuer` delegates `level` over `resource` to `audience`. Signed by the issuer's own instance. Returns an error if the issuer may not do this.
* `ctx.revoke(issuer: &TestIndividual, audience: &impl TestAgent, resource: &impl TestMembered)`: `issuer` removes `audience`'s membership in `resource`.

You can also create content and sync state between keyhive identities:

* `ctx.encrypt(who: &TestIndividual, doc: &TestDocument, bytes) -> TestEncryptedContent`. A `TestEncryptedContent` can be passed to `can_decrypt` to check if an individual can decrypt it.
* `ctx.sync(from: &TestIndividual, to: &TestIndividual) -> usize`: Sends `from`'s events to `to`. The return value is how many events `to` could not yet apply.
* `ctx.sync_all()`: Sends events between every pair of individuals.

Then you can check properties:
* `ctx.effective_access(who: &impl TestAgent, doc: &TestDocument) -> Option<Access>`: Check `who`'s access level for `doc`. `None` for no access. |
* `ctx.effective_access_seen_by(observer: &TestIndividual, who: &impl TestAgent, doc: &TestDocument) -> Option<Access>`: Same as `effective_access()`, but from the point of view of `observer`'s `Keyhive`.
* `ctx.transitive_members_of(membered: &impl TestMembered) -> BTreeMap<String, Access>`: Returns everyone who has access to `resource`, including through nested groups.
* `ctx.can_decrypt(who: &TestIndividual, content: &TestEncryptedContent) -> bool`: Whether `who` can successfully decrypt content.

Note that `effective_access()` and `can_decrypt()` are checking different properties. `effective_access()` tells you what the Keyhive graph says someone may do. `can_decrypt()` tells you whether decryption actually succeeds. They need to be checked independently since they can come apart if there's a bug (this has happened before).

You need to call `sync_all()` before:

* checking `can_decrypt` for anyone other than the person who called `encrypt`,
* checking `effective_access_seen_by` about an identity other than the resource owner,
* having an individual issue a delegation over a resource they did not create, because they need to know that resource exists first.

If you forget to do this, the test will probably fail with `TestError::NotSynced { individual, subject }`.

### Test errors for checking properties

Every method returns `Result<T, TestError>`, with variants representing reasons an operation would be refused:

* `TestError::Escalation { wanted: Access, held: Access }`: The issuer holds some access over the resource, but less than they tried to delegate.
* `TestError::NoAuthority`: The issuer has no access to the resource.
* `TestError::NotSynced { individual: String, subject: String }`: The individual has not yet received the required events.
* `TestError::Other(String)`: Anything else, wrapping the underlying error as a `String`.

Use these variants to check specific properties. For example:

```rust
match ctx.delegate(&bob, &carol, &design_doc, Admin).await {
    Err(TestError::Escalation { wanted, held }) => {
        assert_eq!(wanted, Admin);
        assert_eq!(held, Read);
    }
    other => panic!("expected an escalation refusal, got {other:?}"),
}
```

## 3. An example test

Here is an example of a declarative test that involves only the minimal number of higher level steps to check that a rule is satisfied:

```rust
mod facade;
use facade::{Result, TestContext};
use keyhive_core::access::Access::{Edit, Read};

#[tokio::test]
async fn a_relay_cannot_decrypt() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let server = ctx.individual("server").await?;
    let design_doc = ctx.doc(&alice, "design_doc").await?;
    let relays = ctx.group(&alice, "relays").await?;

    ctx.delegate(&alice, &relays, &design_doc, Relay).await?;
    ctx.delegate(&alice, &server, &relays, Admin).await?;

    let ct = ctx.encrypt(&alice, &design_doc, b"secret").await?;
    ctx.sync_all().await?;

    assert_eq!(ctx.effective_access(&server, &design_doc).await?, Some(Relay));
    assert!(!ctx.can_decrypt(&server, &ct).await?, "a relay may not decrypt");
    Ok(())
}
```

### Guidelines

**Focus on the high-level rules, behaviors, and properties we expect keyhive to respect.** For checking lower-level details, write unit tests in those modules.

**Check one rule per test.** If a test could fail for two unrelated reasons, split it.

**Name a test after the rule it's checking.** `a_reader_cannot_delegate_edit_or_above` rather than `test_add_member_3`.

## 4. Adding methods and entities to the facade

New methods should be phrased as actions or questions about entities. They must not return
internal types (e.g., return `TestIndividual` instead of `Individual`). They should abstract away irrelevant lower-level details. And they may correspond to multiple actions at the lower level.

If you need a new entity, then prefix its name with `Test` and add a creation method to `TestContext`. Don't add methods to that entity for use in tests except for `name()`. Prefer passing the handle into `TestContext` methods so it can manage related lower-level plumbing and state.

If a method can be refused for more than one reason, add a `TestError` variant rather than
letting it fall into `Other`. Tests should be able to check why an operation failed.

