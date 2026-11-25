//! The secret of a key a write rotated in is handed to the caller.

use keyhive_core::test_utils::{content_ref, TestContext, TestResult as Result};
use keyline::power::Power::Edit;

#[tokio::test]
async fn a_write_that_rotates_the_leaf_returns_the_new_secret() -> Result<()> {
    let mut ctx = TestContext::new().await;
    let alice = ctx.individual("alice").await?;
    let bob = ctx.individual("bob").await?;
    let doc = ctx.doc(&alice, "doc").await?;
    alice.add_member(bob.id(), doc, Edit).await?;
    ctx.sync(&alice, &bob).await?;

    let mut rotations = 0;
    for (writer, content) in [(&alice, b"a1"), (&bob, b"b1"), (&alice, b"a2"), (&bob, b"b2")] {
        let written = writer
            .try_encrypt_content(doc, &content_ref(content), &[], content)
            .await?;
        match (written.update_op(), written.local_cgka_secret()) {
            (Some(_), Some((public, secret))) => {
                rotations += 1;
                assert_eq!(secret.share_key(), *public, "the pair is consistent");
            }
            (None, None) => {}
            (op, secret) => panic!(
                "the update and its secret travel together: op {} secret {}",
                op.is_some(),
                secret.is_some()
            ),
        }
        ctx.sync(writer, if std::ptr::eq(writer, &alice) { &bob } else { &alice })
            .await?;
    }
    assert!(rotations > 0, "some write had to rotate its leaf");
    Ok(())
}
