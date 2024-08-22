# Inter-Document References

FIXME rename to "causal pointer"

FIXME TL;DR

NOTE: this also gives a way to handle "branch heads".

```rust
struct IDPointer {
    doc_id: DocumentId,
    heads: Vec<OpHash>,
}
```

TODO: Expand this section here to talk about how this enables you to track more like Git, including signing over data when updating a pointer.
