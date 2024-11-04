# Inter-Document References

NOTE: this also gives a way to handle "branch heads".

```rust
struct SoftPointer {
    agent_id: AgentId,
    heads: Vec<OpHash>,
}
```

<!-- Expand this section here to talk about how this enables you to track more like Git, including signing over data when updating a pointer. -->
