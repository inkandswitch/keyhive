# Inter-Document References

## Motivation

Applications built on Keyhive often need to reference one document from another — for example, a project document linking to its meeting notes, or a collection referencing its member documents. These references must work in a local-first context where documents are identified by public keys and content evolves concurrently across replicas.

Additionally, inter-document references provide a mechanism analogous to Git branch heads: a mutable pointer that tracks the latest state of some document from a specific agent's perspective.

## Soft Pointers

A _soft pointer_ is a lightweight reference from one agent to a specific causal state of a document:

```rust
struct SoftPointer {
    /// The agent asserting this pointer.
    agent_id: AgentId,
    /// The heads of the referenced document at the time of this assertion.
    heads: Vec<OpHash>,
}
```

### Properties

- **Non-authoritative**: A soft pointer is a claim, not a proof. The referenced heads may or may not be the latest state; they represent a snapshot from the asserting agent's perspective.
- **Causally grounded**: The `heads` field is a set of causal heads, consistent with the agent's view at the time of assertion.
- **Updateable**: An agent may issue a new soft pointer with updated heads, similar to updating a Git branch ref. The pointer itself can be part of a document's content operations.
- **Signed**: When embedded in a document operation, the pointer inherits the operation's signature, binding the assertion to a specific agent and causal context.

### Use Cases

| Use case | Description |
|----------|-------------|
| **Document linking** | A project document references its meeting notes by soft pointer. Following the pointer retrieves the notes at the referenced causal state. |
| **Branch heads** | An agent tracks "my latest view of document X" as a soft pointer, updated on each sync. Other agents can follow this pointer to see what that agent considers current. |
| **Collections** | A collection document contains soft pointers to its member documents. Adding or removing a member is a content operation on the collection. |
| **Cross-document dependencies** | Authorization operations in one document may depend on the state of another document (see [group membership](./group_membership.md#cross-group-dependencies)). Soft pointers formalize these references. |

### Resolution

Resolving a soft pointer requires:

1. Having Pull (or higher) access to the referenced document
2. Having the referenced heads available locally (or fetching them via sync)
3. Verifying that the asserting agent had appropriate access at the time of assertion (optional, application-dependent)

If the referenced heads are not available, the pointer is _dangling_ — analogous to a broken link. This is a normal condition under partition; the pointer becomes resolvable once the referenced content is synced.

### Relationship to Collection Sync

[Collection sync](./collection_sync.md) discovers which documents an agent can access by traversing the authority graph. Soft pointers complement this: while collection sync determines _which_ documents to sync, soft pointers determine _what state_ of those documents is relevant from a particular agent's perspective.

<!-- Future work: signing over data when updating a pointer, cross-document causal fences, pointer garbage collection -->
