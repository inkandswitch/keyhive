# BeeKEM: Concurrent CGKA for Local-First Applications

BeeKEM is a _concurrent variant of TreeKEM_ for Continuous Group Key Agreement (CGKA). It manages group membership, key rotation, and derivation of per-content encryption keys. Standard TreeKEM (as used in [MLS]) requires strict linearizability, which is incompatible with local-first / partition-tolerant settings. BeeKEM extends the TreeKEM model to support concurrent updates without exotic cryptographic primitives.

> [!NOTE]
> The name "BeeKEM" distinguishes this design from standard TreeKEM and from Matthew Weidner's Causal TreeKEM. It draws inspiration from both but makes different trade-offs.

## Goals

1. **Post-compromise security (PCS)**: after a key compromise, a single key rotation by any member restores confidentiality of all future content.
2. **Causal consistency**: operations are partially ordered. No global clock or leader is required.
3. **Convergence**: all replicas that have received the same set of operations produce identical tree state, regardless of arrival order.
4. **Standard cryptography only**: X25519 key exchange, ChaCha20-Poly1305 AEAD, BLAKE3 KDF. No commutative group keys, no multiparty DH.
5. **`no_std` compatibility**: the algorithm runs in Wasm and embedded contexts.

## Non-Goals

- Forward secrecy (FS). Local-first CRDTs require full causal history to materialize a document. Restricting access to historical data would prevent new members from reading prior ops. See the [Causal Encryption](./causal_encryption.md) design doc for discussion.

## Tree Structure

BeeKEM uses a left-balanced binary tree with a flat-array index scheme (adapted from [OpenMLS]):

```
   Tree node indices (4 members):

             3
           /   \
          1     5
         / \   / \
        0   2 4   6
        A   B C   D        ← members (leaf nodes)
```

Leaf nodes occupy even positions, inner nodes occupy odd positions. Three strongly-typed index wrappers enforce this at the type level: `LeafNodeIndex`, `InnerNodeIndex`, and `TreeNodeIndex`.

### Node Contents

- **Leaf nodes** hold a `MemberId` (Ed25519 verifying key) and a `NodeKey` (one or more X25519 public keys).
- **Inner nodes** hold an optional `SecretStore` — encrypted copies of the node's secret key, one per "resolved" descendant. An inner node with no `SecretStore` is _blank_.

### Resolution

The _resolution_ of a node is the set of its nearest non-blank, non-conflict descendants. When encrypting a secret at an inner node, the encrypter must produce a ciphertext for every node in the sibling's resolution — those are the nodes whose holders can decrypt.

```
        3 (blank)
       / \
      1   5
     / \ / \
    0  2 4  6

  resolution(3) = resolution(1) ∪ resolution(5)
  resolution(1) = { 1 }      (if node 1 has a clean key)
  resolution(5) = { 4, 6 }   (if node 5 is blank, recurse to leaves)
```

If a subtree's resolution is empty (entirely blank), a throwaway keypair is generated for the DH exchange so that only the encrypting child receives an entry.

## Operations

Three operations mutate the CGKA state:

| Operation  | Effect                                                                 |
|------------|------------------------------------------------------------------------|
| **Add**    | Push a new leaf, blank its direct path                                 |
| **Remove** | Blank the removed leaf and its direct path, collect removed keys       |
| **Update** | Rotate the owner's leaf key, encrypt a new secret along the full path  |

Every operation carries a set of _predecessors_ — the content-addressed hashes of the operations it causally depends on. This forms a DAG (the operation graph).

## Path Encryption (Update)

The core mechanism for establishing a shared group secret:

```
   leaf_sk ─── ratchet ──→ parent_sk ─── ratchet ──→ ... ──→ root_sk
                 │                          │
                 ▼                          ▼
          encrypt for each           encrypt for each
          node in sibling's          node in sibling's
          resolution (DH)            resolution (DH)
```

1. The updater generates a fresh key pair at their leaf.
2. Walking from leaf to root, at each parent:
   - Derive the parent's secret key: `parent_sk = child_sk.ratchet_forward()` (BLAKE3 KDF).
   - Compute the parent's public key: `parent_pk = parent_sk.share_key()`.
   - For each node in the sibling's resolution, perform X25519 DH to derive a symmetric key, then encrypt `parent_sk` under that key (XChaCha20-Poly1305 with a deterministic SIV nonce).
   - Store the ciphertexts in a `SecretStore` at the parent node.
3. The root secret key becomes the `PcsKey`.

### Decryption

To decrypt a tree secret, a member walks from their leaf upward:

1. **Same-encrypter shortcut**: if the decrypter _is_ the encrypter, simply ratchet the leaf secret key forward `path_length` times.
2. **Different encrypter**: at each non-blank parent, look up the encrypted secret keyed by the decrypter's subtree index. Decrypt using DH with the encrypter's public key. Once reaching the _lowest common ancestor_ with the encrypter's leaf, ratchet forward for the remaining path length.

## Handling Concurrency

### Conflict Keys

When two members concurrently update through the same inner node, the node ends up with multiple `SecretStoreVersion` entries — one per concurrent path. This is called a _key conflict_.

```
  Member A updates       Member B updates
  (concurrently)         (concurrently)
       │                      │
       ▼                      ▼
   node 3: version_A      node 3: version_B
           └──────┬───────────┘
                  ▼
          node 3: [version_A, version_B]  ← conflict
```

Conflict nodes are treated like blank nodes during resolution: their descendants are used instead. A subsequent update by _any_ member that encrypts through a conflict node clears the conflict and establishes a single new version.

### Concurrent Structural Changes

Adds and removes change the tree's shape (number of leaves), which invalidates leaf index assignments. When concurrent structural changes are detected:

1. All pending operations are deferred.
2. On the next operation that requires a consistent tree, `replay_ops_graph()` rebuilds the CGKA from genesis:
   - Topologically sort all operations into _epochs_ (groups of concurrent ops with no causal ordering between them).
   - Replay epochs sequentially.
   - Within a multi-op epoch that contains structural changes, concurrently-added leaves are sorted deterministically by `MemberId` and re-assigned. This guarantees convergence.

### Epoch Structure

An epoch is a maximal set of concurrent operations — none causally precedes any other within the same epoch. Epoch boundaries occur where the number of concurrent "heads" drops to one.

```
   epoch 0       epoch 1        epoch 2
  ┌───────┐   ┌──────────┐   ┌─────────┐
  │ Add A │──→│ Update A │──→│ Add D   │
  │       │   │ Update B │   │ Update C│
  │       │   │ Add C    │   │         │
  └───────┘   └──────────┘   └─────────┘
```

The topological sort uses Kahn's algorithm, with ties broken by hash value for determinism.

### Path Validity

When applying a concurrent `PathChange`, the path may no longer be valid (the member's leaf index may have shifted due to a concurrent add/remove, or the tree may have grown). In this case, only the leaf key is updated and the entire path is blanked. This is safe — it simply means the tree lacks a root key until someone performs a fresh update.

## Key Derivation Chain

```
ShareSecretKey (leaf)
      │
      │  ratchet_forward()              ← BLAKE3 derive_key
      ▼
ShareSecretKey (parent)
      │
      │  (repeated up the path)
      ▼
ShareSecretKey (root)  ════════════►  PcsKey
                                        │
                                        │  derive_application_secret()
                                        │  inputs: SIV nonce, content_ref,
                                        │          predecessor_refs, update_op_hash
                                        │  KDF: BLAKE3 domain-separated
                                        ▼
                                   ApplicationSecret
                                        │
                                        │  .key()  ← SymmetricKey::derive_from_bytes
                                        ▼
                                   SymmetricKey ──encrypt/decrypt──► EncryptedContent
```

- **PcsKey**: the root secret. Named for _post-compromise security_ — rotating it ensures a compromised key becomes stale.
- **ApplicationSecret**: unique per piece of content. The derivation includes the content reference, predecessor references, and the hash of the CGKA update operation, so no two content items share a key.
- **SymmetricKey**: the actual AEAD key (XChaCha20-Poly1305).

### Nonce Construction (SIV)

Nonces are computed deterministically as `BLAKE3(separator ‖ doc_id ‖ key ‖ plaintext)`, truncated to 24 bytes. This is a _synthetic initialization vector_ (SIV) construction: nonce-misuse-resistant, since encrypting the same plaintext with the same key always produces the same ciphertext.

## SecretStore

Each inner node's encrypted state:

```
SecretStore
  └── versions: Vec<SecretStoreVersion>      // 1 = clean, >1 = conflict

SecretStoreVersion
  ├── pk: ShareKey                           // this version's public key
  ├── encrypter_pk: ShareKey                 // who encrypted this version
  └── sk: BTreeMap<TreeNodeIndex, EncryptedSecret>
                                             // one entry per resolution node
```

`EncryptedSecret` contains: a SIV nonce, the XChaCha20-Poly1305 ciphertext of the secret key bytes, and the `paired_pk` used for the DH exchange.

## The `has_pcs_key` Invariant

The CGKA can produce a `PcsKey` (and thus encrypt content) only when:

1. The root node has a non-blank, non-conflict `SecretStore`.
2. The operation graph has a single head (no unmerged concurrency).
3. At most one pending `Add` head exists.

When this invariant does not hold, the next encryption attempt automatically triggers an `update()` to re-establish a root key.

## PcsKey Recovery for Decryption

Each `EncryptedContent` envelope includes the `pcs_key_hash` and `pcs_update_op_hash` that identify which root secret was used. Decryption proceeds:

1. Check the local `pcs_keys` cache for the hash. If found, use it directly.
2. Check if the _current_ tree root matches. If so, derive and cache.
3. Otherwise, topologically sort the operation subgraph up to the given update op, rebuild a temporary CGKA from genesis, replay those epochs, extract the root secret, and cache it.

This ensures that any historically-valid `PcsKey` can always be recovered as long as the member held a leaf key at the time of that update.

## Relationship to Other Components

- **[Convergent Capabilities](./convergent_capabilities.md)** drive the CGKA: the capability system determines _who_ has read access and therefore whose keys appear in the tree.
- **[Causal Encryption](./causal_encryption.md)** uses the `ApplicationSecret` produced by BeeKEM to encrypt content chunks. Each chunk's ciphertext includes the keys to decrypt its causal predecessors, forming a self-certifying chain.
- **[Group Membership](./group_membership.md)** manages the delegation graph that determines CGKA membership.

## Security Properties

| Property                    | Status                                                    |
|-----------------------------|-----------------------------------------------------------|
| Post-compromise security    | Yes — one update by any member rotates the root secret    |
| Forward secrecy             | No — required by CRDT history constraint                  |
| Confidentiality             | Tree secret is only derivable by current leaf holders     |
| Convergence                 | Deterministic replay from genesis; sorted tie-breaking    |
| Conflict safety             | Conflict keys degrade to blank; no secret leakage         |
| Replay determinism          | Topological sort + MemberId ordering = identical trees    |

## Open Questions

- **Compaction**: as the operation graph grows, full replay from genesis becomes expensive. A checkpointing/snapshotting mechanism would allow truncating old history.
- **`no_std` serialization**: the current key derivation uses `bincode` (which requires `std`). Migrating to `minicbor` or `postcard` would enable full `no_std` operation.
- **Post-quantum**: the X25519 key exchange is quantum-vulnerable. The design is intentionally modular — replacing X25519 with a PQ-KEM (e.g., ML-KEM) requires only that the new primitive supports asymmetric key encapsulation.

<!-- External Links -->
[MLS]: https://messaginglayersecurity.rocks/
