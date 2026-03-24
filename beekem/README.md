# BeeKEM Overview

BeeKEM is a Continuous Group Key Agreement (CGKA) protocol designed for local-first, peer-to-peer applications. It's an adaptation of TreeKEM (used by MLS) that drops the requirement for a central ordering server, relying only on causal ordering of operations and using only standard cryptographic primitives such as Diffie-Hellman key exchange (DH) and BLAKE3 hashing.

A dynamic group of peers needs to maintain shared encryption keys over time, supporting offline operation, concurrent membership changes, and no central coordinator. BeeKEM is designed to handle this scenario while preserving forward secrecy (compromised keys don't expose past data) and post-compromise security (compromised keys don't expose future data after key rotations).

## Tree Structure

BeeKEM uses a binary ratchet tree:
* Each leaf hold a member's identity and DH public key
* The root holds the group's shared encryption key (encrypted)
* Each inner node holds a DH public key and encrypted secrets (which effectively function as the shared key for its subtree/subgroup)

Each leaf has an implicit secret known only to that member. Inner node secrets are encrypted via DH key exchange with sibling nodes, so any member can decrypt up the tree from their leaf to the root in O(log n) steps.

## Core Operations

1. **Update (key rotation)**: A member generates a fresh leaf keypair, then encrypts new secrets at each ancestor node using DH with the sibling's public key. This "path encryption" refreshes the root secret.

2. **Add**: Places a new member at the next available leaf and blanks the path from that leaf to root (invalidating the old root key, requiring a subsequent update to refresh it).

3. **Remove**: Blanks the removed member's leaf and its entire path to root.

4. **Decrypt**: Traverses from your leaf to the root. At each parent, performs DH with the sibling's public key to derive the symmetric key that decrypts their shared parent's secret. Continues until it reaches the root.

When a sibling is blank (from an add/remove), you can't do a single DH exchange. Instead, you must find the **sibling resolution**, i.e., the highest non-blank descendants of the blank subtree, and encrypt separately for each. This degrades to O(n) in the worst case but is typically O(log n).

## What Makes BeeKEM Novel: Handling Concurrency

BeeKEM's innovation is in how it handles concurrent operations without a central server to pick winners. When two members concurrently update overlapping path nodes, both DH public keys are retained as **conflict keys** at that node.

A node with conflict keys is treated similarly to a blank node during subsequent updates: you encrypt for its resolution rather than using a single key. This is prevents an adversary who compromised one fork from decrypting the other fork's path to root. Future updates by any member whose path passes through the conflicted node resolve the conflict by replacing all conflict keys with a single fresh key.

When applying a concurrent path change, BeeKEM merges keys at each affected node (combining into conflict keys where needed) and merges secret stores (keeping all concurrent versions). Removes are applied last, blanking paths after all other concurrent operations merge.

## Performance

In the common case (a balanced tree with few blanks or conflicts), operations are O(log n). The worst case would be a tree where every inner node is blank or has conflict keys, in which case operations degrade to O(n).

Space is O(n log n) worst case for conflict key storage.

## Security Properties

* **Forward secrecy**: Each update generates a fresh, independent leaf keypair, leading to a fresh root secret. Application secrets are independently derived from that root secret (via one-way BLAKE3 KDF with content-specific context), so compromising an application secret does not reveal the root secret or any other application secret.
* **Post-compromise security**: Leaf key rotation introduces fresh entropy and conflict key handling ensures an adversary with outdated leaf secrets can't decrypt new paths.
* **Standard crypto only**: Unlike Causal TreeKEM (which requires commutative/associative primitives like BLS), BeeKEM uses only DH, BLAKE3, and ChaCha20-Poly1305.

# BeeKEM Deep Dive: The Algorithms

## Definitions

* **Encrypter child**: the child node that last encrypted its parent's secret.
* **Blank node**: a node set to empty. Either an inner node whose secret has been invalidated, an unoccupied leaf, or a removed member's leaf (functioning as a tombstone).
* **Resolution of a node**: if the node has a single public key, the resolution is just that node. If the node is blank or contains conflict keys, the resolution is the set of its highest non-blank, non-conflict descendants. During encryption, resolution is taken on sibling nodes (not on the node being encrypted), so the worst case for a single resolution is n/2 (all leaves in one subtree).
* **Path**: the sequence of inner nodes from a leaf's parent up to and including the root.
* **Secret store**: the data stored at an inner node. It contains one or more *versions*, where each version holds a public key for the node, the encrypter child's public key, and a map of encrypted secrets keyed by tree node indices.

## The Tree

The tree is a complete binary tree sized to the next power of two. Leaves and inner nodes are stored in separate arrays. Leaves are 0-indexed from left to right. Inner nodes are also 0-indexed but mapped to positions within the tree via a standard implicit binary tree layout where leaf `i` sits at tree position `2i` and inner node `j` sits at tree position `2j + 1`.

The tree tracks a "next leaf index" pointer. New members are always placed at this position (the rightmost available slot), and the tree grows (doubling capacity) when needed. When members are removed, contiguous blank leaves at the right edge are trimmed back.

## Initialization

A new BeeKEM tree is created with a single member. That member's identity and DH public key are placed at leaf 0. All inner nodes are blank. There is no root secret yet; an update (path encryption) must be performed first.

## Path Encryption (Update/Key Rotation)

When a member rotates their leaf key, they encrypt a new secret at every ancestor up to the root.

1. **Generate a new leaf keypair.** Place the new public key at the member's leaf. Store the secret key in the member's local key map.

2. **Walk up the path from the leaf toward the root.** At each parent node:

   a. **Derive a new parent secret** by applying a one-way ratchet (BLAKE3-based KDF) to the child secret. The child secret at the first step is the leaf's secret key; at subsequent steps, it is the secret just derived for the previous parent. This means each ancestor's secret is deterministically derived from the leaf secret by ratcheting forward once per level.

   b. **Compute the new parent public key** from the new parent secret.

   c. **Find the sibling's resolution.** Look at the sibling of the current child:
      * If the sibling has a single public key (the common case), the resolution is just that one node.
      * If the sibling is blank or has conflict keys, recursively descend into the sibling's subtree to find the highest non-blank, non-conflict descendants.

   d. **Encrypt the new parent secret for each node in the sibling resolution.** For each resolved node, derive a symmetric key via DH between the child's secret key and the resolved node's public key, then use that symmetric key to encrypt the new parent secret (using ChaCha20-Poly1305 with a synthetic IV). Each encrypted secret also records which public key it was paired with during DH. This is needed later during decryption so that non-encrypter members can identify the correct secret key to use. Store all encrypted secrets in a map keyed by tree node index, plus an additional entry for the encrypter child's own index (a copy of the first entry, enabling the encrypter to decrypt this node later using the same DH pair).

   e. **Handle the empty resolution case.** If the sibling's entire subtree is blank (no members), generate a throwaway keypair and use it for the DH. The encrypted secret is stored keyed by the child's own index only (so the encrypter can still decrypt it later).

   f. **Record the encrypter child's public key** alongside the encrypted secrets. This is needed during decryption so that decrypters know which public key was used for the DH.

   g. **Store the new secret store** (parent's public key, encrypted secret map, and encrypter child's public key) at the parent, replacing whatever was there.

3. **After reaching the root**, record which leaf performed this encryption. The root now has a valid secret and any member can decrypt it.

4. **Emit a path change** containing the leaf's new public key, the new secret store for every inner node on the path, and the list of old public keys that were replaced (the "removed keys"). The removed keys are important for merge; they tell other members which keys have been superseded.

## Decryption (Deriving the Root Secret)

Any group member can derive the current root secret by traversing from their leaf up to the root, decrypting at each step.

1. **Shortcut for the encrypter.** If the member performing decryption is the same member who last encrypted the path, they already know their leaf secret. They simply ratchet it forward by the length of the path (one ratchet per ancestor) to directly derive the root secret. No DH or decryption is needed.

2. **Find the lowest common ancestor (LCA)** of your leaf and the encrypter's leaf. This is the point where your path intersects the encrypter's path. You only need to decrypt up to the LCA. From there, you can ratchet forward to derive the root.

3. **Walk up your path from your leaf.** Keep track of every index you visit (a "seen indices" list). At each parent:

   a. **Skip blank and conflict parents.** If a parent is blank or has conflict keys, skip it and move up to the next ancestor. You must hold onto the last secret you decrypted.

   b. **Decrypt the parent's secret.** Look up the encrypted secret in the parent's secret store. The secret store maps tree node indices to encrypted secrets. Search your seen indices (most recent first) to find which index has a corresponding entry. This handles the case where the encrypter encrypted for a resolution that included a node on your path closer to your leaf rather than the child node immediately below this parent.

   c. **Encrypter vs. non-encrypter decryption.** Each encrypted secret records which public key it was paired with during DH. If your public key matches the stored encrypter child public key (i.e., you are on the encrypter's side), derive the symmetric key via DH between your secret key and the paired public key, and decrypt. Otherwise (non-encrypter side), the paired public key corresponds to your node (or a node on your path to this point). Look up the secret key for it, derive the symmetric key via DH between that secret key and the encrypter child's public key, and decrypt.

   d. **Store the decrypted secret** in your key map (mapping the parent's public key to the decrypted secret). This is reusable for future decryptions.

4. **Once you reach the LCA**, ratchet the decrypted secret forward by the number of remaining ancestors between the LCA and the root. Return this as the root secret.

## Adding a Member

1. Place the new member's identity and public key at the next available leaf index.
2. If the tree capacity is exceeded, grow the tree (double it).
3. Blank the entire path from the new leaf to the root. This invalidates the root secret.
4. Record the operation with its causal predecessors.

After an add, there is no valid root key. Someone must perform an update (path encryption) to create a new one.

## Removing a Member

1. Verify the group has more than one member.
2. Find the leaf index for the member being removed.
3. Collect all public keys from the inner nodes on the removed member's path (these are the "removed keys", needed for merge bookkeeping).
4. Blank the leaf and its entire path to the root.
5. Trim contiguous blank leaves from the right edge of the tree.

Like add, remove invalidates the root key.

## Merging Concurrent Operations

BeeKEM assumes causal delivery of operations. Concurrent operations (those not causally ordered with respect to each other) require special merge handling.

### Merging a Concurrent Update (Path Change)

When applying a path change from another member that was created concurrently:

1. **Check if the path is still valid.** A path is valid if the originating member is still at the same leaf index and the path length matches. A mismatch (e.g., because a concurrent add reshuffled leaves or grew the tree) means the path is structurally incompatible and invalid.

2. **If the path is invalid**: Only update the leaf's public key by merging the new key with the existing one. Blank the path (no inner node updates are meaningful since the tree structure changed).

3. **If the path is valid**: Merge along the path:

   a. **At the leaf**: merge the new public key with the existing one. If the existing key was in the "removed keys" list (meaning this update replaced it), the new key simply substitutes. Otherwise, both keys are retained as **conflict keys**.

   b. **At each inner node on the path**: if the node already has a secret store, merge the new store's versions into the existing one, removing any versions whose public keys appear in the removed keys list and appending the new versions. If the node was blank, just insert the new store.

4. **Check the root.** If the root has a single version (no conflict), record the new encrypter. If the root now has multiple conflicting versions, clear the encrypter. The tree has no valid root key until someone does a fresh update.

### Merging Concurrent Membership Changes

Concurrent adds and removes require extra care. When a batch of concurrent operations includes at least one add or remove:

1. Apply all operations in the batch (updates, adds, removes).
2. Then, as a cleanup step:
   * **Re-blank removed members' paths.** Even though the remove itself blanked the path, concurrent updates from other members may have written new data along it. Re-blanking ensures the removed member's path is fully cleared.
   * **Sort and re-add concurrently added leaves.** If multiple members concurrently added new members, those new leaves might have landed at the same position. Pull them all out, sort them deterministically by identity, and re-insert them in order (each getting the next available leaf, with paths blanked).

This sorting step is what ensures all peers converge to the same tree structure despite concurrent adds targeting the same leaf slot.

## Causal Ordering and Epochs

Operations form a causal graph (a DAG). Each operation records its causal predecessors (the set of operation hashes it was aware of when created).

When the graph has unresolved concurrency (multiple heads), the system topologically sorts all operations and groups them into **epochs**. An epoch is a set of operations that are mutually concurrent. Epochs are then applied in causal order:

* If an epoch contains only updates, apply them one by one (each becomes a merge of concurrent paths).
* If an epoch contains any adds or removes, apply all operations and then run the membership change cleanup (re-blank, re-sort).

When concurrency is too complex to incrementally merge (e.g., after receiving a concurrent membership change), the entire tree is **replayed from scratch**: start from the initial state, topologically sort all known operations, and re-apply them in epoch order. This guarantees convergence regardless of the order in which operations were received.

## The Secret Store (Inner Node Data)

Each inner node stores a list of **versions**. In the normal case, there is exactly one version. After concurrent updates that overlap at that node, there may be multiple.

Each version contains the three components of an inner node described in an earlier section:
* **A public key** for the node corresponding to the encrypted secret.
* **The map from tree node indices to encrypted secrets.**
* **The encrypter child's public key.**

A secret store "has a conflict" when it has more than one version.

## Security Notes

**After a merge of concurrent updates, the tree has no root key.** This is by design. The conflict keys at inner nodes mean that no single member can claim an uncontested root secret. A fresh update from any member will resolve the conflicts along its path and establish a new root.

**An adversary needs all historical leaf secrets from at least one leaf to exploit conflict merges.** Because conflict keys are retained (rather than picking a winner), an adversary who compromises one branch of a fork cannot read the other branch without also knowing its leaf secrets.

**A root secret always corresponds to a specific update at a specific leaf.** It is never a "merged" root secret. Instead, it is always the product of one member's path encryption. Other members decrypt it by traversing up to their lowest common ancestor with the encrypter and ratcheting from there.
