# Glossary

## Agents and Principals

| Term | Definition |
|------|-----------|
| **Agent** | Any entity that can receive, delegate, and exercise authority. Identified by a root key pair. Forms a subtyping hierarchy: `Document <: Group <: Individual`. |
| **Individual** (Stateless Agent) | The simplest agent: a public key with no associated state. Represents a single device key, passkey, or hardware token. Cannot rotate its own key. |
| **Group** (Stateful Agent) | An agent with mutable membership state. Authorization operations form a causal DAG rooted at the group's public key. Common pattern: creator adds itself via _membership by parenthood_. |
| **Document** (Document Agent) | A subtype of Group that adds encrypted content operations alongside authorization state. The document's public key is also used as its identifier. |
| **Active** | The current user's agent — the one that holds a signing key and can produce signatures. |
| **Peer** | A remote agent known to the local replica (may or may not be a member of any group). |

## Capabilities and Access

| Term | Definition |
|------|-----------|
| **Convergent Capabilities** (concap) | A CRDT-aware capability system that extends certificate capabilities with statefulness from object capabilities. Provides delegation, attenuation, and revocation under eventual consistency. |
| **Access** | The four capability levels, ordered by inclusion: **Pull** (sync ciphertext), **Read** (decrypt), **Write** (mutate content), **Manage** (change membership). |
| **Delegation** | A signed operation granting authority from one agent to another. May be attenuated (narrowed). Forms a DAG that may contain cycles. |
| **Revocation** | A signed operation removing a prior delegation. Revocations cascade: revoking a delegator also revokes their sub-delegations. However, revocation of the revoker can undo the cascade. |
| **Attenuation** | Restricting delegated authority to a subset (e.g., granting Write but not Manage). |
| **Invocation** | Exercising a capability: a signed action accompanied by proof of delegation. |
| **Authority Graph** | The directed graph of delegations between agents. Validated recursively to determine who can do what. May contain cycles (e.g., two groups delegating to each other). |

## Cryptography

| Term | Definition |
|------|-----------|
| **Digest** | A typed, content-addressed BLAKE3 hash: `Digest<T>` carries a phantom type parameter for type safety. |
| **Signed** | A wrapper that bundles a value with its Ed25519 signature and the signer's verifying key. |
| **ShareKey** / **ShareSecretKey** | X25519 public/secret keys used for Diffie-Hellman key exchange in the CGKA tree. |
| **SymmetricKey** | A symmetric encryption key derived from the CGKA for encrypting content. |
| **SIV** (Synthetic Initialization Vector) | A nonce derived deterministically from the content, key, and domain separator. Provides nonce-misuse resistance. |
| **Signing Key** / **Verifying Key** | Ed25519 key pair. Following convention: "signing key" (not "private key") and "verifying key" (not "public key") for signature operations. Reserve "private/public" for key exchange. |
| **ReadCap** (Read Capability) | An encrypted key granting read access to a specific content block. |
| **Prekey** | A pre-published ShareKey that allows inviting an offline Individual to a document's encryption tree. Consumed on use and should be rotated. |

## CGKA and BeeKEM

| Term | Definition |
|------|-----------|
| **CGKA** (Continuous Group Key Agreement) | A protocol for maintaining a stream of shared group keys that evolve over time as members join, leave, and rotate keys. |
| **BeeKEM** | Keyhive's concurrent variant of TreeKEM. Handles concurrent updates by keeping all conflict keys at inner nodes until resolved by a future update. |
| **TreeKEM** | The key agreement protocol underlying MLS. Requires strict linearizability; BeeKEM relaxes this for causal consistency. |
| **PCS Key** (Post-Compromise Security Key) | A symmetric key derived from the CGKA tree root. Represents the current shared group secret. Rotated when members are added, removed, or update their keys. |
| **Application Secret** | A per-content encryption key derived from a PCS key and a content reference. Used to encrypt individual content blocks. |
| **Conflict Keys** | When concurrent updates create conflicting public keys at a tree node, BeeKEM retains all of them. A passive adversary must compromise _all_ concurrent secret keys to derive the root secret. |
| **Epoch** | A snapshot of the CGKA operation graph at a consistent point. Operations are organized into epochs for replay. |

## Encryption

| Term | Definition |
|------|-----------|
| **Causal Encryption** | The strategy of embedding predecessor keys in each encrypted block, so that given an entry point key you can recursively decrypt all causal ancestors back to genesis. |
| **Forward Secrecy** (FS) | Restricting access to _historical_ data after a compromise. Keyhive intentionally sacrifices FS because op-based CRDTs require complete history for materialization. |
| **Post-Compromise Security** (PCS) | Restricting access to _future_ data after a compromise. Achieved by rotating CGKA keys; a compromised agent removed from the group loses access to subsequent keys. |
| **Encrypted Content** | Ciphertext paired with its content hash, predecessor content references, PCS key hash, and encrypted symmetric key. |
| **Crypt Store** | The unordered set of encrypted blobs for a document. No dependency on ordering between blobs. |

## Sync and Data

| Term | Definition |
|------|-----------|
| **Beelay** | The Keyhive relay: syncs E2EE chunks using stateless RPCs over TLS. Does not require identities; capability proofs authorize data access. |
| **Sedimentree** | A data structure that recursively compresses ranges of a commit DAG. Older commits are compressed into larger strata (like sedimentary rock layers). |
| **Stratum** | A compressed range of commits within a sedimentree, defined by start hash, end hash, level, and interior checkpoint hashes. |
| **Stable Chunking** | Coordination-free chunking using hash hardness (trailing zeros). All replicas with shared history produce the same chunks independently. |
| **Collection Sync** | Discovering _which documents_ to sync for a given agent by walking the authority graph from the agent's key to all reachable documents. |
| **Edge Names** | A lightweight, non-authoritative naming system where agents share their name bindings (pet names) to enable recursive name discovery. Not part of core Keyhive but provided as a default mechanism. |

## Miscellaneous

| Term | Definition |
|------|-----------|
| **ContentRef** | A trait for content references (hashes or identifiers that address content blocks). Default: `[u8; 32]`. |
| **CaMap** | A content-addressed map: keys are `Digest<T>`, providing automatic deduplication. |
| **Fork / Merge** | Transactional primitives: fork a data structure to get a cheap copy, operate on it, and merge back on success (or discard on failure). |
| **Membership by Parenthood** | Pattern where the creator of a group includes an instruction to add itself to the child's membership during initialization. |
| **Self-Certifying** | A property where the document's public key serves as its identifier, and the authorization chain can be verified without external trust anchors. |
