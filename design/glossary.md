# Glossary

Terms used across the Keyhive design documents and code. Where the design documents and the Rust code use different names, both are given.

## Principals

| Term | Meaning | In code |
|------|---------|---------|
| _Agent_ | Anything that can hold, delegate, or exercise authority. Identified by an Ed25519 verifying key. | `Agent` enum: `Individual`, `Group`, `Document`, `Active` |
| _Individual_ (design docs: _Stateless Agent_, _Singleton_) | A bare key pair with no membership state. Leaves of the authority graph: devices, WebCrypto contexts, passkeys, hardware keys. Publishes X25519 prekeys so it can be added to BeeKEM trees. | `Individual`, `IndividualId` |
| _Group_ (design docs: _Stateful Agent_) | An agent with a mutable membership: a set of delegations and revocations rooted at the group's key. | `Group`, `GroupId` |
| _Document_ | A group that additionally owns encrypted content and a BeeKEM tree. `Document :< Group :< Individual` in the design-doc subtyping. | `Document`, `DocumentId` |
| _Active_ | The local user's own agent: the individual whose signing key this replica controls. | `Active` |
| _Public_ | A well-known individual whose keys everyone holds; used to encrypt "to anyone" as a fallback. | `Public` |
| _Membered_ | Anything with a membership (a `Group` or a `Document`). | `Membered` |
| _Peer_ | Anything you can delegate _to_ (an individual, group, or document) as opposed to a delegator. | `Peer` |
| _Root_ / _Genesis key_ | The key pair whose verifying key _is_ a group's or document's identifier. All authority over that subject is rooted in delegations signed by it. Self-certifying: possession of the root key proves you created the subject. | |

## Authority

| Term | Meaning | In code |
|------|---------|---------|
| _Capability_ | A signed statement that some agent may act on some subject at some access level. In Keyhive a capability is a _delegation_ plus the chain of delegations that justifies it. | |
| _Delegation_ | A signed edge in the authority graph: _issuer_ grants _delegate_ `can` over the subject, citing a _proof_ (the issuer's own delegation) and recording the revocations and document heads it was issued after. | `Delegation`, `Signed<Delegation>` |
| _Revocation_ | A signed statement that a specific delegation no longer holds, with a proof of the revoker's own authority. | `Revocation`, `Signed<Revocation>` |
| _Membership operation_ | Either a delegation or a revocation. | `MembershipOperation` |
| _Access level_ | `Relay < Read < Edit < Admin`. Totally ordered; each level implies the ones below. | `Access` |
| _Relay_ | May sync and forward ciphertext but not decrypt it. The level held by sync servers. Never placed in a BeeKEM tree. | `Access::Relay` |
| _Read_ | May decrypt content; is a BeeKEM member. | `Access::Read` |
| _Edit_ | May append operations to content. | `Access::Edit` |
| _Admin_ | May revoke any delegation in the group, not only those in their own proof lineage; may manage membership generally. | `Access::Admin` |
| _Authority graph_ | The directed graph whose vertices are agents and whose edges are delegations. Authorisation is reachability from the subject to the agent along validly-signed edges. | |
| _Transitive authority_ | Authority that reaches an agent through one or more groups. Clamped to the _weakest link_: the minimum access level along the best path. | `Membered::transitive_members` |
| _Seniority_ | Causal precedence within a group: an agent added earlier is senior to one added later. A non-admin may only revoke members junior to itself. An agent whose transitive access into the group is at least the target's level may also revoke it. A re-added agent keeps the seniority of its earliest add. Conflicting concurrent revocations are ordered by depth in the causal operation graph, then digest. | `Group::revoke_member`, `MembershipOperation::reverse_topsort` |
| _Proof_ | The delegation an issuer cites to justify a new delegation or revocation. | `Delegation::proof` |
| _Materialised view_ | The current membership computed from the full set of operations: for each agent, the maximum over paths of the per-path minimum access. | `Group::members`, `transitive_members` |
| _Membership by parenthood_ | The pattern where whoever creates a group or document immediately delegates to themselves (or their group) from the fresh root, then may discard the root key. | |
| _PoLA_ | Principle of Least Authority: grant the narrowest capability that does the job. Keyhive never restricts sub-delegation because doing so pushes users toward sharing raw keys instead. | |
| _Whiteout_ | Operations whose authority was later revoked are retained (to preserve causality) but excluded from materialisation. | |
| _Back-dating_ | A revoked agent fabricating operations that claim causal predecessors from before the revocation. Detected against the causal frontier (`after_content`) the revocation records. | `Delegation::after_content` |
| _Convergent capabilities_ (_concap_) | Keyhive's capability model: certificate capabilities whose authority is evaluated over a CRDT of delegations and revocations, so all replicas converge on the same view. See [Convergent Capabilities](./convergent_capabilities.md). | |
| _Keyline_ | The next iteration of the authority model: a uniform graph over keys with jurisdiction-scoped revocation. Design in progress on the `keyline` branch. | |

## Encryption

| Term                             | Meaning                                                                                                                                                                                                        | In code                               |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
| _BeeKEM_                         | Keyhive's concurrent variant of TreeKEM: a binary tree of X25519 keys whose root secret is shared by all readers. See [`beekem/README.md`](../beekem/README.md).                                               | `beekem` crate, `Cgka`, `BeeKem`      |
| _CGKA_                           | Continuous Group Key Agreement: the class of protocol BeeKEM belongs to. Members keep agreeing on a fresh shared secret as membership changes.                                                                 | `Cgka`                                |
| _Share key_ / _Share secret key_ | An X25519 public / secret key used for key exchange (as distinct from a signing key).                                                                                                                          | `ShareKey`, `ShareSecretKey`          |
| _Prekey_                         | A share key an individual publishes ahead of time so others can add it to a BeeKEM tree without a round trip.                                                                                                  | `KeyOp`, `AddKeyOp`, `RotateKeyOp`    |
| _Path secret_                    | The secret at an inner BeeKEM node, sampled independently per update and encrypted for the sibling's resolution.                                                                                               | `SecretStore`                         |
| _Root secret_ / _PCS key_        | The secret at the BeeKEM root after a successful update. Source of all application secrets for an epoch.                                                                                                       | `PcsKey`                              |
| _Application secret_             | A per-chunk symmetric key derived from the PCS key, the content reference, and the predecessor references.                                                                                                     | `ApplicationSecret`                   |
| _Epoch_                          | In BeeKEM, the set of mutually concurrent operations applied together; more loosely, the period during which one root secret is current.                                                                       | `CgkaEpoch`                           |
| _Conflict keys_                  | Multiple public keys retained at one tree node after concurrent updates. Treated like a blank node until resolved by a later update.                                                                           | `ConflictKeys`, `NodeKey`             |
| _Blank node_                     | A tree node with no key: unoccupied leaf, removed member, or an inner node invalidated by an add/remove.                                                                                                       |                                       |
| _Resolution_                     | For a blank or conflicted node, the set of its highest non-blank, non-conflicted descendants; what an update must encrypt for.                                                                                 |                                       |
| _Causal encryption_              | Encrypting each content chunk under its own key and embedding the keys of its causal predecessors, so possession of the current key unlocks the history. See [`causal_encryption.md`](./causal_encryption.md). | `EncryptedContent`, `CiphertextStore` |
| _Forward secrecy (FS)_           | Compromise of current keys does not reveal past data. Not provided: members keep old BeeKEM secrets so that history stays decryptable.                                                                         |                                       |
| _Post-compromise security (PCS)_ | Compromise of current keys does not reveal future data after a key rotation. Provided by BeeKEM updates.                                                                                                       |                                       |
| _SIV_ / _Synthetic nonce_        | The 24-byte XChaCha nonce derived by BLAKE3 from the key, plaintext, and document ID. See [`ciphersuite.md`](./ciphersuite.md).                                                                                | `Siv`                                 |
| _Domain separator_               | The byte string `/keyhive/`: first input to the synthetic nonce, AEAD associated data, and `derive_key` context for the final stage of every derived key. Not used in content-addressing digests.                               | `domain_separator::SEPARATOR`         |

## Data and Sync

| Term | Meaning | In code |
|------|---------|---------|
| _Content reference_ | An application-defined identifier for a chunk of encrypted content, typically its BLAKE3 hash. | `ContentRef` (32-byte array by default) |
| _Digest_ | A typed BLAKE3 hash. `Digest<T>` for different `T` are distinct types. | `Digest<T>` |
| _Signed_ | A payload with its Ed25519 signature and the signer's verifying key. | `Signed<T>` |
| _Event_ / _Static event_ | The replication unit: a signed membership operation, prekey operation, or CGKA operation, in a form that can be serialised without live references. | `Event`, `StaticEvent` |
| _Archive_ | A serialisable snapshot of a whole `Keyhive` for persistence. | `Archive` |
| _Contact card_ | The minimal out-of-band bundle (verifying key + a prekey) needed to add someone. | `ContactCard` |
| _Relay_ (noun) | A peer or server that holds `Relay` access: stores and forwards ciphertext for others. | |
| _Subduction_ | The sync protocol and relay implementation that transports Keyhive events and ciphertext. Formerly _Beelay_. Separate repository. | |
| _Sedimentree_ | Subduction's depth-partitioned structure for compressing and syncing commit DAGs. | |
| _Causal delivery_ | The guarantee that an operation is applied only after all of its predecessors. Assumed by Keyhive, provided by the sync layer plus local buffering. | |

## Meta

| Term | Meaning |
|------|---------|
| _E2EE_ | End-to-end encryption: only endpoints with `Read` hold plaintext. |
| _Local-first_ | Software where the primary copy of data lives on the user's device and collaboration happens by sync, so it must tolerate partitions and offline work. |
| _CRDT_ | Conflict-free Replicated Data Type. Both Keyhive's membership and BeeKEM's operation graph are op-based CRDTs; Keyline is a state-based one. |
| _ocap_ | Object-capability model: authority as unforgeable references, fail-stop, no third-party revocation. |
| _SPKI_ / _Certificate capabilities_ | Authority as signed certificate chains presented by the invoker (SPKI, UCAN). |
