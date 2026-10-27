# Glossary

Terms used across the Keyhive design documents and code. Where the design documents and the Rust code use different names, both are given.

## Principals

| Term | Meaning | In code |
|------|---------|---------|
| _Principal_ | Anything that can hold, delegate, or exercise authority. Identified by an Ed25519 verifying key. | `keyhive_crypto::identifier::Identifier`; a transient `Principal` handle |
| _Individual_ | A bare key pair with no membership state: a device, WebCrypto context, passkey, or hardware key. Publishes X25519 prekeys so it can be added to BeeKEM trees. | `Individual`, `IndividualState`, `IndividualId` |
| _Group_ | A key that stands for a set of members: a Keyline subject other keys hold delegations about. Keyline's _role_. | `Group`, `GroupId` |
| _Document_ | A subject that also owns encrypted content and a BeeKEM tree. A replica knows a document from its authorized CGKA operations. | `Document`, `DocumentState`, `DocumentId` |
| _Active_ | The individual whose signing key this replica controls. | `Active` |
| _Membered_ | A group or a document: anything with members. | `MemberedId` |
| _Root_ / _Genesis key_ | The key pair whose verifying key _is_ a group's or document's identifier. It signs the subject's root edges (`Admin` to each creator) and is then discarded. | `certificate::root_edges` |

## Authority

Keyhive's authority model is [Keyline]; its [glossary][keyline glossary] defines the graph terms (route, live, admin reach, positive graph, closure, heal). The terms the rest of Keyhive uses:

| Term | Meaning | In code |
|------|---------|---------|
| _Certificate_ | A signed delegation or revocation. The certificate set is a state-based CRDT: it only grows, and merges by union. | `keyline::certificate::Certificate` |
| _Delegation_ | A signed edge: _issuer_ grants _audience_ `power` over _subject_, optionally citing an earlier revocation (a re-issue). It names no proof: authority is recomputed from the whole set. | `keyline::delegation::Delegation` |
| _Revocation_ | A signed statement that a delegation, named by digest, no longer holds, with a `retain` watermark of content heads. | `keyline::revocation::Revocation` |
| _Power_ | `Relay < Read < Edit < Admin`. Totally ordered; each level implies the ones below. | `Power` |
| _Relay_ | May sync and forward ciphertext but not decrypt it. The level held by sync servers. Never placed in a BeeKEM tree. | `Power::Relay` |
| _Read_ | May decrypt content; is a BeeKEM member. | `Power::Read` |
| _Edit_ | May append operations to content. | `Power::Edit` |
| _Admin_ | May act on the graph: revoke on routes through the node, and so manage a group's members. | `Power::Admin` |
| _Effective power_ | What a principal holds over a subject: the maximum over live routes of the minimum `power` along each. | `Keyline::effective_power` |
| _Admin reach_ | The nodes a key ever held `Admin` over, plus its own. A revocation by a third party breaks its target only on routes through the issuer's admin reach. | |
| _Adoption_ | Re-issuing, from the revoker, the delegations a removed member issued, at no more than the revoker's power, so the members they admitted keep their access. Distinct from Keyline's _heal_ (a re-issue citing a revocation). | `revoke_member(…, retain_all_other_members: true)` |
| _Reconciliation_ | Bringing each held document's BeeKEM tree in line with its readers after this replica's own certificate write, citing the certificate behind each add and remove. Certificates received from peers do not trigger it ([threat model, G4](./threat_model.md#g4-reconciliation-follows-local-writes-only)). | `Keyhive::insert_and_reconcile` |
| _Membership by parenthood_ | Whoever creates a group or document holds `Admin` over it through a root edge from the fresh root key, which is then discarded. | |
| _PoLA_ | Principle of Least Authority: grant the narrowest capability that does the job. Keyhive never restricts sub-delegation, because doing so pushes users toward sharing raw keys instead. | |
| _Retention watermark_ | The content heads a revocation records for each document it can affect: what the issuer had seen when revoking, as the application last set them (`Keyhive::set_content_heads`). The content layer decides what the revoked key's later content means. | `Revocation::retain`, `ContentHeads` |
| _Convergent capabilities_ (_concap_) | Certificate capabilities whose authority is evaluated over a CRDT of delegations and revocations, so all replicas converge on the same view. See [Convergent Capabilities](./convergent_capabilities.md). | |
| _Keyline_ | The authority graph: a uniform graph over keys, with revocation scoped by the issuer's admin reach. See [Keyline]. | `keyline`, `keyline_memory` |

## Encryption

| Term                             | Meaning                                                                                                                                                                                                        | In code                               |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
| _BeeKEM_                         | Keyhive's concurrent variant of TreeKEM: a binary tree of X25519 keys whose root secret is shared by all readers. See [`beekem/README.md`](../beekem/README.md).                                               | `beekem` crate, `Cgka`, `BeeKem`      |
| _CGKA_                           | Continuous Group Key Agreement: the class of protocol BeeKEM belongs to. Members keep agreeing on a fresh shared secret as membership changes.                                                                 | `Cgka`                                |
| _Share key_ / _Share secret key_ | An X25519 public / secret key used for key exchange (as distinct from a signing key).                                                                                                                          | `ShareKey`, `ShareSecretKey`          |
| _Prekey_                         | A share key an individual publishes ahead of time so others can add it to a BeeKEM tree without a round trip.                                                                                                  | `KeyOp`, `AddKeyOp`, `RotateKeyOp`    |
| _Path secret_                    | The secret at an inner BeeKEM node, sampled independently per update and encrypted for the sibling's resolution.                                                                                               | `SecretStore`                         |
| _Root secret_ / _PCS key_        | The secret at the BeeKEM root after a successful update. Source of all application secrets for an epoch.                                                                                                       | `PcsKey` (beekem), `GroupSecret` (keyhive_content) |
| _Application secret_             | A per-chunk symmetric key derived from the PCS key, the content reference, and the predecessor references.                                                                                                     | `ApplicationSecret`                   |
| _Epoch_                          | The period during which one root secret is current (from the update that establishes it until the next operation that changes the root).                                                                       |                                       |
| _Batch_                          | In BeeKEM, a group of operations a replay applies together, containing every operation concurrent with any operation in it. Batches are applied in causal order.                                               | `CgkaBatch`                           |
| _Conflict keys_                  | Multiple public keys retained at one tree node after concurrent updates. Treated like a blank node until resolved by a later update.                                                                           | `ConflictKeys`, `NodeKey`             |
| _Blank node_                     | A tree node with no key: unoccupied leaf, removed member, or an inner node invalidated by an add/remove.                                                                                                       |                                       |
| _Resolution_                     | For a blank or conflicted node, the set of its highest non-blank, non-conflicted descendants; what an update must encrypt for.                                                                                 |                                       |
| _Causal encryption_              | Encrypting each content chunk under its own key and embedding the keys of its causal predecessors, so possession of the current key unlocks the history. See [`causal_encryption.md`](./causal_encryption.md). | `EncryptedContent`, `CiphertextStore` |
| _Forward secrecy (FS)_           | Compromise of current keys does not reveal past data. Not provided: members keep old BeeKEM secrets so that history stays decryptable.                                                                         |                                       |
| _Post-compromise security (PCS)_ | Compromise of current keys does not reveal future data after a key rotation. Provided by BeeKEM updates.                                                                                                       |                                       |
| _SIV_ / _Synthetic nonce_        | The 24-byte XChaCha nonce derived by keyed BLAKE3 from a subkey, the associated data, and the plaintext; checked after decryption. See [`ciphersuite.md`](./ciphersuite.md).                                   | `siv::synthetic_nonce`                |
| _Key-derivation context_         | A BLAKE3 `derive_key` context, `/keyhive/<area>/<purpose>/v<N>/<YYYY-MM-DD>`, one per derivation. See [`ciphersuite.md`](./ciphersuite.md#domain-separation).                                                  | `context::Context`                    |

## Data and Sync

| Term | Meaning | In code |
|------|---------|---------|
| _Content reference_ | An application-defined identifier for a chunk of encrypted content, typically its BLAKE3 hash. | `ContentRef` (32-byte array by default) |
| _Digest_ | A typed BLAKE3 hash. `Digest<T>` for different `T` are distinct types. | `Digest<T>` |
| _Signed_ | A payload with its Ed25519 signature and the signer's verifying key. | `Signed<T>` |
| _Event_ / _Static event_ | The replication unit: a certificate, prekey operation, or CGKA operation, in a form that can be serialised without live references. | `Event`, `StaticEvent` |
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
| _CRDT_ | Conflict-free Replicated Data Type. BeeKEM's operation graph is an op-based CRDT; Keyline's certificate set is a state-based one. |
| _ocap_ | Object-capability model: authority as unforgeable references, fail-stop, no third-party revocation. |
| _SPKI_ / _Certificate capabilities_ | Authority as signed certificate chains presented by the invoker (SPKI, UCAN). |

<!-- Links -->

[Keyline]: ./keyline/README.md
[keyline glossary]: ./keyline/README.md#glossary
