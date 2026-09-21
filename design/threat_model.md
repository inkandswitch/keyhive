# Threat Model

This document describes who Keyhive defends against, what it defends, and what it does not. It covers the crates in this repository (`keyhive_core`, `keyhive_crypto`, `beekem`, `keyhive_wasm`). Transport-level threats (handshake impersonation, replay, denial of service on a relay) are covered by [Subduction's threat model][subduction threats].

> [!WARNING]
> Keyhive is pre-alpha and has not been audited. This document describes the intended security properties. See [SECURITY.md](../SECURITY.md) for how to report a problem.

## Assets

| Asset                                            | Protected by                                                                                   |
|--------------------------------------------------|------------------------------------------------------------------------------------------------|
| Document content (plaintext of CRDT operations)  | Causal encryption under BeeKEM application secrets                                             |
| Membership (who may read, edit, administer)      | Signed delegation / revocation graph ([Convergent Capabilities](./convergent_capabilities.md)) |
| Integrity and authorship of membership operations | Ed25519 signatures; content addressing of predecessors                                         |
| Signing keys and X25519 share keys               | Out of scope (see [Non-Goals](#non-goals)); `AsyncSigner` lets hosts keep keys in WebCrypto, hardware, or a KMS |
| Existence of documents; shape of the graph       | Not protected from `Relay` holders (see [T8](#t8-metadata))                                    |

## Trust Assumptions

- Ed25519, X25519, XChaCha20-Poly1305, and BLAKE3 are secure. The synthetic-nonce construction in [`ciphersuite.md`](./ciphersuite.md) is assumed secure pending review.
- Each replica's CSPRNG is sound. BeeKEM samples every path secret from it.
- A replica's local storage is as trustworthy as the replica. There is no defence against an adversary who controls the host.
- Operations are delivered causally. The sync layer is responsible for this; Keyhive buffers operations whose predecessors are missing.
- The genesis key of a group or document is honest at creation.

## Adversaries

### A1. Untrusted relay

Holds `Relay`: stores and forwards ciphertext; sees operation hashes, sizes, timing, and the membership graph. Cannot decrypt.

_Mitigations_: content is E2EE; `Relay` is excluded from the BeeKEM tree, so a relay never receives a path secret; a relay serves only peers that can prove `Relay` or better.

### A2. Revoked member

Was a legitimate reader or editor. Retains every key and plaintext seen while a member.

_Mitigations_: post-compromise security. The next path update after a removal produces a root secret the revoked member cannot derive. Edits that causally follow the revocation are rejected. Historical plaintext is not recoverable from them; see [Non-Goals](#non-goals).

### A3. Malicious member

Holds valid `Read` or `Edit`. May try to escalate, grief others, or break convergence.

_Mitigations_: delegation is capped at the delegator's level; transitive authority is the minimum along the best path; revocation authority is limited to the revoker's proof lineage unless they hold `Admin` or transitive access of at least the target's level; all membership and CGKA operations are signed and content-addressed. Concurrent membership changes converge deterministically ([Group Membership](./group_membership.md)).

### A4. Compromised device

Exfiltrates a member's signing key and share keys, becoming indistinguishable from that member (A3) until revoked (A2).

_Mitigations_: Keyhive does not own key storage; `AsyncSigner` and `JsSigner` let hosts use non-extractable WebCrypto keys, passkeys, or hardware. A user group delegating to per-device keys limits the blast radius to one device, which the user group can revoke.

### A5. Network adversary

Observes or modifies traffic.

_Mitigations_: every membership, prekey, and CGKA operation is signed; every reference is a BLAKE3 digest; content is E2EE and each chunk is bound by its AEAD tag and `pcs_update_op_hash` to a signed CGKA operation. Content chunks carry no signature of their own; content authorship belongs to the CRDT layer. Traffic-pattern confidentiality depends on the transport.

### A6. Byzantine peer

Sends malformed, duplicated, or unauthorised operations.

_Mitigations_: unauthorised operations fail signature or capability checks. Duplicates are idempotent. Operations with missing predecessors are buffered, not applied, so withholding history cannot cause divergence.

## Threats

### T1. Unauthorised read

- Content is encrypted under per-chunk application secrets derived from the BeeKEM root secret.
- Only members with `Read` or higher are BeeKEM leaves.
- Transitive access is clamped to the weakest link, so `Relay` on a group cannot become `Read` on a document.

### T2. Unauthorised write

- Every membership operation is signed and cites a proof chain to the root; every replica verifies it.
- Content is not signed by Keyhive. Producing a chunk whose AEAD tag verifies requires the current application secret, so an adversary without `Read` cannot forge content. Distinguishing `Read` from `Edit` on the content path is the CRDT layer's responsibility, using the authority graph Keyhive exposes.

### T3. Privilege escalation by delegation

- `Access` is totally ordered; a delegation's level is capped by its proof's level.
- Authority is the maximum over paths of the per-path minimum, so indirection cannot raise it.

### T4. Revocation cascades

A revokes B while B concurrently revokes A; or a revocation removes the proof for an unrelated delegation.

- Revocations are causally ordered with delegations and content (`after_revocations`, `after_content`).
- Revocation authority follows proof lineage; `Admin`, or transitive access of at least the target's level, overrides it. Seniority (earlier add wins) constrains non-admins.
- Conflicting revocations are totally ordered by depth in the causal operation graph (proof and after-revocation edges), then digest, so every replica selects the same survivor.
- Operations whose authority is revoked after the fact are retained for causality and excluded from materialisation.

### T5. Back-dating

A revoked member fabricates operations claiming earlier causal predecessors.

- Every revocation records the document heads it was issued after. Content authored by the revoked key that does not causally precede that frontier is rejected.
- Keyhive cannot distinguish a genuinely old operation that arrives late from a back-dated one. Applications that need this must add a timestamping or anchoring service. See [Non-Goals](#non-goals).

### T6. BeeKEM fork attacks

Two members issue concurrent path updates; an attacker who compromised one fork tries to read the other.

- Conflicting node keys are retained. A node with conflict keys is treated as blank, so an update encrypts for its resolution; neither fork's secrets suffice to decrypt the other.
- Concurrent adds and removes are re-sorted deterministically so replicas converge on the same tree.

### T7. Nonce reuse and key commitment

- Nonces are derived from key, plaintext, and document ID; reuse requires an identical triple.
- The recipient recomputes the nonce after decryption and rejects a mismatch, which commits the ciphertext to one key. See [`ciphersuite.md`](./ciphersuite.md).

### T8. Metadata

An observer without plaintext learns document IDs, membership, operation counts, sizes, and timing.

- Accepted. Relays must see membership to evaluate capabilities. Sizes and timing are visible to the transport. Padding and cover traffic are application or transport concerns.

### T9. Genesis compromise

The root key of a group or document is malicious or leaked at creation.

- Accepted. The root is the trust anchor. Applications should treat creation as security-relevant and may create from a hardened key and delegate immediately.

## Non-Goals

- _Forward secrecy._ A current reader can decrypt all history, and members retain old BeeKEM secrets to do so. Op-based CRDTs cannot materialise with gaps.
- _Identity._ Keys are the only principals. Binding keys to people is a layered concern (DIDs, petnames, ATProto).
- _Key recovery or storage._ Hosts choose how keys are held.
- _Trusted time._ Ordering is causal only.
- _Availability._ Keyhive guarantees that what is delivered is correct, not that it is delivered.
- _Protection from a compromised host._
- _Traffic analysis resistance._ See T8.

## Open Questions

- Independent review of the synthetic-nonce and key-commitment construction.
- Test coverage for T4 and T5.
- Whether [Keyline]'s jurisdiction-scoped revocation changes T4.

<!-- External Links -->
[Keyline]: https://github.com/inkandswitch/keyhive/tree/keyline/design/keyline
[subduction threats]: https://github.com/inkandswitch/subduction/blob/main/design/security/threats.md
