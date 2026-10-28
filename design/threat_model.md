# Threat Model

This document describes who Keyhive defends against, what it defends, and what it does not. It covers the crates in this repository (`keyhive_core`, `keyhive_crypto`, `beekem`, `keyhive_wasm`). Transport-level threats (handshake impersonation, replay, denial of service on a relay) are covered by [Subduction's threat model][subduction threats].

> [!WARNING]
> Keyhive is pre-alpha and has not been audited. This document describes the intended security properties; [Known Gaps](#known-gaps) lists where the current code falls short of them. See [SECURITY.md](../SECURITY.md) for how to report a problem.

## Assets

| Asset                                            | Protected by                                                                                   |
|--------------------------------------------------|------------------------------------------------------------------------------------------------|
| Document content (plaintext of CRDT operations)  | Causal encryption under BeeKEM application secrets                                             |
| Membership (who may read, edit, administer)      | Signed delegation / revocation graph ([Keyline])                                               |
| Integrity and authorship of membership certificates | Ed25519 signatures; certificates content-addressed by the digest of their issuer and payload  |
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

Holds `Relay`: stores and forwards ciphertext and the document's CGKA operations; sees operation hashes, sizes, timing, the membership graph, and the CGKA group's shape and public keys. Cannot decrypt.

_Mitigations_: content is E2EE; `Relay` is excluded from the CGKA group, so a relay never receives a path secret (the CGKA operations it carries are signed, and their secrets are encrypted to the CGKA group's members); a relay serves only peers that can prove `Relay` or better. A relay can still remove members from a document's CGKA group ([G3](#g3-eviction-through-a-self-revoked-delegation)).

### A2. Revoked member

Was a legitimate reader or editor. Retains every key and plaintext seen while a member.

_Mitigations_: post-compromise security. The next path update after a removal produces a root secret the revoked member cannot derive. Each revocation records the content heads it was issued after, so the content layer can reject the revoked member's later edits (T5). Historical plaintext is not recoverable from them; see [Non-Goals](#non-goals). Today a revoked member can put a fresh key of its own back in the tree ([G1](#g1-a-revoked-member-can-re-seat-a-key)), and only the revoker's replica removes it ([G4](#g4-reconciliation-follows-local-writes-only)).

### A3. Malicious member

Holds valid `Read` or `Edit`. May try to escalate, grief others, or break convergence.

_Mitigations_: effective power is the minimum along a route, so delegating above your own level grants nothing extra; a revocation acts only on routes through its issuer's admin reach, or on a certificate the issuer signed or is named by; all certificates and CGKA operations are signed and content-addressed. The certificate set is a state-based CRDT, so concurrent membership changes converge ([Keyline]).

### A4. Compromised device

Exfiltrates a member's signing key and share keys, becoming indistinguishable from that member (A3) until revoked (A2).

_Mitigations_: Keyhive does not own key storage; `AsyncSigner` and `JsSigner` let hosts use non-extractable WebCrypto keys, passkeys, or hardware. A user group delegating to per-device keys limits the blast radius to one device, which the user group can revoke.

### A5. Network adversary

Observes or modifies traffic.

_Mitigations_: every membership, prekey, and CGKA operation is signed; every reference is a BLAKE3 digest; content is E2EE and each chunk is bound by its AEAD tag and `pcs_update_op_hash` to a signed CGKA operation. Content chunks carry no signature of their own; content authorship belongs to the CRDT layer. Traffic-pattern confidentiality depends on the transport.

### A6. Byzantine peer

Sends malformed, duplicated, or unauthorised operations.

_Mitigations_: unauthorised operations fail signature or capability checks. Duplicates are idempotent. Certificates need no causal order: authority is recomputed from the whole set. CGKA operations with missing predecessors are buffered, not applied, so withholding history cannot cause divergence.

## Threats

### T1. Unauthorised read

- Content is encrypted under per-chunk application secrets derived from the BeeKEM root secret.
- Only members with `Read` or higher are seated as BeeKEM leaves. Not yet enforced against a revoked member ([G1](#g1-a-revoked-member-can-re-seat-a-key)) or an adder's choice of key ([G2](#g2-an-adds-key-is-not-bound-to-the-added-members-prekeys)).
- A prekey operation counts only once its signature verifies against its issuer, and a prekey must be a canonical X25519 key of large order, so nobody can publish keys for an identity they do not hold, or a key whose shared secrets anyone can compute.
- Transitive access is clamped to the weakest link, so `Relay` on a group cannot become `Read` on a document.

### T2. Unauthorised write

- Every certificate is signed, and every replica verifies it. Certificates carry no proof: authority is recomputed from the whole set (late binding), so there is no chain to forge.
- A CGKA operation is accepted only from a principal whose standing over the document allows it. For a remove, that check is weaker than intended ([G3](#g3-eviction-through-a-self-revoked-delegation)).
- Content is not signed by Keyhive. Producing a chunk whose AEAD tag verifies requires the current application secret, so an adversary without `Read` cannot forge content. Distinguishing `Read` from `Edit` on the content path is the CRDT layer's responsibility, using the authority graph Keyhive exposes.

### T3. Privilege escalation by delegation

- `Power` is totally ordered. Effective power is the maximum over routes of the minimum along each, so indirection cannot raise it.
- `keyhive_core` refuses to sign a delegation above the issuer's effective power (`AddMemberError::Escalation`). A delegation signed elsewhere is clamped by the same rule.

### T4. Revocation cascades

A revokes B while B concurrently revokes A; or a revocation cuts off delegations its issuer never meant to touch.

- Revocation coverage is computed on the positive graph (every revocation ignored), so no revocation can disable another and the result does not depend on delivery order.
- A third party's revocation breaks its target only on routes through the issuer's admin reach; the issuer or audience of a certificate may break it on every route. An edge above your admin reach never routes through it, so seniority needs no rule. `keyhive_core` signs a revocation only when its issuer holds `Admin`, or issued the delegation itself.
- Concurrent revocations by peers both stand ([permanence][keyline permanence]); the role's parent repairs by rotation.
- Cascades are implicit: a delegation dies when its issuer loses standing, and revives if the issuer regains it. `revoke_member` with `retain_all_other_members` re-issues the removed member's delegations from the revoker, at no more than the revoker's power (adoption), so the members they admitted keep their access.
- Revoked certificates are kept: the set only grows.

### T5. Back-dating

A revoked member fabricates operations claiming earlier causal predecessors.

- Every revocation `keyhive_core` signs records, in `retain`, the content heads of each held document it can affect, as the application last set them (`set_content_heads`); a document with no heads set is left out. Content authored by the revoked key that does not causally precede those heads came after the revocation. Keyhive does not sign or follow content, so the application keeps the heads current and the content layer applies this check.
- Keyhive cannot distinguish a genuinely old operation that arrives late from a back-dated one. Applications that need this must add a timestamping or anchoring service. See [Non-Goals](#non-goals).

### T6. BeeKEM fork attacks

Two members issue concurrent path updates; an attacker who compromised one fork tries to read the other.

- Conflicting node keys are retained. A node with conflict keys is treated as blank, so an update encrypts for its resolution; neither fork's secrets suffice to decrypt the other.
- Concurrent adds and removes are re-sorted deterministically so replicas converge on the same tree.

### T7. Nonce reuse and key commitment

- Nonces are a keyed hash, under a subkey of the encryption key, of the associated data and plaintext (for content, per chunk, with the chunk's index, the block's header and its document); reuse requires identical inputs.
- The recipient recomputes the nonce after decryption and rejects a mismatch, which commits the ciphertext to one key. Content, wrapped root secrets and BeeKEM node secrets are all checked. See [`ciphersuite.md`](./ciphersuite.md).
- A BeeKEM node secret's associated data is its tree and both public keys of the exchange it was sealed under, so it opens in no other tree, even where the same share keys appear in several trees.
- Content's associated data binds every chunk to its block's header, its document, its index, and whether it is the last.

### T8. Metadata

An observer without plaintext learns document IDs, membership, operation counts, sizes, and timing.

- Accepted. Relays must see membership to evaluate capabilities. Sizes and timing are visible to the transport. Padding and cover traffic are application or transport concerns.

### T9. Genesis compromise

The root key of a group or document is malicious or leaked at creation.

- Accepted. The root is the trust anchor. Applications should treat creation as security-relevant and may create from a hardened key and delegate immediately.

## Known Gaps

Where the current code falls short of the threats above. Each is tracked for a fix.

### G1. A revoked member can re-seat a key

CGKA authorization reads Keyline's positive graph, which ignores revocations, so a revoked member keeps the standing it once had. It can delegate to a fresh key of its own and sign a CGKA add that cites that delegation, and every replica seats the new key. Affects A2 and T1.

### G2. An add's key is not bound to the added member's prekeys

A CGKA add names the share key to seat, and nothing checks that it is one of the added member's published prekeys. An adder can seat a key it holds itself. Affects T1.

### G3. Eviction through a self-revoked delegation

A remove must cite a revocation that covers a delegation on the removed member's route. Any principal with positive standing over the document, a `Relay` included, can sign a delegation to a reader, revoke it, and cite that revocation to remove the reader from the tree, though Keyline still says they read. Removing the document's creator empties the tree. This is denial of service, not disclosure: the evicted reader loses new content. Affects A1, A3 and T2.

### G4. Reconciliation follows local writes only

A replica adds and removes readers in its trees after its own membership writes, for the documents it holds. A certificate received from a peer changes Keyline but not the trees, so a reader that a peer revoked is removed from a tree only by the revoker's replica. A reader whose prekeys a replica does not hold is not added there.

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
- Test coverage for T5: no content layer here reads `retain` yet.

<!-- External Links -->
[Keyline]: ./keyline/README.md
[keyline permanence]: ./keyline/README.md#permanence
[subduction threats]: https://github.com/inkandswitch/subduction/blob/main/design/security/threats.md
