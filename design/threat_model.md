# Threat Model

## Scope

This document describes the threat model for Keyhive: the authorization, encryption, and group key agreement layers. Threats specific to the Beelay sync relay, transport security (TLS/mTLS), or specific identity systems are out of scope here.

## Security Goals

| Goal | Description |
|------|-------------|
| **Authorization integrity** | Only agents with a valid delegation chain can perform actions at or below their granted access level. |
| **Confidentiality (read control)** | Document content is readable only by agents whose public keys are included in the CGKA tree at the time the content was encrypted. |
| **Post-compromise security** | After an agent is removed from a group, they cannot decrypt content encrypted with subsequent PCS keys. |
| **Self-certification** | Authorization chains can be verified without external trust anchors. A document's public key is its identifier; the delegation DAG is self-certifying. |
| **Availability under partition** | The system operates correctly under network partitions. Authorization and content operations are eventually consistent; no online coordinator is required. |

## Non-Goals

| Non-goal | Rationale |
|----------|-----------|
| **Forward secrecy** | Op-based CRDTs require complete causal history for materialization. Restricting access to historical data would prevent document reconstruction. |
| **Identity / authentication** | Keyhive is authZ only. Identity binding (DIDs, KERI, OpenPGP, etc.) is explicitly out of scope and pluggable. |
| **Transport confidentiality** | Assumed to be handled by TLS/mTLS at the transport layer. |
| **Denial-of-service resistance** | Rate limiting and connection management are relay concerns, not protocol concerns. |

## Trust Assumptions

| Assumption | Detail |
|------------|--------|
| **Ed25519 is secure** | Signing keys are unforgeable; verifying keys faithfully identify agents. |
| **X25519 is secure** | Diffie-Hellman key exchange produces shared secrets unknown to passive observers. |
| **BLAKE3 is collision-resistant** | Content addressing and SIV construction depend on collision resistance. |
| **XChaCha20-BLAKE3-MiCKey is IND-CPA secure** | Symmetric encryption is semantically secure under chosen-plaintext attack. _Note: this construction needs further cryptographic review (see [cipher suite](./ciphersuite.md))._ |
| **Signing keys are kept secret** | Compromise of a signing key grants the attacker all capabilities of that agent until revoked. |
| **Causal delivery** | Operations are received in causal order (guaranteed by Keyhive's event system and sync protocol). |

## Threat Actors

### Passive External Adversary

An observer who can read all network traffic and stored ciphertext but cannot compromise any signing or encryption keys.

**Capabilities:**
- Read all E2EE ciphertext in transit and at rest
- Observe the structure of the authority graph (which agents exist, delegation topology)
- Observe operation timing and frequency

**Mitigations:**
- Content is encrypted with per-block symmetric keys derived from CGKA
- SIV construction prevents nonce reuse across payloads
- Key-committing encryption prevents key-switching attacks

### Compromised Member (Insider)

An agent who was once a legitimate member but has been revoked, or a member who acts maliciously within their granted authority.

**Capabilities:**
- Access all content encrypted before their revocation (no forward secrecy)
- Attempt to backdate operations (sign operations with timestamps before revocation)
- Attempt sub-delegation beyond their authority

**Mitigations:**
- PCS: after removal from the CGKA tree, new PCS keys exclude the revoked member's public key
- Backdating detection: revocations lock to causal document state via `doc_heads`; operations from a revoked agent that causally succeed the lock point are rejected
- Visibility index: operations from revoked agents remain available for causal integrity but may not materialize depending on the auth graph

### Compromised Sync Server (Honest-but-Curious Relay)

A Beelay relay that stores and forwards E2EE chunks but may attempt to learn content.

**Capabilities:**
- Store all ciphertext
- Observe the delegation graph structure (needed for [collection sync](./collection_sync.md))
- Observe which agents sync which documents
- Withhold or delay message delivery

**Mitigations:**
- Server only has Pull access; cannot decrypt content
- Key-committing encryption means server cannot substitute ciphertext
- Capability proofs are required for data access; server validates delegation chains
- Sedimentree chunking is designed for ciphertext-only operation (no plaintext needed for sync)

### Active Network Adversary

An attacker who can intercept, modify, and inject network messages.

**Capabilities:**
- All passive adversary capabilities
- Modify messages in transit
- Replay old messages
- Inject new messages

**Mitigations:**
- TLS/mTLS at the transport layer (out of scope for Keyhive but assumed)
- All operations are signed with Ed25519; modified messages fail signature verification
- Content-addressed hashing detects tampering
- Causal ordering prevents replay of stale operations

## Attack Surface

### Delegation Graph Manipulation

**Attack:** An attacker with Manage access delegates broader authority than intended, or creates delegation cycles to confuse authorization resolution.

**Mitigation:** Delegation can only grant authority the delegator themselves possesses (attenuation is monotonically narrowing). Cycles are explicitly permitted and handled by fixed-point resolution during [collection sync](./collection_sync.md). Authorization validation recurses through the full graph.

### Revocation Evasion

**Attack:** A revoked agent races to create sub-delegations or content operations before the revocation propagates.

**Mitigation:** Revocations include `doc_heads` that lock the revocation to a specific causal state of the document content. Operations from the revoked agent that causally succeed this state are not materialized. The visibility index retains them for causal completeness but suppresses materialization.

### Revocation Cascade Instability

**Attack:** Agent A revokes Agent B, but then Agent C revokes Agent A. The cascade of A's revocation of B is itself revoked.

**Mitigation:** The system is designed for this. Revocation cascades are computed from the materialized auth graph at each causal point. The auth graph is a CRDT; concurrent revocations converge deterministically.

### CGKA State Divergence

**Attack:** Concurrent key rotations create conflicting states at inner tree nodes, potentially allowing a passive adversary to derive the root secret from a subset of keys.

**Mitigation:** BeeKEM retains _all_ concurrent public keys at conflict nodes. A passive adversary must possess _all_ historical secret keys at one of the leaves to derive the root secret after a merge. This is a fundamental design property of BeeKEM.

### Prekey Reuse

**Attack:** In a fully concurrent system, the same prekey may be selected for multiple document invitations, linking the security of those documents.

**Mitigation:** Individuals publish multiple prekeys. The probability of reuse is tunable by adjusting the prekey set size. Upon coming online, the invitee rotates the BeeKEM key and removes the consumed prekey.

## Open Questions

- The XChaCha20-BLAKE3-MiCKey construction needs further cryptographic review (flagged in [cipher suite](./ciphersuite.md))
- Post-quantum migration path: X25519 and ChaCha20 are replaceable, but the migration mechanism is not yet specified
- Formal verification of the BeeKEM security properties against the concurrent TreeKEM threat model
