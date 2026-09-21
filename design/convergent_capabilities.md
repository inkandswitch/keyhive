# Convergent Capabilities

Convergent capabilities ("concap") are Keyhive's authorization model: a capability system whose state is a CRDT. Every replica that has seen the same set of delegations and revocations computes the same answer to "who may do what", regardless of the order in which it saw them.

This document explains why the model exists and how it differs from its ancestors. Worked examples are in [Group Membership](./group_membership.md). Terms are defined in the [glossary](./glossary.md).

> [!NOTE]
> [Keyline] is the successor design: a uniform authority graph over keys with jurisdiction-scoped revocation. This document describes the current model.

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

## Motivation

Keyhive authorises edits to op-based CRDTs such as Automerge. Three constraints follow:

1. _Partition tolerance._ Replicas MUST be able to grant, revoke, and exercise authority while offline, and converge on reconnection.
2. _Complete history._ An op-based CRDT cannot skip an operation. Authorisation decisions must therefore cover operations authored under authority that was later revoked, and those operations cannot be deleted.
3. _Size._ Automerge documents live on end-user devices. Authorisation metadata must be proportionate.

Neither established family of capability systems satisfies all three.

## Lineage

### Object capabilities (ocap)

In an [object-capability][ocap] system, authority is an unforgeable reference: you have authority over an object if and only if you hold a reference to it. Delegation is passing the reference on; revocation is interposing a proxy and later cutting it.

Ocap has a stateful authority graph and the [Principle of Least Authority][PoLA] follows naturally. But it is _fail-stop_: the reference graph is global mutable state and a revocation is observed atomically by everyone. Under partition two replicas can hold contradictory graphs with no reconciliation rule. Delegator-independence (dropping your reference leaves the copies you handed out intact) also means an administrator cannot cut off authority they did not personally grant.

### Certificate capabilities (SPKI, UCAN)

In [SPKI] and its descendant [UCAN], a capability is a signed certificate, and a chain of certificates from the resource owner to the invoker is the proof of authority. The invoker presents the chain; the verifier checks signatures and attenuation.

Certificates are stateless and work offline. The same property makes revocation weak: a revocation is a separate statement the verifier must already know about, and because authority is evaluated per invocation, group policy (groups of groups, admin override) must be encoded as further certificates. Expressing Keyhive's revocation semantics this way needs a number of certificates that grows exponentially with group nesting.

### Convergent capabilities

Concap keeps SPKI's artefacts (signed, content-addressed delegations and revocations that anyone can verify offline) and ocap's evaluation model (authority is a property of a stateful graph, not of a chain the invoker presents), and adds a CRDT merge rule so the graph is well defined under partition.

|                         | ocap                                   | Certificate capabilities                | Convergent capabilities                                                            |
|-------------------------|----------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------|
| Authority is            | an unforgeable reference               | a chain of signed certificates          | reachability in a replicated graph                                                 |
| Who assembles the proof | nobody; holding the reference is proof | the invoker presents a chain            | the verifier searches the set it holds                                             |
| Evaluation happens      | on every message send                  | at invocation                           | continuously                                                                       |
| State model             | global, mutable, atomic                | stateless                               | op-based CRDT (grow-only set)                                                      |
| Under partition         | fail-stop                              | grants work; revocations may be unknown | converges                                                                          |
| Third-party revocation  | caretaker pattern                      | issuers along the chain                 | issuers along the proof lineage, admins, or holders of at least the target's level |
| Metadata size           | n/a                                    | exponential in nesting                  | linear in operations                                                               |

## Model

### Principals

Every principal is an Ed25519 verifying key. Individuals, groups, and documents are all agents and differ only in the state attached to the key. A group's identifier is its root verifying key, so a delegation chain rooted in a signature by that key is self-certifying.

### Operations

There are two kinds of authority operation, both signed by their issuer and both content-addressed:

- A _delegation_: _issuer_ grants _delegate_ access level `can` over the group, citing `proof` (the issuer's own delegation into the group) and recording the revocations and document heads it was issued after.
- A _revocation_: _issuer_ withdraws a specific delegation by hash, citing `proof` of the issuer's own authority and recording the document heads it was issued after.

The set of operations is grow-only and merges by set union. A revocation is a new fact about an old operation, not a deletion.

### Access levels

```
Relay < Read < Edit < Admin
```

A delegation's level MUST be at or below its proof's level. `Relay`, `Read`, and `Edit` are conveyance levels: what may travel along the edge. `Admin` is the governance level: authority over the graph itself. The [glossary](./glossary.md#authority) lists what each level permits.

### Evaluation

Authority is reachability. An agent _A_ holds level _L_ over group _G_ if there is a path of un-revoked delegations from _G_'s root to _A_ in which every hop is validly signed by the previous hop's delegate, and _L_ is the minimum level along that path. Where several paths exist, the agent holds the maximum of the per-path minimums.

Groups may be members of groups and the graph MAY contain cycles; two groups that delegate `Admin` to each other are one group for evaluation purposes. Evaluation is a fixed point over the graph, not a chain walk, so cycles are harmless.

### Revocation

- _Authority to revoke._ An agent MAY revoke a delegation it issued, any delegation whose proof chain passes through one it issued, or, holding `Admin`, any delegation in the group. An agent whose transitive access into the group is at least the target's level MAY also revoke it.
- _Seniority._ An agent added earlier is senior to one added later. A non-admin MUST NOT revoke a member senior to itself. A re-added agent keeps the seniority of its earliest add.
- _Concurrent revocations._ Conflicting revocations are totally ordered by depth in the causal operation graph (proof and after-revocation edges), then by digest, so every replica selects the same survivor.
- _Cascades._ Revoking a delegation invalidates every delegation whose proof chain passes through it, possibly including the revoker's own.
- _Causal position._ Every operation records the document heads (`after_content`) and revocations (`after_revocations`) it was issued after. Content that causally follows a revocation and is authored by the revoked key is rejected; content that precedes it stands.
- _Whiteout._ Operations whose authority is revoked after the fact are retained, because later operations may depend on them, but excluded from materialisation.

### Encryption

The capability graph determines membership of a document's BeeKEM tree: every agent with transitive `Read` or better is a leaf; agents with only `Relay` are not. Membership changes drive key rotation, and a `Relay`-only sync server can evaluate the graph without holding a decryption key. Certificate capabilities alone cannot support this, because the verifier does not hold a complete view of membership.

## Properties

- _Convergence._ Same operation set, same materialised authority, on every replica.
- _Offline operation._ Granting, revoking, and exercising authority are signed operations and need no connectivity.
- _Self-certification._ A group's authority is verifiable from its identifier alone.
- _Least authority._ Delegation is attenuating and always permitted.
- _Bounded metadata._ Authorisation state is linear in the number of membership changes.
- _Deterministic concurrent revocation._ Seniority and the depth-then-digest order resolve every conflict identically everywhere.

## Limitations

- _No delegator-independence._ If your standing is revoked, everything you delegated goes with it. This enables cascades and healing, but an administrator's mistake can be wide-reaching.
- _Membership is visible to relays._ A `Relay` must see the graph to evaluate it.
- _Causal, not temporal._ A genuinely old operation arriving late is indistinguishable from a back-dated one; see the [threat model](./threat_model.md#t5-back-dating).
- _Tiebreaks are arbitrary._ Seniority and depth-then-digest are deterministic but do not reflect who ought to win. Keyline replaces them with explicit jurisdictions.

## FAQ

### Is this SPKI with a revocation list?

No. In SPKI the invoker chooses which chain to present and the verifier checks only that chain. In concap the verifier holds the whole graph and computes reachability; the invoker presents only a signature. A revocation anywhere in the graph therefore affects authority everywhere it is relevant, without re-issuing certificates.

### Is this ocap over a CRDT?

Closer, but ocap has no third-party revocation and no administrator. Concap adds `Admin`, lineage-scoped revocation, and causal ordering so that group governance is expressible.

### Why not delete revoked operations?

Op-based CRDTs cannot materialise with gaps. Revoked operations are retained for causality and excluded from materialisation.

### Can sub-delegation be restricted?

No. Forbidding delegation leads users to share secret keys instead. Attenuate: delegate the narrowest level that does the job.

<!-- External Links -->
[BCP 14]: https://datatracker.ietf.org/doc/bcp14/
[Keyline]: https://github.com/inkandswitch/keyhive/tree/keyline/design/keyline
[PoLA]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
[SPKI]: https://datatracker.ietf.org/doc/html/rfc2693
[UCAN]: https://github.com/ucan-wg/spec
[ocap]: https://en.wikipedia.org/wiki/Object-capability_model
