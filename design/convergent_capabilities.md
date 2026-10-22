# Convergent Capabilities

Convergent capabilities ("concap") are Keyhive's authorization model: a capability system whose state is a CRDT. Every replica that has seen the same set of delegations and revocations computes the same answer to "who may do what", regardless of the order in which it saw them.

This document explains why the model exists and how it differs from its ancestors. Worked examples are in Keyline's [Worked Example](./keyline/README.md#worked-example). Terms are defined in the [glossary](./glossary.md).

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

## Motivation

Keyhive authorizes edits to op-based CRDTs such as Automerge. Three constraints follow:

1. _Partition tolerance._ Replicas MUST be able to grant, revoke, and exercise authority while offline, and converge on reconnection.
2. _Complete history._ An op-based CRDT cannot skip an operation. Authorization decisions must therefore cover operations authored under authority that was later revoked, and those operations cannot be deleted.
3. _Size._ Automerge documents live on end-user devices. Authorization metadata must be proportionate.

Neither established family of capability systems satisfies all three.

## Lineage

### Object capabilities (ocap)

In an [object-capability][ocap] system, authority is an unforgeable reference: you have authority over an object if and only if you hold a reference to it. Delegation is passing the reference on; revocation is interposing a proxy and later cutting it.

Ocap has a stateful authority graph and the [Principle of Least Authority][PoLA] follows naturally. But it is _fail-stop_: the reference graph is global mutable state and a revocation is observed atomically by everyone. Under partition two replicas can hold contradictory graphs with no reconciliation rule. Delegator-independence (dropping your reference leaves the copies you handed out intact) also means an administrator cannot cut off authority they did not personally grant.

### Certificate capabilities (SPKI, UCAN)

In [SPKI] and its descendant [UCAN], a capability is a signed certificate, and a chain of certificates from the resource owner to the invoker is the proof of authority. The invoker presents the chain; the verifier checks signatures and attenuation.

Certificates are stateless and work offline. The same property makes revocation weak: a revocation is a separate statement the verifier must already know about, and because authority is evaluated per invocation, group policy (groups of groups, admin override) must be encoded as further certificates. Expressing Keyhive's revocation semantics this way needs a number of certificates that grows exponentially with group nesting.

### Convergent capabilities

Concap keeps SPKI's artifacts (signed, content-addressed delegations and revocations that anyone can verify offline) and ocap's evaluation model (authority is a property of a stateful graph, not of a chain the invoker presents), and adds a CRDT merge rule so the graph is well defined under partition.

|                         | ocap                                   | Certificate capabilities                | Convergent capabilities                                                            |
|-------------------------|----------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------|
| Authority is            | an unforgeable reference               | a chain of signed certificates          | reachability in a replicated graph                                                 |
| Who assembles the proof | nobody; holding the reference is proof | the invoker presents a chain            | the verifier searches the set it holds                                             |
| Evaluation happens      | on every message send                  | at invocation                           | continuously                                                                       |
| State model             | global, mutable, atomic                | stateless                               | state-based CRDT (grow-only set)                                                   |
| Under partition         | fail-stop                              | grants work; revocations may be unknown | converges                                                                          |
| Third-party revocation  | caretaker pattern                      | issuers along the chain                 | the issuer, the audience, or anyone whose admin reach the route passes through      |
| Metadata size           | n/a                                    | exponential in nesting                  | linear in operations                                                               |

## Model

The model is [Keyline]; this is a summary. Terms are defined in its [glossary][keyline glossary].

### Principals

Every principal is an Ed25519 verifying key. Individuals, groups, and documents are all principals and differ only in the state attached to the key. A group's or document's identifier is the verifying key of a fresh key pair: it signs the subject's root edges, which name its creators as `Admin`, and is then discarded. Authority over a subject is therefore verifiable from its identifier alone.

### Certificates

There are two kinds, both signed by their issuer and content-addressed:

- A _delegation_: _issuer_ grants _audience_ `power` over _subject_. It names no proof: whether it conveys anything is evaluated from the whole set. A delegation re-issued after a revocation cites that revocation (`citation`), so it gets a fresh digest.
- A _revocation_: _issuer_ withdraws one delegation, named by digest. It may record a watermark of content heads per document (`retain`), for the content layer.

The certificate set is grow-only and merges by set union: a state-based CRDT. A revocation is a new fact about an old certificate, not a deletion.

### Power Levels

```
Relay < Read < Edit < Admin
```

`Relay`, `Read`, and `Edit` are _data_ levels: what may travel along the edge. `Admin` is the only level that acts on the graph itself. The [glossary](./glossary.md#authority) lists what each level permits.

### Evaluation

Authority is reachability. A principal holds power _L_ over subject _S_ if a route of live delegations leads from _S_ to it. Along a route, power is the minimum of each hop; across routes, the maximum. A delegation is live while its issuer has standing over its subject: it dies when the issuer loses standing, and revives if the issuer regains it.

Groups may be members of groups, and the graph MAY contain cycles. Evaluation is a fixed point over the graph, not a chain walk, so cycles are harmless. See Keyline's [Computation][keyline computation].

### Revocation

- _Coverage._ A revocation by a delegation's issuer or audience breaks it on every route. A revocation by anyone else breaks it only on routes through the revoker's _admin reach_: the nodes it ever held `Admin` over, computed with every revocation ignored, so reach only grows. A revocation that reaches nothing is inert, not invalid.
- _No seniority rule._ An edge above your admin reach never routes through it, so you cannot revoke the branch you stand on.
- _Concurrent revocations._ Both stand ([permanence][keyline permanence]). Peers who revoke each other are resolved by rotating the role, not by a tiebreak.
- _Cascades._ Revoking a delegation implicitly ends everything that depended on its audience's standing, without enumerating it.
- _Retention._ Revoked certificates are kept: later certificates may depend on them, and a re-grant cites them.

### Encryption

The capability graph determines membership of a document's BeeKEM tree: every individual with `Read` or better is a leaf; one with only `Relay` is not. A change in a document's readers drives the tree's adds and removes, each citing the certificates of the document's closure that its history does not already cite. A `Relay`-only sync server can evaluate the graph without holding a decryption key. Certificate capabilities alone cannot support this, because the verifier does not hold a complete view of membership.

## Properties

- _Convergence._ The same certificate set gives the same authority on every replica, in any delivery order.
- _Offline operation._ Granting, revoking, and exercising authority are signed statements and need no connectivity.
- _Self-certification._ A subject's authority is verifiable from its identifier alone.
- _Least authority._ Delegation is attenuating and always permitted.
- _Bounded metadata._ Authorization state is linear in the number of certificates.
- _Revocations never judge each other._ Coverage is computed with every revocation ignored, so no delivery order undoes an applied revocation.

## Limitations

- _No delegator-independence._ If your standing ends, everything you delegated goes with it. When that is not wanted, the revoker can re-issue the removed member's delegations (_adoption_).
- _Membership is visible to relays._ A `Relay` must see the graph to evaluate it.
- _Causal, not temporal._ A genuinely old operation arriving late is indistinguishable from a back-dated one; see the [threat model](./threat_model.md#t5-back-dating).
- _Mutual destruction._ Peers holding `Admin` over the same node can revoke each other, and both revocations stand. Recovery is rotating the role.

## FAQ

### Is this SPKI with a revocation list?

No. In SPKI the invoker chooses which chain to present and the verifier checks only that chain. In concap the verifier holds the whole graph and computes reachability; the invoker presents only a signature. A revocation anywhere in the graph therefore affects authority everywhere it is relevant, without re-issuing certificates.

### Is this ocap over a CRDT?

Closer, but ocap has no third-party revocation and no administrator. Concap adds `Admin` and revocation scoped by admin reach, so that group governance is expressible.

### Why not delete revoked certificates?

A revocation names a delegation by digest, and a re-grant cites a revocation, so both must remain to be evaluated. The content they authorized also remains: an op-based CRDT cannot skip an operation.

### Can sub-delegation be restricted?

No. Forbidding delegation leads users to share secret keys instead. Attenuate: delegate the narrowest level that does the job.

<!-- External Links -->
[BCP 14]: https://datatracker.ietf.org/doc/bcp14/
[Keyline]: ./keyline/README.md
[keyline computation]: ./keyline/README.md#computation
[keyline glossary]: ./keyline/README.md#glossary
[keyline permanence]: ./keyline/README.md#permanence
[PoLA]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
[SPKI]: https://datatracker.ietf.org/doc/html/rfc2693
[UCAN]: https://github.com/ucan-wg/spec
[ocap]: https://en.wikipedia.org/wiki/Object-capability_model
