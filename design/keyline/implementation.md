# The `keyline` Crate

This document explains the Rust crate that implements the [Keyline model][keyline]. The model document says what authority _is_; this one says what the code exposes, what it assumes, and what it leaves to the layer above. The contract a backend is checked against is executable: the `Keyline` trait and the [conformance suite](#conformance-suite).

Three things share a name. _Keyline_ is the design, `keyline` is the crate, and `Keyline` is the trait.

## Scope

`keyline` is a flat namespace of Ed25519 verifying keys and a set of signed certificates over them. It answers one family of questions: given this set, what power does key _A_ hold over key _S_, and which certificates are live.

| `keyline` knows                    | `keyline` does not know                        |
|------------------------------------|------------------------------------------------|
| `Id` (a verifying key)             | prekeys, `ShareKey`, any X25519 material       |
| `Delegation`, `Revocation`         | BeeKEM, CGKA operations, key rotation          |
| `Power`                            | the difference between a document and a group  |
| the certificate set and its digest | content references, `after_content`, causality |
| how to evaluate the set            | how certificates travel or are stored          |

A revocation can carry content-layer data (`retain`, below), but only as an opaque, canonically encoded value that evaluation never reads.

The crate sits beside `beekem`: both are engines over untyped keys, and neither is meant to be exposed to users. The plan is for `keyhive_core` to keep its `Individual` / `Group` / `Document` handles and its public API, and to convert IDs at the boundary when a handle needs a membership or reachability answer, the same way `keyhive_core::cgka::Cgka` wraps `beekem::Cgka`. The typed handles are the [Ghosts of Departed Proofs][gdp] witnesses; `keyline` is the untyped thing they are proofs about. See [Integration Sketch](#integration-sketch).

## Types

Field names follow one rule. Participants and references are nouns: `issuer`, `audience`, `subject`, `power`, `citation`. A revocation is a signed directive, so its directives are imperative verbs: `revoke` this delegation, `retain` these watermarks. Read aloud, a revocation says "Alice: revoke `#d1`, retain `{doc: heads}`".

### `Id`

A newtype over the 32-byte compressed form of an `ed25519_dalek::VerifyingKey`. Every principal, role, document, and group is an `Id`. `keyline` attaches no meaning to which is which.

`Id::from_bytes` accepts only the canonical encoding of a curve point outside the small-order subgroup. A non-canonical encoding would give one key two `Id`s, and a small-order key verifies forged signatures. `InvalidId` says which check failed.

`keyhive_core` has `Identifier` for the same thing; `keyline` defines its own, to be converted at the boundary as `beekem::MemberId` is. Shared types are slated for a `keyhive_types` crate; `TODO(keyhive_types)` marks the sites.

### `Power`

```rust
pub enum Power { Relay, Read, Edit, Admin }
```

Totally ordered, `Relay < Read < Edit < Admin`. Attenuation along a route is `min`; combination across routes is `max`. The type belongs here rather than in `keyhive_core` because the ordering is part of the graph semantics, not of the API layer.

Order and encoding are separate. The lattice is `Power::rank()`; the wire tag is the ASCII initial (`L`, `R`, `E`, `A`), one byte. Neither is derived from the other: `Admin` is the top of the order and the lowest of the four bytes, which a unit test pins. This keeps the level set extensible. A level added later takes any free byte and sits wherever its rank puts it, so no existing certificate's bytes change and no digest moves. With consecutive integer tags, inserting a level would renumber `Admin` and invalidate every `revoke` and `citation` pointer in every stored set.

### `Delegation`

```rust
pub struct Delegation {
    pub issuer:   Id,
    pub audience: Id,
    pub subject:  Id,
    pub power:    Power,
    pub citation: Option<Digest<RevocationId>>,
}
```

`RevocationId` is an uninhabited marker. `Revocation` is generic over its watermark type (below), and naming it as `Digest<Revocation<W>>` would make `Delegation` generic over a type it never uses.

| Field      | Meaning                                                                                                                             |
|------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `issuer`   | Signer. The edge rides this key's standing over `subject`.                                                                          |
| `audience` | Receives `min(power, issuer's effective power over subject)`.                                                                       |
| `subject`  | Scope. `issuer == subject` is a root edge. A role key as `subject` is membership in that role.                                      |
| `power`    | Requested level; clamped, never raised.                                                                                             |
| `citation` | The revocation being re-issued past. Gives a delegation identical to a revoked one a fresh digest. Evaluation ignores it. Absent means first issuance. |

A delegation is the Granovetter introduction from object capabilities; the [model document](README.md#intuition--lineage) draws it. One difference matters for the rules: anyone can name anyone as `audience`, and the audience never consents. That is why revocation by the audience exists, and why the [gift-cert attack](evaluation-notes.md#single-queries-and-the-gift-cert-attack) is possible.

Anyone may issue a delegation over any subject. The issuer's effective power over `subject` clamps the result; issuing needs no Admin.

Admin matters for revocation, in two tiers. You can always revoke a delegation you issued: revocation by the issuer needs no standing. Holding Admin over a node lets you act as that node for revocation: your revocations cover anything on routes through it, all the way down. "Act as" is revocation-side only. Admin over `N` does not let you sign as `N`; you delegate authority _over_ `N` by issuing `{issuer: you, subject: N, …}`, clamped by your own level.

`citation` names a revocation rather than using a random nonce, so that an accidental duplicate issuance is one certificate, not two; see [alternatives](alternatives.md#a-random-nonce-instead-of-citation). It names the revocation, not the revoked delegation; see [The `citation` Field](README.md#the-citation-field).

### `Revocation`

```rust
pub struct Revocation<W> {
    pub issuer: Id,
    pub revoke: Digest<Delegation>,
    pub retain: BTreeMap<Id, W>,
}
```

| Field    | Meaning                                                                                          |
|----------|--------------------------------------------------------------------------------------------------|
| `issuer` | Signer. Its admin reach scopes the effect.                                                       |
| `revoke` | The delegation being withdrawn, by payload digest.                                               |
| `retain` | Per-subject retention watermarks for the content layer. Evaluation ignores it. Empty by default. |

The type of `revoke` makes revoking a revocation unwritable. There is no `subject`: the effect is scoped by the issuer's admin reach, not by the issuer's choice. A `subject` field was considered and rejected because every rotation would moot every standing revocation; see [alternatives](alternatives.md#a-subject-field-on-revocation).

#### `retain`

Revoking a key raises a second question that the authority graph cannot answer: what happens to the content that key already wrote? This is the [whiteout](README.md#open-questions) question. `retain` is where whoever signs the revocation records an answer: a retention watermark per subject, a bound on which of the removed key's content to keep, for example "this writer's ops up to these heads". The layer that materializes content reads it. Evaluation does not, in the same way that it ignores `citation`. Laws pin this (see [Conformance Suite](#conformance-suite)).

`W` is the watermark type, chosen by the consumer. Its only bound is `Encode + Decode`. The field is typed rather than opaque bytes for canonicality: if one watermark had two encodings, one revocation would have two certificates. `W::decode` rejects non-canonical values, and [`Signed::verify`](#signedt-and-verifiedt) re-encodes every payload and compares, which also covers a `W` whose decoder is lax.

The map is incomplete by construction:

- A role gains subjects by late binding, so a subject supplied after the revocation was signed can never appear in it.
- Because of partial visibility, the revocation's issuer may not have seen every subject that already exists.

The policy for a subject that the map does not name therefore belongs to the content layer. An empty map is the extreme case of that same incompleteness. It is not a separate instruction such as "retain nothing".

`retain` is covered by the digest. Two revocations of one delegation with different watermarks are two certificates. Both stand, and they revoke the same delegation. How to combine their watermarks is also a content-layer question.

### `Certificate`

```rust
pub enum Certificate<W> { Delegation(Delegation), Revocation(Revocation<W>) }
```

The unit of insertion and of the set. `W` is fixed for each set as `Keyline::RetentionWatermark`.

### `Encoded<T>`

Bytes that claim to encode a `T`, tagged with the type:

```rust
pub struct Encoded<T> {
    bytes: Vec<u8>,
    _phantom: PhantomData<fn() -> T>,   // covariant; Send + Sync regardless of T
}
```

The type does not check the claim. `Encode::encode` produces canonical bytes from a value; `Encoded::from_bytes_unchecked` wraps whatever a transport received; `Encoded::decode` is the check. Equality, `Hash`, and `Ord` are by bytes, so for bytes that decode canonically, equal bytes mean equal values. It serializes as a byte string behind a `serde` feature.

`Encoded<T>` and the `Encode` / `Decode` traits live in the `keyhive_codec` crate (see [Crates](#crates)).

### `Digest<T>`

`keyhive_crypto::digest::Digest<T>`: BLAKE3, 32 bytes, phantom-typed. `keyline` obtains it as `Digest::of(&Encoded<T>)`, which requires `T: Domain` and hashes the [domain-separated](#domain-separation) bytes. The `std`-gated `Digest::hash` (which needs `bincode`) is not used; its `T: Serialize` bound sits on `hash()` alone.

### Domain Separation

The keys that sign Keyline certificates may also sign in other protocols, such as `keyhive_core`'s serde-encoded payloads. If one byte string were valid in two formats, one signature would be valid in both. So every byte string Keyline signs or hashes is prefixed with a context naming the protocol, its version, and the type, then a NUL byte:

| Type                | Context                  |
|---------------------|--------------------------|
| `Delegation`        | `keyline/v0/delegation`  |
| `Revocation<W>`     | `keyline/v0/revocation`  |
| `Certificate<W>`    | `keyline/v0/certificate` |
| `CertificateSet<W>` | `keyline/v0/set`         |

Contexts contain no NUL, so no prefixed string is a prefix of another. The trait is `keyhive_crypto::domain_separator::Domain`: `Domain::message` builds the prefixed bytes a signature covers, and `Digest::of` hashes exactly those bytes, so a signature and a digest always cover the same input. `v0` is the protocol version. It changes whenever the meaning of signed bytes does, so a certificate from one version never verifies under another. The contexts live together in `keyline/src/domain.rs`, where a test checks that they are distinct.

### `Signed<T>` and `Verified<T>`

```rust
pub struct Signed<T> {
    encoded:   Encoded<T>,
    signature: ed25519_dalek::Signature,   // over T::message(encoded.as_bytes())
}

pub struct Verified<T> {
    payload: T,          // decoded once, canonical form checked
    signed:  Signed<T>,  // retained so the certificate can be forwarded as received
}

impl<T: Domain + Encode + Verifiable> Signed<T> {
    pub fn try_sign(value: &T, key: &SigningKey) -> Result<Self, SignError>;
}

impl<T: Decode + Domain + Encode + Verifiable> Signed<T> {
    pub fn verify(self) -> Result<Verified<T>, VerifyError>;
}
```

There is no issuer field. The payload names its own issuer (`Delegation.issuer`, `Revocation.issuer`), exposed through `keyhive_crypto::verifiable::Verifiable`, and `verify` checks the signature against that key and no other. In order, it:

1. decodes the payload;
2. re-encodes it and requires exactly the received bytes, so a `Verified<T>` is always canonical;
3. runs `verify_strict` over the domain-separated bytes with `payload.verifying_key()`.

A certificate that names one issuer and is signed by another does not verify. Storing the signer separately would be a redundant field that the transport controls, and checking the signature against it instead of the payload would admit exactly that forgery. `try_sign` refuses a key that is not the payload's issuer for the same reason. `verify_strict` rejects the small-order and malleable signatures that plain `verify` accepts; a unit test builds such a forgery and checks that it fails.

`verify` is the only public constructor of `Verified<T>`. The digest is taken from the same bytes the signature covers, so nothing re-encodes a payload to identify it. Two digests exist per delegation: the set is keyed by `Digest<Certificate>` (over the tagged bytes), while `revoke` and `citation` name the payload digest (`Delegation::digest()`, `Revocation::digest()`, over the untagged bytes); both are functions of the same canonical bytes. A crate-private constructor lets `test_utils::cert` build fixtures without paying for signing; one scenario goes through `try_sign` and `verify` so the shortcut cannot hide a discrepancy.

`Signed<T>` equality is by bytes _and_ signature. RFC 8032 signing is deterministic, so one key signing one payload twice yields equal values. A signer that picks its nonce another way produces a different, equally valid signature: a different `Signed<T>` with the same digest. A `Keyline` set is keyed by digest, so it holds such a pair as one certificate; the `second_signature_is_the_same_certificate` scenario pins this.

These two types live in `keyline` (`TODO(keyhive_types)`). `keyhive_crypto`'s serde-based `Signed<T>` is unchanged and remains what `keyhive_core` uses; the codec migration unifies them.

## The `Keyline` Trait

```rust
pub trait Keyline {
    type RetentionWatermark: Encode + Decode;

    fn insert(&mut self, cert: Verified<Certificate<Self::RetentionWatermark>>) -> bool;
    fn contains(&self, cert: &Digest<Certificate<Self::RetentionWatermark>>) -> bool;

    fn effective_power(&self, subject: Id, audience: Id) -> Option<Power>;
    fn members(&self, subject: Id) -> BTreeMap<Id, Power>;
    fn is_live(&self, cert: &Digest<Delegation>) -> bool;
    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<RevocationId>>;
    fn digest(&self) -> Digest<CertificateSet<Self::RetentionWatermark>>;
}
```

| Item                 | Meaning                                                                                                                   |
|----------------------|---------------------------------------------------------------------------------------------------------------------------|
| `RetentionWatermark` | The `retain` watermark type. Evaluation never reads it. A backend that does not care picks `()`.                          |
| `insert`             | Add a certificate. `true` if newly added, as `BTreeSet::insert`. Idempotent. A dedupe signal, not a change signal.        |
| `contains`           | Whether the digest is in the set. Ingest checks this before paying for signature verification.                            |
| `effective_power`    | `audience`'s effective power over `subject`: max over live routes of min along each. `None` if unreachable.               |
| `members`            | Every `Id` other than `subject` itself with a live route to `subject`, with its effective power. The materialized view.   |
| `is_live`            | Whether the named delegation survives evaluation.                                                                         |
| `revocations_naming` | Revocations that name the delegation, covering or not. Explains a silent `citation` collision.                            |
| `digest`             | A digest of the set, usable as a cache key: same digest, same answers. `CertificateSet<W>` is an uninhabited marker.      |

Every method is defined purely in terms of the set. That is what makes the trait a backend contract: an implementation over DBSP, Postgres, or anything else is correct if and only if it gives the same answers as the reference implementation for the same set. The conformance suite (below) is how a backend shows that.

The trait is `&self` for queries and `&mut self` for `insert`. It is synchronous. There is no `FutureForm` parameter: the evaluator does no I/O, and concurrency is the wrapper's concern. A wrapper holds the implementation behind a `RwLock` (or a `Local` equivalent); readers take the read guard and call `&self` methods in parallel, and writers take the write guard briefly.

### Insert

`insert` cannot fail on bad input: the `Verified` witness has already excluded it. It returns whether the certificate was new so that ingest can avoid re-announcing a certificate it already held. It does not say whether any query result changed: a new certificate may be dead on arrival, and a duplicate never changes anything. A caller that must react to membership changes (to drive BeeKEM key rotation) diffs `members(subject)` before and after; an incremental evaluator that reports deltas is a later optimization.

A duplicate is also how a silent `citation` collision shows up: an issuer who re-mints a revoked delegation without `citation` produces the identical certificate, `insert` returns `false`, and `revocations_naming` reports which revocations named it, so the layer above can prompt for a re-issue with `citation` set.

A revocation whose target is not (yet) in the set is stored like any other certificate and contributes nothing until the target arrives; insertion order never matters.

Not yet on the trait: `get(&Digest<Certificate>) -> Option<&Signed<Certificate>>` and iteration over the set. Sync and archiving need them, but their shape depends on how Subduction pulls certificates, and a database-backed implementation may not hold the signed bytes. Decided at integration.

### `MemoryKeyline`

The reference implementation: in-memory, `impl Keyline`, generic over the watermark type `W` with no default. Plain maps of plain data; no `Rc`, no `Cell`, so `Send + Sync` hold without effort. It does no caching: every query recomputes both strata, so cost scales with the replica's whole certificate set rather than with the queried subject. That suits the deployment it is for, an embedded or Wasm replica holding a document's [closure](README.md#what-a-replica-must-hold), and not a relay holding many documents, which wants a backend that materializes the monotone stratum.

It is also not demand-driven. `effective_power(s, a)` materializes `s`'s whole row and indexes into it, so a point query costs what the full view costs. Magic sets would fix that, at the price of the property that makes a bottom-up evaluator safe: forward chaining from the subject never visits a fact it cannot ground, so an attacker's ungrounded structure costs nothing. A demand-driven evaluator must earn that back with the ordering obligation in [evaluation notes §7](evaluation-notes.md#7-threat-model-evaluation-cost-as-a-dos-surface). The reference implementation stays simple; a faster backend is what the trait and the conformance suite are for.

## Evaluation

Evaluation is a pure function of the set. The strata below are the canonical order the model document describes (all delegations, then all revocations, then the check), made executable: stratum 1 replays the proxy network of delegations, stratum 2 applies every revocation to it, and a query is the invocation being checked. The reference implementation is this program executed literally, and any faster backend must agree with it on every set.

```
Stratum 0 — facts
  del(h, issuer, audience, subject, power)   one per delegation, h its digest
  rev(k, h)                                   one per revocation

Stratum 1 — positive pass, blind to revocations
  reaches(n, n, Admin)                                                                     every node grounds itself
  reaches(n, audience, min(l, power)) :- reaches(n, issuer, l), del(_, issuer, audience, n, power)   edge about n
  reaches(s, x, min(l₁, l₂))          :- reaches(s, n, l₁), reaches(n, x, l₂), n ≠ s                membership

  admin_reach(k, n) :- reaches(n, k, Admin)                                                k ever held Admin over n
  admin_reach(k, k)                                                                        own node always counts
  covered(h, n)     :- rev(k, h), admin_reach(k, n)

Stratum 2 — live pass, negation over stratum 1 only
  -- existence: least fixed point
  route(s, s, h)        :- ¬covered(h, s)
  route(s, audience, h) :- route(s, issuer, h), live(h′), del(h′, issuer, audience, s, _), ¬covered(h, audience)
  route(s, x, h)        :- route(s, n, h), route(n, x, h), n ≠ s
  live(h)               :- del(h, issuer, audience, s, _), route(s, issuer, h), ¬rev(audience, h)

  -- level: least fixed point, rising from cap(h) = Relay
  level(s, s, h, Admin)                  :- ¬covered(h, s)
  level(s, audience, h, min(l, cap(h′))) :- level(s, issuer, h, l), live(h′), del(h′, issuer, audience, s, _), ¬covered(h, audience)
  level(s, x, h, min(l₁, l₂))            :- level(s, n, h, l₁), level(n, x, h, l₂), n ≠ s
  cap(h) = min(power, max l . level(s, issuer, h, l))                                      for del(h, issuer, _, s, power)
```

`route(s, x, h)` and `level(s, x, h, l)` are "x is reachable from s, through live edges, without touching any node covered for h"; the exclusion set is what `h` parameterizes. Write `⊥` for a pseudo-certificate that nothing covers: `route(s, x, ⊥)` is plain live reachability and `level(s, x, ⊥, l)` is the plain live level. Then:

- `effective_power(s, a)` is the maximum `l` with `level(s, a, ⊥, l)`; `Some(Admin)` when `a = s`.
- `members(s)` is every `x ≠ s` with `route(s, x, ⊥)`, paired with its `effective_power`.
- `is_live(h)` is `live(h)`.

Notes on the program:

- _`subject` composes._ The third `reaches` rule is what makes `subject: Members` mean membership: whatever `Members` reaches, its members reach too, clamped by both hops. Without it `members(Doc)` would name roles and never humans, and the layer above would have to know which nodes are roles, which the crate boundary forbids. Every node with standing over `s` acts as a role for `s`; the rule does not ask what kind of key `n` is. A "route" is therefore a derivation, not a walk along `issuer → audience` edges: Alice's membership `{issuer: Bob, audience: Alice, subject: Members}` sits on Doc's route to Alice because Bob has standing over `Members`, not because Bob is the previous node.
- _Admin reach is composed._ `admin_reach(k, n)` is Admin standing over `n` however derived. Bob, an Admin member of `Owners`, has `Owners` in his reach and, because `Owners` is Admin over `Doc`, `Doc` as well, and every role `Owners` administers. Seniors adjudicate inside junior roles without an explicit `subject: Junior` delegation. The price is that the apex of an Admin-rooted document is in the reach of everyone who ever held Admin in the apex role, so any of them can revoke the root edge and brick the document, permanently. That is accepted; see [Griefing](README.md#griefing). A last-hop ("direct") definition was rejected; see [alternatives](alternatives.md#direct-last-hop-admin-reach).
- _Admin over a document buys nothing but kill power._ Delegation is open to anyone, clamped by attenuation; membership management is Admin over the _role_. The only thing Admin over `Doc` itself gates is reach over `Doc`'s routes. Creation therefore chooses: root at `Admin` and every apex admin can brick the document; root at `Edit` and nobody ever holds Admin over `Doc`, so its root edge is irrevocable by anyone (the subject key being destroyed) and re-rooting with a retained key escapes old admins' reach. See [patterns, Rooting Level](patterns.md#rooting-level).
- _Stratum 1 is global; stratum 2 is rooted._ `admin_reach(k, n)` must see every subject, because Bob's Admin over `Members` is what lets him revoke delegations on `Doc`'s routes. Stratum 2 is grounded at one subject and ranges over every subject that subject reaches; "per-subject" means rooted at one subject, not confined to one subject's certificates.
- _The route for `h` is rooted at `subject(h)`, not at the querying subject._ `route(subject, issuer, h)` lives entirely in `h`'s own subject's graph. How some other subject `S` reaches `subject(h)` is irrelevant to whether `h` is live. Supplying a role into `S` (a `{issuer: Dan, audience: Members, subject: S}` edge) gives Dan power over that supply edge (revoke it and every member loses `S` at once) but none over `Members`' roster, which never routes through him. To revoke delegations inside `Members`, `Members` must be in your reach. This holds even when Dan reaches `S` at Admin through some other role: `S` is in his reach, `Members` is not. (Checking the hop's coverage against the `S`-rooted derivation instead was considered and rejected: it would let anyone who feeds authority into a role revoke individual roster entries of that role.)
- _Both passes are the same rule._ `reaches` is `level(·, ·, ⊥, ·)` with every edge live and every cap equal to its `power`. The reference implementation is one bounded widest-path search over the composed graph, parameterized by an exclusion set; stratum 1 runs it with the empty set.
- _Both fixed points are least fixed points._ Existence (`route`, `live`) assumes a revisited node is dead, so ungrounded cycles cannot certify themselves. Caps rise from `Relay`: a live covered edge conveys at least `Relay`, because liveness found a grounded derivation that avoids its covered set, and each round raises it to `min(power, issuer's level on that derivation)`. Starting from the bottom means a cap is only as high as some grounded derivation supports. Two covered edges on each other's avoiding derivation therefore cannot lift each other, which a greatest fixed point descending from `power` would allow (the `mutually_covered_edges_cannot_lift_each_other` scenario). The ascent is finite (four levels, finitely many edges). The two are separable because existence never reads a cap.
- _Covered edges are clamped, not just gated._ A covered edge conveys at most the level its issuer holds _on a derivation that avoids the covered nodes_, not the issuer's global level. Example: Dan is an Admin of role `Mods`, which is supplied into `Doc` at Edit (so `Doc` is not in Dan's reach); Eve is a Mod (Edit over `Doc` via `Mods`) and also holds a direct Read over `Doc` from `Owners`; Eve delegates Admin over `Doc` to Frank (`h`); Dan revokes `h`. `admin_reach(Dan) = {Dan, Mods}`, so `h` is dead on the derivation through `Mods` and live on the one through `Owners`. Frank gets `min(Read, Admin) = Read`: Eve's standing as a Mod does not flow through the edge Dan revoked, while her independent Read does. Gating alone (existence via the avoiding derivation, level from Eve's global Edit) would hand Frank the very authority the revocation was about. Clamping yields the same live set and levels `≤` the gated reading everywhere: ambiguity resolves toward less authority.
- _Clamping is a relaxation of route-consistency._ The exact reading (a single derivation in which every edge's own covered set is avoided by that derivation's prefix) is a path-with-forbidden-pairs problem and is not known to be polynomial, and a reference semantics an adversary can make exponential with crafted certificates is a denial-of-service vector. `cap(h)` avoids `h`'s covered set but takes the edges it traverses as already-live facts, each justified by its own derivation. See [alternatives, route-consistent levels](alternatives.md#route-consistent-levels).
- _Negation appears once, over fully computed lower strata._ Revocations target delegations, never other revocations, so `covered` never depends on `live`. This is what makes the result independent of insertion order.
- _Coverage that touches no route is dropped._ A route for `h` transits only nodes with standing over `subject(h)`, so a covered node without such standing changes nothing, and `h` behaves as if uncovered. `MemoryKeyline` drops those nodes before grouping, and drops `h` from coverage when none remain. A revocation by a key with no reach over its target's subject therefore costs storage only. Both oracles keep the unpruned coverage, so agreement checks that pruning changes no answer.
- _Aggregation is a bucketed BFS._ Four levels, so the widest-path pass over un-revoked certificates is linear. Covered certificates are grouped by exclusion set: `covered(h, ·)` depends only on who revoked `h`, so one key's revocation spree is one group. Each group pays one route search per round of the live fixpoint and one per round of the cap ascent. Without the grouping a `k`-revocation spree by one key would cost `k` searches per round instead of one.
- _The route ends at `issuer`; the audience answers only to its own signature._ Admin-reach coverage applies to the nodes a derivation transits, and the derivation for `h` runs from `subject` to `issuer`. Revocation by the issuer (`k = issuer`) is therefore total with no special case: `issuer` is in its own admin reach and on its own route. Revocation by the audience (`k = audience`) is the one explicit clause, `¬rev(audience, h)`: the audience's _own_ revocation kills what names it, but nobody's _reach_ covers a certificate through its `audience`. Putting `audience` on the route would give every admin of a role revocation power over every delegation _to_ that role: a `Members` admin could revoke `Doc → Members` supply edges they never issued and hold no reach over on `Doc`'s side.
- _Ungrounded certificates cost storage only._ Evaluation forward-chains from root edges and never visits them.
- _Root edges are not special-cased._ `reaches(n, n, Admin)` puts every node at Admin over itself, so `{issuer: Doc, audience: Owners, subject: Doc}` is an ordinary edge whose issuer happens to reach the subject. The evaluator never tests `issuer == subject`.

The model document's [Computation] section explains why the shortcut "delete revoked edges, then compute reachability" gives order-dependent results.

### The Same Program in Threshold Form

The program above carries levels as values and computes caps as a second fixed point. The following is the same semantics as a single stratified Datalog¬ program with no aggregation: levels are decomposed into thresholds (a fact at `L` means "standing `≥ L`"; `Power` is a finite total order, so four boolean passes recover the exact level), and each covered certificate's exclusion set is a _context_ the search runs in. It is the form that drops directly into a Datalog engine, or into SQL as one statement per fixpoint round. The conformance suite's second oracle, `oracle::threshold`, transcribes it rule for rule. The AND/OR reading of the graph, the complexity argument, and the SQL and DBSP hosting options are worked out in [evaluation notes](evaluation-notes.md).

```prolog
% stratum 0 — facts
%   delegation(C, Iss, Aud, Sub, Pow)   revocation(R, Iss, C)   node(N)   level(L)   le(L1, L2)

% stratum 1 — positive pass. The two recursive premises are rules 2 and 3 folded together.
reaches(L, S, S)   :- node(S), level(L).
reaches(L, S, Aud) :- delegation(_, Iss, Aud, Sub, Pow), le(L, Pow),
                      reaches(L, S, Sub), reaches(L, Sub, Iss).

% stratum 1b — reach and coverage; no recursion
admin_reach(K, N)  :- reaches(admin, N, K).
covered_total(C)   :- revocation(_, I, C), delegation(C, I, _, _, _).      % revocation by the issuer
covered_total(C)   :- revocation(_, I, C), delegation(C, _, I, _, _).      % revocation by the audience
covered(C, N)      :- revocation(_, I, C), delegation(C, Di, Da, _, _),
                      I != Di, I != Da, admin_reach(I, N).

% contexts: the empty one, plus one per covered certificate
ctx(empty).            excl(empty, _) is false.
ctx(C)             :- covered(C, _).
excl(C, N)         :- covered(C, N).
own_ctx(C, C)      :- covered(C, _).
own_ctx(C, empty)  :- delegation(C, _, _, _, _), not covered(C, _).

% stratum 2 — live pass in every context; negation only over strata 0–1b
live(X, L, S, S)   :- ctx(X), node(S), level(L), not excl(X, S).
live(X, L, S, Aud) :- delegation(C, Iss, Aud, Sub, Pow), le(L, Pow), ctx(X),
                      live(X, L, S, Sub), live(X, L, Sub, Iss),          % feeds, in the query's context
                      own_ctx(C, O),      live(O, L, Sub, Iss),          % the hop, in its own context, rooted at its own subject
                      not covered_total(C), not excl(X, Iss), not excl(O, Iss), not excl(X, Aud).

% stratum 3 — read off the maximum threshold
effective(S, N, L) :- live(empty, L, S, N), not shadowed(S, N, L).
shadowed(S, N, L)  :- live(empty, L2, S, N), le(L, L2), L != L2.
```

`is_live(C)` is `live(O, _, Sub, Iss)` for `own_ctx(C, O)` and `delegation(C, Iss, _, Sub, _)`, together with `not covered_total(C)`. Contexts whose exclusion sets coincide (one key's revocation spree) may share a single context, as `MemoryKeyline` does. Sharing never changes the answers, and it is what keeps a one-key revocation spree from costing a search per revoked certificate ([evaluation notes, §7](evaluation-notes.md#7-threat-model-evaluation-cost-as-a-dos-surface)).

How it corresponds to the value form:

- `reaches(L, S, Aud) :- … reaches(L, S, Sub), reaches(L, Sub, Iss)` is rules 2 and 3 in one: with `Sub = S` the first premise is the axiom and the rule is "edge about `S`"; with `Sub ≠ S` it is membership composition.
- `live(O, L, Sub, Iss)` in the hop's own context, rooted at `Sub`, is `route(subject, issuer, h)` and `cap(h)` at once: existence at some `L` is liveness, the largest such `L` is the cap. Rooting it at `Sub` rather than at the querying `S` is the daisy-chain rule.
- `not excl(X, Aud)` is the value form's `¬covered(h, audience)`: an excluded node is never reached in its context.
- Thresholds are monotone: "issuer holds `≥ L` avoiding `covered(h)`" is a positive fact, and every stratum-2 rule is positive in `live`, so the whole stratum is a least fixed point, like the value form's caps rising from `Relay`. Both are grounded at a subject: a cap can never raise the level at its own issuer, and a cycle of covered edges cannot lift itself.

One property of this program matters for every backend: the membership rule has _two_ premises in the relation being defined. That is non-linear recursion, and SQL's `WITH RECURSIVE` (SQLite, PostgreSQL) admits exactly one reference to the relation under construction, so the fixpoint cannot be a single recursive CTE. It is one plain statement per round plus a loop that stops when a round adds nothing. Stratification and the negation are the easy part (chained CTEs, anti-joins); the loop is the only non-declarative ingredient. This is why the `Keyline` trait is synchronous and `MemoryKeyline` has a driver loop, and why a Datalog engine (`ascent`, Soufflé, DBSP) hosts the program natively where SQL needs a stored procedure.

Two things this does _not_ say. It is not a cost claim: evaluation is polynomial with small constants, and a document with 180 members answers in about a millisecond. And it is not caused by revocations: the difficulty is entirely in stratum 1, where `subject`-as-scope means the edges usable in a subject's graph are themselves derived facts. Coverage and replay are a join and an anti-join over a finished relation. A Keyline with no revocations has the same shape.

Whether the rule could be _rewritten_ into linear form is a separate question, and one this document does not settle. Non-linear phrasing alone proves nothing: textbook transitive closure is usually written non-linearly and linearizes trivially. The argument that this one does not is inherited: the membership rule is RT₀'s linking inclusion, and SPKI/SDSI resolution maps onto pushdown reachability, which is P-complete. That is a citation, not a proof about this rule set. See [evaluation notes §4](evaluation-notes.md#4-why-it-is-not-one-query).

## Encoding

```rust
// keyhive_codec
pub trait Encode {
    fn encode_into(&self, out: &mut Vec<u8>);
    fn encode(&self) -> Encoded<Self> where Self: Sized;
}

pub trait Decode: Sized {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;
}
```

Every implementation satisfies two laws:

1. Round trip: `decode(encode(x)) == x`.
2. Canonicality: `encode(decode(b)) == b` for every `b` that `decode` accepts.

The second is a security requirement. Certificates travel as `Encoded<T>`, and the receiver hashes the bytes it received. If the codec admitted two byte forms for one value, a peer could ship the same delegation twice with two digests, producing two live certificates for one delegation of which a revocation covers only one: the [nonce failure mode](alternatives.md#a-random-nonce-instead-of-citation) by another route. Each `decode` therefore rejects non-canonical input, and `Signed::verify` re-encodes and compares as a backstop (`DecodeError::NonCanonical`). An absent `citation` has exactly one encoding, distinct from every present value. Fuzz harnesses mutate valid encodings (flip, insert, remove, truncate) and check that whatever still decodes re-encodes to the same bytes.

`keyline` implements the traits for its own types with a fixed-width layout:

```
Certificate: kind:u8 ‖ payload
Delegation:  issuer ‖ audience ‖ subject ‖ power:u8 ‖ citation_tag:u8 ‖ citation?    power is one of L R E A
Revocation:  issuer ‖ revoke ‖ count:u32 ‖ entry*
  entry:     subject ‖ len:u32 ‖ W
```

In `Delegation`, `citation_tag` is `0` with no following bytes when `citation` is absent, and `1` followed by 32 bytes when present. `power` is one of the four ASCII tags. Fixed-width layouts are canonical by construction, so `decode` only has to check length, tag membership, and that each `Id` is a valid point. `0x00` is not a valid `power`, so a zeroed buffer fails to decode.

`retain` is the only variable-length field, so it is the only place where canonicality is not free. `decode` enforces it with four rules:

1. Entries ascend by subject with no repeats, so a map has one ordering (`DecodeError::UnsortedKeys`).
2. Counts and lengths are fixed-width big-endian `u32`, so a number has one encoding.
3. The input must be consumed exactly, so there is no slack to hide bytes in.
4. `W::decode` rejects a non-canonical value.

Offsets are computed with checked arithmetic, because a declared length near `u32::MAX` overflows `usize` on 32-bit targets. An empty `retain` costs four bytes.

This layout is a placeholder for the bespoke codec. When that lands, these `Encode` / `Decode` impls are replaced (possibly by derive macros in `keyhive_codec`), every digest changes, and the domain contexts move to the next protocol version. `Encoded<T>`, `Signed<T>`, `Verified<T>`, and the `Keyline` trait do not change. The placeholder exists so that the crate is `no_std` from the start (no `bincode`) and so that the evaluator and its tests have stable digests to build against.

## Crates

```
keyhive_codec        Encode, Decode, Encoded<T>, DecodeError. Depends on thiserror; serde optional.
      ▲
keyhive_crypto       Digest<T>, Digest::of(&Encoded<T>), Domain. Its serde-based Signed<T> is untouched.
      ▲
keyline              Id, Power, Delegation, Revocation, Certificate, Signed/Verified over Encoded,
                     the Keyline trait, MemoryKeyline, conformance suite.
      ▲
keyhive_core         (planned) consumes keyline; never sees raw bytes.
```

`keyhive_codec` holds only the traits and `Encoded<T>` because the dependency direction is only right if it sits at the bottom: `beekem` will implement the same traits when it migrates, and `beekem → keyline` would be wrong. It contains no BLAKE3; hashing an `Encoded<T>` is `keyhive_crypto`'s job.

## Crate Layout and Features

```
keyline/
  src/
    lib.rs           //! model summary, naming convention, links to design/keyline/
    id.rs            Id, InvalidId
    power.rs         Power
    delegation.rs    Delegation
    revocation.rs    Revocation, RevocationId
    certificate.rs   Certificate; Encode/Decode impls for all three
    domain.rs        Domain contexts for every signed or hashed type
    signed.rs        Signed<T>, Verified<T>
    contract.rs      the Keyline trait, CertificateSet, set_digest
    memory.rs        MemoryKeyline: storage, stratified evaluator, Keyline impl
    collections.rs   (private) Map/Set aliases: HashMap with std, BTreeMap without
    test_utils.rs    deterministic ids, unsigned and signed Verified fixtures, fuzz helpers
    test_utils/
      conformance.rs                  the cast, helpers, keyline_conformance! macro
      conformance/gen.rs              CertSet generator
      conformance/laws.rs             bolero properties
      conformance/oracle.rs           shared oracle types
      conformance/oracle/naive.rs     value-form oracle
      conformance/oracle/threshold.rs threshold-form oracle
      conformance/scenarios.rs        named cases, generic over K: Keyline
```

- `#![no_std]` + `extern crate alloc`; `#![forbid(unsafe_code)]`. `keyline`, `keyhive_codec` and `keyhive_crypto` build for `wasm32-unknown-unknown` with `--no-default-features` (checked by `ci-no-std`). Targets without atomic compare-and-swap (e.g. `thumbv6m-none-eabi`) fail in `tracing-core`. `keyline` uses three items from `keyhive_crypto`: `Digest<T>`, `Domain`, and `Verifiable`. Moving them down to `keyhive_codec`, or to a crate beneath it, would be the cleaner layering, for the same reason that put `Encode`/`Decode` at the bottom.
- Depends on `keyhive_codec` (traits, `Encoded`), `keyhive_crypto` (`Digest`, `Domain`, `Verifiable`), `ed25519-dalek` (`VerifyingKey`, `Signature`), `tracing`, and `thiserror` 2 (`no_std`-capable; pinned locally until the workspace moves off 1). Optional: `serde`, `arbitrary`, and, for `test_utils`, `bolero` and `sha2`.
- `std` feature (default on): `HashMap`/`HashSet` for the evaluator's maps, plus the `std` features of `tracing` and `thiserror`. Without it, `BTreeMap`/`BTreeSet`.
- `test_utils` feature: the conformance suite, the fixtures, and `bolero`/`arbitrary`. Implies `arbitrary`, which implies `std` (`derive(Arbitrary)` expands to a `thread_local!`). Also implies `serde`, so the serde round-trip tests run wherever the full suite does (`ci-test`, mutation testing), and `ed25519-dalek/hazmat`, for the fixture that signs with a non-standard nonce.
- Testing is split by feature, and no configuration silently skips the evaluator. `cargo test -p keyline` runs the unit tests and every conformance _scenario_ (plain generic functions needing nothing beyond the crate); `--no-default-features` runs the same set against the `no_std` build, since the crate never links `std` and only the harness does; `--features test_utils` adds the `bolero` laws and property tests, which need `Arbitrary` and so `std`. `nix run .#ci-test` (menu: `test:host`) runs the whole workspace with `test_utils`, as hosted CI does; `ci-no-std` runs the `no_std` set.
- `serde` feature: derives on the public types for archives. Not the wire format.
- No `parallel` feature yet. If one comes, it is native-only (`rayon`); Wasm stays single-threaded because `wasm-bindgen-rayon` needs `SharedArrayBuffer`, COOP/COEP headers, and a worker pool. The evaluator is written so the independent units (admin reach per issuer, route search per covered certificate) are plain iterators.

The crate follows the workspace's `beekem` conventions: `foo.rs` + `foo/`, manual impls instead of `derivative`, `tracing` in every configuration with its `std` feature behind ours. Library types take no defaulted type parameters: a backend states its watermark type.

Instrumentation: `insert` logs each certificate at `debug` (kind, endpoints, whether the revocation target is known, duplicates); `evaluate` is a `debug` span reporting set size, contexts, live/dead counts and clamped edges; the two fixpoint loops emit a `trace` line per round; queries are `trace` spans. `Signed::verify` logs failures at `debug` with the digest. Nothing is logged at `info` or above: the crate has no events a deployment must see.

## Conformance Suite

Every backend runs the same tests against `impl Keyline`. The suite is exported behind `test_utils` as plain functions generic over `K: Keyline + Default`, and one macro call writes a `#[test]` for each:

```rust
mod conformance {
    keyline::keyline_conformance!(my_crate::MyKeyline<()>);
}
```

_Generator._ `test_utils::conformance::gen::CertSet` draws from a pool of eight deterministic identities:

- a root edge per subject (one to three), at Admin or Edit;
- up to ten free-form delegations over any node in the pool, so some land on roles and some are ungrounded;
- at most one planted shape that random wiring rarely produces: the clamping shape (a role supplied into a subject, an admin of it, a member of it with an independent delegation over the subject, that member's delegation to a third party, and the admin's revocation of it); two clamps chained so that each covered edge lies on the other's avoiding derivation; or a role chain three deep;
- occasionally a revocation of a delegation that is not in the set;
- up to four revocations naming delegations already present, a third of them by the target's issuer or audience, each carrying zero to two retention watermarks;
- up to two re-issues past a revocation, and sometimes a revocation of a re-issue.

Random 32-byte keys would give nothing but ungrounded edges.

_Oracles._ Two transcriptions of the program, sharing no code with each other or with any backend. `oracle::naive` runs the value form above as Jacobi iteration over tuple maps, with caps as a second fixed point. `oracle::threshold` runs the threshold form rule for rule, with one context per covered certificate and no cap fixed point. Both keep only `(issuer, revoke)` from each revocation, so neither can read a watermark. A backend must agree with both, and their agreement with each other checks that the two forms in this document say the same thing. With the chained-clamp shape in the generator, a backend whose caps are a greatest fixed point fails the threshold law within CI's iteration budget.

_Laws_ (`bolero`, over generated sets):

- Oracle agreement: `members` over the pool and `is_live` for every delegation agree with `oracle::naive` (without revocations, and with) and with `oracle::threshold`.
- Order independence: a generated permutation and the reversed order both give the same `digest`, the same levels over the pool, the same live set, and the same `members`.
- Idempotence: re-inserting every certificate returns `false` and changes nothing.
- Revocations only deny: for each revocation in a set, the set without it has levels `≥` everywhere and a live set `⊇`.
- Revocation by a party is total: a revocation signed by its target's issuer or audience kills the target.
- `retain` is inert: emptying every `retain` map changes no answer.
- Digest identifies the set: permutation-invariant; dropping any non-duplicated certificate changes it.
- Query consistency: `effective_power(s, s) = Some(Admin)` for every `s`; `members(s)` is `effective_power(s, ·)` minus `s`; `contains` holds for every inserted certificate and fails for one left out; `revocations_naming(h)` is exactly the revocations in the set with `revoke = h`.

Every law builds its backend through a helper that checks each `insert` reports whether its certificate was new. At `W = ()` a `retain` entry carries a subject but no watermark bytes, so `MemoryKeyline` re-runs both oracles, the inert-`retain` law, and digest identity with `W = Vec<u8>`.

_Scenarios._ Named cases derived from the [edge-cases] findings and the model document:

- rotation escapes a frozen admin reach while the revocations made in office stand;
- concurrent mutual revocation leaves both standing, and in an Edit-rooted document an apex duel still kills both memberships signed at creation;
- ex-admin revocations cover only the frozen admin reach;
- an apex admin of an Admin-rooted document can revoke the root edge, while an Edit-rooted document's root edge is irrevocable;
- revocation by the issuer and revocation by the audience are total; a non-admin's revocation is confined to their own node;
- `citation` re-issue heals, reviving everything downstream under its original digest;
- membership carries whatever the role reaches, including documents added later;
- a senior role's admin revokes delegations inside a junior role without an explicit delegation;
- supplying a role into a document gives power over the supply edge and none over the roster;
- a covered edge conveys only what its issuer holds on the avoiding derivation (the `Mods` example), and two covered edges on each other's avoiding derivation cannot lift each other's level;
- the gift-cert attack from the [evaluation notes](evaluation-notes.md#gift-cert-scenario): an unconsented delegation into an attacker's ladder, which removing the attacker takes out of the document, which a same-key re-add revives and a fresh key does not, and which the victim severs by revoking it as audience;
- a second valid signature over a certificate already present is the same certificate;
- two revocations differing only in `retain` are two certificates with the same effect.

_Negative._ A revocation naming an unknown digest is new and changes no answer. A duplicate returns `false` from `insert`, and `revocations_naming` reports what named it.

## Integration Sketch

Not implemented here; recorded so the crate's shape is checked against its one planned consumer.

- `keyhive_core` holds `Arc<RwLock<MemoryKeyline<W>>>` (or `Rc<RefCell<_>>` for `Local`) on `Keyhive`, with `W` the watermark type it picks.
- `Group::members()`, `Document::members()`, `Membered::transitive_members()` become `keyline.members(id)` with ID conversion.
- `add_member` builds a `Delegation`, signs it with the active signer, `verify()`s it (cheap, and it exercises the same path as ingest), and `insert`s.
- `revoke_member` builds one `Revocation` per delegation to revoke. Whether to also revoke everything the member issued (explicit removal) is a `keyhive_core` policy, per the model document's removal tiers.
- Events for sync carry `Verified<Certificate>`; ingest is `insert`.
- BeeKEM membership is `members(doc).filter(|(_, a)| a >= Read)`. The coupling of revocation to key rotation remains an open design item in the model document.
- `keyhive_core::Delegation`'s `proof`, `after_revocations`, and `after_content` fields have no counterpart, and `delegate: Agent` becomes `audience: Id`. This is a wire-format break, absorbed by the pending API break.

## Deferred

- Whiteout: `retain` gives the revocation's issuer a place to record an answer, but deciding what a watermark _means_ is still a content-layer question. That includes the type `keyhive_core` picks for `W`, the policy for subjects the map does not name, and how to combine concurrent revocations of one delegation.
- The `Relay`/BeeKEM rotation coupling: an integration question.
- The bespoke codec.
- Incremental evaluation and memoization: only once the conformance suite pins semantics.
- A second backend and a `keyline` / `keyline_memory` crate split: only if a second backend appears.

<!-- Links -->

[Computation]: README.md#computation
[edge-cases]: edge-cases.md
[gdp]: https://kataskeue.com/gdp.pdf
[keyline]: README.md
