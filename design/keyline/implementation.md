| `is_live` | Whether the named delegation survives evaluation.                                                  |
| `revocations_naming` | Revocations that name the delegation, covering or not. Explains a silent `seen` collision.   |
# The `keyline` Crate```rust
pub trait Keyline {
    fn insert(&mut self, cert: Verified<Certificate>) -> bool;
    fn contains(&self, cert: &Digest<Certificate>) -> bool;

    fn effective_access(&self, sub: Id, aud: Id) -> Option<Access>;
    fn members(&self, sub: Id) -> BTreeMap<Id, Access>;
    fn is_live(&self, cert: &Digest<Delegation>) -> bool;
    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<Revocation>>;
    fn digest(&self) -> Digest<BTreeSet<Certificate>>;
}
```

| Method    | Meaning                                                                                            |
|-----------|----------------------------------------------------------------------------------------------------|
| `insert`  | Add a certificate. `true` if newly added, as `BTreeSet::insert`. Idempotent. A dedupe signal for gossip, not a membership-change signal. |
| `contains` | Whether the digest is in the set. Ingest checks this before paying for signature verification.   |

This document specifies the Rust crate that implements the [Keyline model][keyline]. The model document says what authority _is_; this one says what the code exposes, what it assumes, and what it deliberately leaves to the layer above. Decisions recorded here were made before any code was written so that the implementation can be checked against them.

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

Three things share a name. In prose: _Keyline_ is the design, `keyline` is the crate, `Keyline` is the trait.

## Scope

`keyline` is a flat namespace of Ed25519 verifying keys and a set of signed certificates over them. It answers one family of questions: given this set, what access does key _A_ have over key _S_, and which certificates are live. It does this and nothing else.

| `keyline` knows                    | `keyline` does not know                       |
|------------------------------------|-----------------------------------------------|
| `Id` (a verifying key)             | prekeys, `ShareKey`, any X25519 material      |
| `Delegation`, `Revocation`         | BeeKEM, CGKA operations, key rotation         |
| `Access`                           | the difference between a document and a group |
| the certificate set and its digest | content references, `after_content`, causality |
| how to evaluate the set            | how to sign or verify (it receives witnesses) |

The crate sits beside `beekem`: both are engines over untyped keys, both are wrapped by `keyhive_core`, and neither is exposed to users. `keyhive_core` keeps its `Individual` / `Group` / `Document` handles and its public API. When a handle needs a membership or reachability answer, it converts IDs at the boundary and asks `keyline`, the same way `keyhive_core::cgka::Cgka` wraps `beekem::Cgka`. The typed handles are the [Ghosts of Departed Proofs][gdp] witnesses; `keyline` is the untyped thing they are proofs about.

## Types

### `Id`

A newtype over `ed25519_dalek::VerifyingKey`. Every principal, role, document, and group is an `Id`. `keyline` attaches no meaning to which is which.

`keyhive_core` has `Identifier` for the same thing; `keyline` defines its own for now and `keyhive_core` converts at the boundary, as it does for `beekem::MemberId`. Unifying shared types into a `keyhive_types` crate is a follow-up; the code carries `TODO(keyhive_types)` markers where it applies.

### `Access`

```rust
pub enum Access { Relay, Read, Edit, Admin }
```

Totally ordered, `Relay < Read < Edit < Admin`. Attenuation along a route is `min`; combination across routes is `max`. The type moves down from `keyhive_core` (which re-exports it) because the ordering is part of the graph semantics, not of the API layer.

### `Delegation`

```rust
pub struct Delegation {
    pub iss:  Id,
    pub aud:  Id,
    pub sub:  Id,
    pub can:  Access,
    pub seen: Option<Digest<Revocation>>,
}
```

| Field  | Meaning                                                                                                            |
|--------|--------------------------------------------------------------------------------------------------------------------|
| `iss`  | Signer. The edge rides this key's standing over `sub`.                                                             |
| `aud`  | Recipient. Gains `min(can, iss's effective level over sub)`.                                                       |
| `sub`  | Scope. `iss == sub` is a root edge. A role key as `sub` is membership in that role.                                |
| `can`  | Requested level; clamped, never raised.                                                                             |
| `seen` | The revocation being re-issued past. Gives a grant identical to a revoked one a fresh hash. Evaluation ignores it. Absent means first issuance. |

A delegation is the Granovetter operator from object capabilities: Alice, who has a reference to Carol, introduces Bob to Carol by handing him that reference. In the classic diagram the arrows are references; here they are authority over a subject.

```
                     ┌───────┐
                     │ Alice │  iss
                     └───┬───┘
            has authority │  \
              over Carol  │   \  introduces: { iss: Alice, aud: Bob, sub: Carol, can }
                          │    \
                          ▼     ▼
                     ┌───────┐  ┌─────┐
                sub  │ Carol │◄╴╴│ Bob │  aud
                     └───────┘  └─────┘
                            Bob now has min(Alice's level, can) over Carol
```

The solid arrow is Alice's existing authority over the subject; the dashed one is what the certificate creates. Everything about the rules follows from reading it this way: Alice can only introduce Bob to what she herself reaches (attenuation), the introduction is a fact about Alice's standing and dies with it (issuer-recursive liveness), and Alice can always take it back (retraction). Ocap's Granovetter diagram is a message; Keyline's is a signed, content-addressed record of the same act, evaluated against the whole set instead of delivered once.

Anyone MAY issue a delegation over any subject. The issuer's effective level over `sub` clamps the result; no Admin requirement exists on the grant side. This resolves the model document's open question on delegation below Admin: the attenuation rule is the whole rule.

Admin is not required to grant. It matters for revocation, in two tiers. You can always cut a delegation you issued: the edge below you is yours, and retraction needs no standing. Holding Admin over a node lets you act as that node for revocation: your cuts cover anything on routes through it, all the way down. "Act as" is revocation-side only. Admin over `N` does not let you sign as `N`; you grant authority _over_ `N` by issuing `{iss: you, sub: N, …}`, clamped by your own level.

Compared with the current `keyhive_core::Delegation`, the fields `proof`, `after_revocations`, and `after_content` are gone, and `delegate: Agent` is just `aud: Id`. This is a wire-format break; it lands with the wider API break that follows this branch.

#### Why `seen` and not a nonce

A random nonce would remove the need for an issuer to know which certificate it is re-issuing past. It was considered and rejected because it changes the fail direction. Two accidental issuances of the same grant (a retry, a device restore, two devices) would produce two independently live certificates with two hashes; revoking one leaves the other live, and a duplicate nobody noticed is a lingering grant. With `seen`, an identical re-issue produces the identical certificate: same payload, and because Ed25519 is deterministic, the same signature and the same hash. One revocation covers every copy. An issuer who re-mints a revoked grant without knowing it was revoked produces a certificate that silently does not take. That is fail-closed, and it is detectable: [`insert`](#insert) returns `false` and `revocations_naming` reports what named the duplicate, so `keyhive_core` can prompt for a re-issue with `seen` set to one of those revocations. `seen` also records in the certificate that the issuer re-granted knowing of the revocation. A nonce records nothing.

`seen` names the revocation, not the revoked delegation. The revoked delegation's digest is a function of the very fields being re-issued, so it carries no information and a second heal of the same grant would collide with the first; revocations are distinct certificates, so each heal is fresh. And a revocation is the only event that ever poisons a hash (implicit deaths revive by late binding), so it is always the thing one must have seen. See [README, The `seen` Field](README.md#the-seen-field).

### `Revocation`

```rust
pub struct Revocation {
    pub iss:    Id,
    pub revoke: Digest<Delegation>,
}
```

The type of `revoke` makes revoking a revocation unwritable. There is no `sub`: effect is scoped by the issuer's admin reach, not by the issuer's choice. A jurisdiction field was considered and rejected because it would make every rotation invalidate every standing denial; see [alternatives](alternatives.md#a-sub-jurisdiction-field-on-revocation).

### `Certificate`

```rust
pub enum Certificate { Delegation(Delegation), Revocation(Revocation) }
```

The unit of insertion and of the set.

### `Encoded<T>`

The bytes of a `T`, tagged with the type they encode:

```rust
pub struct Encoded<T> {
    bytes: Vec<u8>,
    _phantom: PhantomData<fn() -> T>,   // covariant; Send + Sync regardless of T
}
```

`Encoded::new(&T)` is the only way in from a value. Equality, `Hash`, and `Ord` are byte equality, which is certificate identity, so a set of `Encoded<Certificate>` needs no separate digest index. It serializes as a byte string behind a `serde` feature so that `keyhive_core` can carry it through its existing serde paths for now.

`Encoded<T>` and the `Encode` / `Decode` traits live in a new `keyhive_codec` crate (see [Crates](#crates)). Digest and signature are both computed over `Encoded::as_bytes()`, so they cover the same bytes by construction; nothing re-encodes a payload to check it.

### `Digest<T>`

`keyhive_crypto::Digest<T>`: BLAKE3, 32 bytes, phantom-typed. `keyline` obtains it as `Digest::of(&Encoded<T>)`, a constructor added to `keyhive_crypto` that hashes the encoded bytes. The `std`-gated `Digest::hash` (which needs `bincode`) is not used. `Digest<T>`'s `T: Serialize` bound is removed from the struct and its trait impls and kept only on `hash()`; this is additive.

### `Signed<T>` and `Verified<T>`

```rust
pub struct Signed<T> {
    encoded:   Encoded<T>,
    issuer:    Id,
    signature: ed25519_dalek::Signature,   // over encoded.as_bytes()
}

pub struct Verified<T> {
    payload: T,          // decoded exactly once, canonical form checked
    digest:  Digest<T>,
    signed:  Signed<T>,  // retained so the certificate can be forwarded as received
}

impl<T: Decode> Signed<T> {
    pub fn verify(self) -> Result<Verified<T>, VerifyError>;
}
```

`verify` is the only public constructor of `Verified<T>`. It checks the signature over the encoded bytes, decodes, and rejects non-canonical input (below). Because the digest is taken from the same bytes the signature covers, the identity a revocation names and the identity the set stores can never disagree. A `test_utils`-gated constructor exists for the conformance suite so that tests do not pay for signing.

These two types live in `keyline` for this branch, marked `TODO(keyhive_types)`. `keyhive_crypto`'s existing serde-based `Signed<T>` is untouched and remains what `keyhive_core` uses until the codec migration unifies them.

`keyline` does not verify signatures anywhere else. It depends on `ed25519-dalek` for `VerifyingKey`, `Signature`, and `verify_strict`.

## The `Keyline` Trait

```rust
pub trait Keyline {
    fn insert(&mut self, cert: Verified<Certificate>) -> bool;
    fn contains(&self, cert: &Digest<Certificate>) -> bool;

    fn effective_access(&self, sub: Id, aud: Id) -> Option<Access>;
    fn members(&self, sub: Id) -> BTreeMap<Id, Access>;
    fn is_live(&self, cert: &Digest<Delegation>) -> bool;
    fn revocations_naming(&self, cert: &Digest<Delegation>) -> BTreeSet<Digest<Revocation>>;
    fn digest(&self) -> Digest<BTreeSet<Certificate>>;
}
```

| Method               | Meaning                                                                                                        |
|----------------------|----------------------------------------------------------------------------------------------------------------|
| `insert`             | Add a certificate. `true` if newly added, as `BTreeSet::insert`. Idempotent. A dedupe signal, not a change signal. |
| `contains`           | Whether the digest is in the set. Ingest checks this before paying for signature verification.                 |
| `effective_access`   | `aud`'s effective level over `sub`: max over live routes of min along each. `None` if unreachable.             |
| `members`            | Every `Id` other than `sub` itself with a live route to `sub`, with its effective level. The materialized view. |
| `is_live`            | Whether the named delegation survives evaluation.                                                              |
| `revocations_naming` | Revocations that name the delegation, covering or not. Explains a silent `seen` collision.                     |
| `digest`             | A digest of the set, usable as a cache key: same digest, same answers.                                         |

Every method is defined purely in terms of the set. That is what makes the trait a backend contract: an implementation over DBSP, Postgres, or anything else is correct if and only if it gives the same answers as the reference implementation for the same set. The conformance suite (below) is how a backend proves that.

The trait is `&self` for queries and `&mut self` for `insert`. It is synchronous. There is no `FutureForm` parameter: the evaluator does no I/O, and concurrency is the wrapper's concern. `keyhive_core` holds the implementation behind a `RwLock` (or the `Local` equivalent); readers take the read guard and call `&self` methods in parallel, writers take the write guard briefly.

### Insert

`insert` cannot fail on bad input: the `Verified` witness has already excluded it. It returns whether the certificate was new so that ingest can avoid re-announcing a certificate it already held. It does not say whether any query result changed: a new certificate may be dead on arrival, and a duplicate never changes anything. A caller that must react to membership changes (to drive BeeKEM key rotation) diffs `members(sub)` before and after; an incremental evaluator that reports deltas is a later optimization.

A revocation whose target is not (yet) in the set is stored like any other certificate and contributes nothing until the target arrives; insertion order never matters.

Not yet on the trait: `get(&Digest<Certificate>) -> Option<&Signed<Certificate>>` and iteration over the set. Sync and archiving need them, but their shape depends on how Subduction pulls certificates, and a database-backed implementation may not hold the signed bytes. Decided at integration.

### `MemoryKeyline`

The reference implementation: in-memory, `impl Keyline`. Plain maps of plain data; no `Rc`, no `Cell`, so `Send + Sync` hold without effort. It MAY memoize stratum-1 results (admin reach, coverage) between inserts, since those are monotone in the set; any memo is invalidated on `insert` and never requires a write lock to read.

## Evaluation

Evaluation is a pure function of the set. The strata below are the canonical order the model document describes — all delegations, then all revocations, then the check — made executable: stratum 1 replays the proxy network of delegations, stratum 2 applies every revocation to it, and a query is the invocation being checked. The reference implementation is this program executed literally; anything faster MUST agree with it on every set.

```
Stratum 0 — facts
  del(h, iss, aud, sub, can)     one per delegation, h its digest
  rev(k, h)                      one per revocation

Stratum 1 — positive pass, blind to revocations
  reaches(n, n, Admin)                                                  every node grounds itself
  reaches(n, aud, min(l, can)) :- reaches(n, iss, l), del(_, iss, aud, n, can)         edge about n
  reaches(s, x,   min(l₁, l₂)) :- reaches(s, n, l₁), reaches(n, x, l₂), n ≠ s          membership

  admin_reach(k, n)   :- reaches(n, k, Admin)                                k ever held Admin over n
  admin_reach(k, k)                                                          own node always counts
  covered(h, n)  :- rev(k, h), admin_reach(k, n)

Stratum 2 — live pass, negation over stratum 1 only
  -- existence: least fixed point
  route(s, s, h)      :- ¬covered(h, s)
  route(s, aud, h)    :- route(s, iss, h), live(h′), del(h′, iss, aud, s, _), ¬covered(h, aud)
  route(s, x, h)      :- route(s, n, h), route(n, x, h), n ≠ s
  live(h)             :- del(h, iss, aud, s, _), route(s, iss, h), ¬rev(aud, h)

  -- level: greatest fixed point, iterated down from cap(h) = can
  level(s, s, h, Admin)              :- ¬covered(h, s)
  level(s, aud, h, min(l, cap(h′)))  :- level(s, iss, h, l), live(h′), del(h′, iss, aud, s, _), ¬covered(h, aud)
  level(s, x, h, min(l₁, l₂))        :- level(s, n, h, l₁), level(n, x, h, l₂), n ≠ s
  cap(h) = min(can, max l . level(s, iss, h, l))      for del(h, iss, _, s, can)
```

`route(s, x, h)` and `level(s, x, h, l)` are "x is reachable from s, through live edges, without touching any node covered for h"; the exclusion set is what `h` parameterises. Write `⊥` for a pseudo-certificate that nothing covers: `route(s, x, ⊥)` is plain live reachability and `level(s, x, ⊥, l)` is the plain live level. Then:

- `effective_access(s, a)` is the maximum `l` with `level(s, a, ⊥, l)`; `Some(Admin)` when `a = s`.
- `members(s)` is every `x ≠ s` with `route(s, x, ⊥)`, paired with its `effective_access`.
- `is_live(h)` is `live(h)`.

Notes on the program:

- _`sub` composes._ The third `reaches` rule is what makes `sub: Members` mean membership: whatever `Members` reaches, its members reach too, clamped by both hops. Without it `members(Doc)` would name roles and never humans, and the layer above would have to know which nodes are roles — which the crate boundary forbids. Every node with standing over `s` acts as a role for `s`; the rule does not ask what kind of key `n` is. A "route" is therefore a derivation, not a walk along `iss → aud` edges: Alice's membership `{iss: Bob, aud: Alice, sub: Members}` sits on Doc's route to Alice because Bob has standing over `Members`, not because Bob is the previous node.
- _Admin reach is composed._ `admin_reach(k, n)` is Admin standing over `n` however derived: Bob, an Admin member of `Owners`, has `Owners` in his reach and — because `Owners` is Admin over `Doc` — `Doc` as well, and every role `Owners` administers. Seniors adjudicate inside junior roles without an explicit `sub: Junior` grant. The price is that the apex of an Admin-rooted document is in every ever-apex-admin's reach, so any of them can revoke the root edge and brick the document, permanently. That is accepted: it is not a new power (a root admin can already eject every peer and lose their own key) and it is the same tier as a retained subject key. A last-hop ("direct") definition was rejected; see [alternatives](alternatives.md#direct-last-hop-admin-reach).
- _Admin over a document buys nothing but kill power._ Delegation is open to anyone, clamped by attenuation; membership management is Admin over the _role_. The only thing Admin over `Doc` itself gates is reach over `Doc`'s routes. A ceremony therefore chooses: root at `Admin` and every apex admin can brick the document; root at `Edit` and nobody ever holds Admin over `Doc`, so its root edge is undeniable by anyone (the subject key being destroyed) and re-rooting with a retained key escapes old admins' reach. One rule; the certificate set decides. See [patterns, Rooting Level](patterns.md#rooting-level).
- _Stratum 1 is global; stratum 2 is rooted._ `admin_reach(k, n)` must see every subject, because Bob's Admin over `Members` is what lets him cut things on `Doc`'s routes. Stratum 2 is grounded at one subject and ranges over every subject that subject reaches; "per-subject" means rooted at one subject, not confined to one subject's certificates.
- _The route for `h` is rooted at `sub(h)`, not at the querying subject._ `route(sub, iss, h)` lives entirely in `h`'s own subject's graph. How some other subject `S` reaches `sub(h)` is irrelevant to whether `h` is live; supplying a role into `S` (a `{iss: Dan, aud: Members, sub: S}` edge) gives Dan power over that plug — retract it and every member loses `S` at once — but none over `Members`' roster, which never routes through him. To cut inside `Members`, `Members` must be in your reach. This holds even when Dan reaches `S` at Admin through some other role: `S` is in his reach, `Members` is not. (Checking the hop's coverage against the `S`-rooted derivation instead was considered and rejected: it would let anyone who feeds authority into a role cut individual roster entries of that role.)
- _Both passes are the same rule._ `reaches` is `level(·, ·, ⊥, ·)` with every edge live and every cap equal to its `can`. The reference implementation is one bounded widest-path search over the composed graph, parameterised by an exclusion set; stratum 1 runs it with the empty set.
- _Two fixed points, in the safe direction each._ Existence (`route`, `live`) is a least fixed point: revisiting a node assumes dead, so ungrounded cycles cannot certify themselves. Caps are a greatest fixed point iterated down from `can`: caps only ever decrease, and the descent is finite (four levels, finitely many edges). The two are separable because existence never reads a cap.
- _Covered edges are clamped, not just gated._ A covered edge conveys at most the level its issuer holds _on a derivation that avoids the covered nodes_, not the issuer's global level. Example: Dan is an Admin of role `Mods`, which is supplied into `Doc` at Edit (so `Doc` is not in Dan's reach); Eve is a Mod (Edit over `Doc` via `Mods`) and also holds a direct Read over `Doc` from `Owners`; Eve grants Frank Admin over `Doc` (`h`); Dan revokes `h`. `admin_reach(Dan) = {Dan, Mods}`, so `h` is dead on the derivation through `Mods` and live on the one through `Owners`. Frank gets `min(Read, Admin) = Read`: Eve's standing as a Mod does not flow through the edge Dan cut, while her independent Read does. Gating alone (existence via the avoiding derivation, level from Eve's global Edit) would hand Frank the very authority the cut was about. Clamping yields the same live set and levels `≤` the gated reading everywhere: ambiguity resolves toward less authority.
- _Clamping is a relaxation of route-consistency._ The exact reading — a single derivation in which every edge's own covered set is avoided by that derivation's prefix — is a path-with-forbidden-pairs problem and is not known to be polynomial; a reference semantics an adversary can make exponential with crafted certificates is a denial-of-service vector. `cap(h)` avoids `h`'s covered set but takes the edges it traverses as already-live facts, each justified by its own derivation. See [alternatives, route-consistent levels](alternatives.md#route-consistent-levels).
- _Negation appears once, over fully computed lower strata._ Revocations target delegations, never other revocations, so `covered` never depends on `live`. This is what makes the result independent of insertion order.
- _Aggregation is a bucketed BFS._ Four levels, so the widest-path pass over un-revoked certificates is linear. Each covered certificate pays one route search with its exclusion set, plus one more per cap-descent round.
- _The route ends at `iss`; the recipient answers only to their own signature._ Admin-reach coverage applies to the nodes a derivation transits, and the derivation for `h` runs from `sub` to `iss`. Retraction (`k = iss`) is therefore total with no special case: `iss` is in its own admin reach and on its own route. Renunciation (`k = aud`) is the one explicit clause, `¬rev(aud, h)`: the recipient's _own_ revocation kills what names them, but nobody's _reach_ covers a certificate through its `aud`. Putting `aud` on the route would give every admin of a role deny power over every grant _to_ that role — a `Members` admin could cut `Doc → Members` supply edges they never issued and hold no reach over on `Doc`'s side.
- _Un-grounded certificates cost storage only._ Evaluation forward-chains from root edges and never visits them.
- _Root edges are not special-cased._ `reaches(n, n, Admin)` puts every node at Admin over itself, so `{iss: Doc, aud: Owners, sub: Doc}` is an ordinary edge whose issuer happens to reach the subject. The evaluator never tests `iss == sub`.

The model document's [Computation] section explains why the shortcut "delete revoked edges, then compute reachability" is wrong, not merely slow.

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

Every implementation MUST satisfy two laws:

1. `decode(encode(x)) == x` — round trip.
2. `encode(decode(b)) == b` for every `b` that `decode` accepts — canonicality.

The second is a security requirement, not tidiness. Certificates travel as `Encoded<T>` and the receiver verifies and hashes the bytes it received; nothing re-encodes. If the codec admitted two byte forms for one value, a peer could ship the same delegation twice with two digests, producing two live certificates for one grant of which a revocation covers only one — the [nonce failure mode](alternatives.md#a-random-nonce-instead-of-seen) through the back door. `decode` MUST therefore reject any non-canonical input, either because the format admits exactly one encoding per value or by re-encoding and comparing. A corollary: absent `seen` has exactly one encoding, distinct from every present value.

For this branch, `keyline` implements the traits for its own types with a fixed-width layout:

```
Delegation:  iss ‖ aud ‖ sub ‖ can:u8 ‖ seen_tag:u8 ‖ seen?
Revocation:  iss ‖ revoke
```

where `seen_tag` is `0` with no following bytes when `seen` is absent and `1` followed by 32 bytes when present. Fixed-width layouts are canonical by construction, so `decode` only has to check length and enum ranges.

This layout is a placeholder. Keyhive is moving to a bespoke codec after this branch; when it lands, these `Encode` / `Decode` impls are replaced (possibly by derive macros in `keyhive_codec`), every hash changes, and the API break already in progress absorbs that. `Encoded<T>`, `Signed<T>`, `Verified<T>`, and the `Keyline` trait do not change. The placeholder exists so that the crate is `no_std` from the start (no `bincode`) and so that the evaluator and its tests have stable hashes to build against.

## Crates

```
keyhive_codec        Encode, Decode, Encoded<T>. No dependencies beyond alloc; serde optional.
      ▲
keyhive_crypto       Digest<T> (bound loosened), Digest::of(&Encoded<T>). Old Signed<T> untouched.
      ▲
keyline              Id, Access, Delegation, Revocation, Certificate, Signed/Verified over Encoded,
                     the Keyline trait, MemoryKeyline, conformance suite.
      ▲
keyhive_core         consumes keyline (later); never sees raw bytes.
```

`keyhive_codec` exists now, with only the traits and `Encoded<T>`, because the dependency direction is only right if it sits at the bottom: `beekem` will implement the same traits when it migrates, and `beekem → keyline` would be wrong. It contains no BLAKE3; hashing an `Encoded<T>` is `keyhive_crypto`'s job.

## Crate Layout and Features

```
keyline/
  src/
    lib.rs          //! model summary, prose convention, links to design/keyline/
    id.rs           Id
    access.rs       Access
    delegation.rs   Delegation
    revocation.rs   Revocation
    certificate.rs  Certificate; Encode/Decode impls for all three
    signed.rs       Signed<T>, Verified<T>
    keyline.rs      the Keyline trait, set_digest
    memory.rs       MemoryKeyline: storage, stratified evaluator, Keyline impl
    conformance.rs  the shared test suite and the keyline_conformance! macro
    conformance/    gen.rs (CertSet generator), laws.rs (bolero properties, naive oracle),
                    scenarios.rs (named cases, generic over K: Keyline)
    test_utils.rs   deterministic ids, unsigned Verified fixtures
```

- `#![no_std]` + `extern crate alloc`; `#![forbid(unsafe_code)]`.
- Depends on `keyhive_codec` (traits, `Encoded`), `keyhive_crypto` (`Digest`), and `ed25519-dalek` (`VerifyingKey`, `Signature`). Nothing else at runtime.
- `std` feature (default on): `HashMap`/`HashSet` via `beekem::collections`-style aliases, `thiserror`. Without it, `BTreeMap`/`BTreeSet`.
- `test_utils` feature: the conformance suite, the unverified `Verified` constructor, and `bolero`/`arbitrary`. Also compiled under `cfg(test)` so the crate's own tests run without the feature.
- `serde` feature: derives on the public types for `keyhive_core`'s internal use (archives). Not the wire format.
- No `parallel` feature yet. If one comes, it is native-only (`rayon`); Wasm stays single-threaded because `wasm-bindgen-rayon` needs `SharedArrayBuffer`, COOP/COEP headers, and a worker pool. The evaluator is written so the independent units (admin reach per issuer, route search per covered certificate) are plain iterators.

Follows the workspace's `beekem` conventions: `foo.rs` + `foo/`, manual impls instead of `derivative`, `tracing` behind `std`.

## Conformance Suite

Every backend runs the same tests against `impl Keyline`. The suite is exported behind `test_utils`; `keyline_conformance!(MyBackend)` expands to one `#[test]` per scenario and per law. `MemoryKeyline` runs it on itself.

_Generator._ `conformance::gen::CertSet` draws from a pool of eight deterministic identities: a root edge per subject (one to three), up to ten free-form delegations over any node in the pool (so some land on roles and some are ungrounded), up to four revocations naming delegations already present, and up to two re-issues past a revocation. Random 32-byte keys would give nothing but ungrounded edges.

_Laws_ (`bolero`, over generated sets):

- Oracle agreement without revocations: `effective_access` over every pair in the pool equals `naive_reaches`, the three stratum-1 rules run as a plain tuple fixpoint that shares no code with any backend; `is_live(h)` iff `iss(h)` reaches `sub(h)`. This is the one independent oracle; it pins the composition and attenuation semantics exactly.
- Order independence: any permutation of a set gives the same `digest`, the same levels over the pool, the same live set, the same `members`.
- Idempotence: re-inserting every certificate returns `false` and changes nothing.
- Revocations only deny: for each revocation in a set, the set without it has levels `≥` everywhere and a live set `⊇`.
- Digest identifies the set: permutation-invariant; dropping any non-duplicated certificate changes it.
- Query consistency: `effective_access(s, s) = Some(Admin)` for every `s`; `members(s)` is `effective_access(s, ·)` minus `s`; `contains` holds for everything inserted; `revocations_naming(h)` is exactly the revocations in the set with `revoke = h`.

With revocations, exact agreement is by scenario. A second oracle for that case — the full program transcribed into a Datalog engine (`ascent`) as a dev-dependency — is an open option.

_Scenarios._ The seven findings and the running scenario from [edge-cases], encoded as fixtures: rotation moots but never un-applies; concurrent mutual revocation leaves both standing; ex-admin cuts cover only the frozen admin reach; an apex admin of an Admin-rooted document can deny the root edge, while an Edit-rooted document's root edge is undeniable; retraction and renunciation are total; a non-admin's cut is confined to their own node; `seen` re-issue heals with the same downstream hashes. Plus the composition and reach cases from [Evaluation](#evaluation): membership carries whatever the role reaches, including documents added later; a senior role's admin cuts inside a junior role without an explicit grant; supplying a role into a document gives power over the supply edge and none over the roster; a covered edge conveys only what its issuer holds on the avoiding derivation (the `Mods` example). `MemoryKeyline` runs these via `keyline_conformance!`.

_Negative._ A revocation naming an unknown hash is new and changes no answer. A duplicate returns `false` from `insert` and `revocations_naming` reports what named it.

## Integration Sketch

Not part of this branch; recorded so the crate's shape is checked against its one consumer.

- `keyhive_core` holds `Arc<RwLock<MemoryKeyline>>` (or `Rc<RefCell<_>>` for `Local`) on `Keyhive`.
- `Group::members()`, `Document::members()`, `Membered::transitive_members()` become `keyline.members(id)` with ID conversion.
- `add_member` builds a `Delegation`, signs it with the active signer, `verify()`s it (cheap, and it exercises the same path as ingest), and `insert`s.
- `revoke_member` builds one `Revocation` per delegation to cut. Whether to also cut everything the member issued (explicit removal) is a `keyhive_core` policy, per the model document's removal tiers.
- Events for sync carry `Verified<Certificate>`; ingest is `insert`.
- BeeKEM membership is `members(doc).filter(|(_, a)| a >= Read)`. The coupling of revocation to key rotation remains an open design item in the model document.

## Resolved Here

| Model-document open item | Resolution                                                                                                    |
|--------------------------|---------------------------------------------------------------------------------------------------------------|
| Delegation below Admin   | Anyone may delegate; attenuation is the only rule. Admin matters for admin reach only.                    |
| `seen` vs nonce          | `seen`. Rationale above.                                                                                      |
| Silent collision UX      | `insert == false` plus `revocations_naming` gives the caller what it needs to prompt.                         |

## Deferred

- Whiteout and the `Relay`/BeeKEM rotation coupling: unchanged, content-layer and integration questions respectively.
- The bespoke codec: last task on this branch, or the branch after.
- Incremental evaluation and memoization beyond stratum 1: only once the conformance suite pins semantics.
- A second backend and a `keyline` / `keyline_memory` crate split: only if a second backend appears.

<!-- Links -->

[BCP 14]: https://datatracker.ietf.org/doc/bcp14/
[Computation]: README.md#computation
[edge-cases]: edge-cases.md
[gdp]: https://kataskeue.com/gdp.pdf
[keyline]: README.md
