# The `keyline` Crate

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
    pub seen: Option<Digest<Delegation>>,
}
```

| Field  | Meaning                                                                                                            |
|--------|--------------------------------------------------------------------------------------------------------------------|
| `iss`  | Signer. The edge rides this key's standing over `sub`.                                                             |
| `aud`  | Recipient. Gains `min(can, iss's effective level over sub)`.                                                       |
| `sub`  | Scope. `iss == sub` is a root edge. A role key as `sub` is membership in that role.                                |
| `can`  | Requested level; clamped, never raised.                                                                             |
| `seen` | Freshness for re-issuing a grant identical to a revoked one. Evaluation ignores it. Absent means first issuance.   |

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

A random nonce would remove the need for an issuer to know which certificate it is re-issuing past. It was considered and rejected because it changes the fail direction. Two accidental issuances of the same grant (a retry, a device restore, two devices) would produce two independently live certificates with two hashes; revoking one leaves the other live, and a duplicate nobody noticed is a lingering grant. With `seen`, an identical re-issue produces the identical certificate: same payload, and because Ed25519 is deterministic, the same signature and the same hash. One revocation covers every copy. An issuer who re-mints a revoked grant without knowing it was revoked produces a certificate that silently does not take. That is fail-closed, and it is detectable: [`insert`](#insert) reports the collision and the covering revocation, so `keyhive_core` can prompt for a re-issue with `seen`. `seen` also records in the certificate that the issuer re-granted knowing of the revocation. A nonce records nothing.

### `Revocation`

```rust
pub struct Revocation {
    pub iss:    Id,
    pub revoke: Digest<Delegation>,
}
```

The type of `revoke` makes revoking a revocation unwritable. There is no `sub`: effect is scoped by the issuer's service record, not by the issuer's choice. A jurisdiction field was considered and rejected because it would make every rotation invalidate every standing denial; see [alternatives](alternatives.md#a-sub-jurisdiction-field-on-revocation).

### `Certificate`

```rust
pub enum Certificate { Delegation(Delegation), Revocation(Revocation) }
```

The unit of insertion and of the set.

### `Digest<T>`

`keyhive_crypto::Digest<T>`: BLAKE3, 32 bytes, phantom-typed. `keyline` computes it over the certificate's canonical bytes (see [Encoding](#encoding)) and builds the `Digest` from the raw hash, so the `std`-gated `Digest::hash` (which needs `bincode`) is not used.

### `Verified<T>`

A witness that a `Signed<T>` has had its signature checked against `iss`. It lives in `keyhive_crypto` so that `keyline` and `keyhive_core` share it:

```rust
pub struct Verified<T> { /* private */ }

impl<T> Signed<T> {
    pub fn verify(self) -> Result<Verified<T>, VerificationError>;
}
```

The only public constructor is `verify`. `Verified<T>` carries the `Digest<T>` computed over the same bytes the signature covers, so the identity a revocation names and the identity the set stores can never disagree. A `test_utils`-gated constructor exists for the conformance suite so that tests do not pay for signing.

`keyline` does not verify signatures. It depends on `ed25519-dalek` only for the `VerifyingKey` type.

## The `Keyline` Trait

```rust
pub trait Keyline {
    fn insert(&mut self, cert: Verified<Certificate>) -> Inserted;

    fn access(&self, sub: Id, aud: Id) -> Option<Access>;
    fn members(&self, sub: Id) -> BTreeMap<Id, Access>;
    fn is_live(&self, cert: &Digest<Delegation>) -> bool;
    fn digest(&self) -> SetDigest;
}
```

| Method    | Meaning                                                                                            |
|-----------|----------------------------------------------------------------------------------------------------|
| `insert`  | Add a certificate to the set. Idempotent.                                                          |
| `access`  | `aud`'s effective level over `sub`: max over live routes of min along each. `None` if unreachable. |
| `members` | Every `Id` with a live route to `sub`, with its effective level. The materialized view.            |
| `is_live` | Whether the named delegation survives evaluation.                                                  |
| `digest`  | A digest of the set, usable as a cache key: same digest, same answers.                             |

Every method is defined purely in terms of the set. That is what makes the trait a backend contract: an implementation over DBSP, Postgres, or anything else is correct if and only if it gives the same answers as the reference implementation for the same set. The conformance suite (below) is how a backend proves that.

The trait is `&self` for queries and `&mut self` for `insert`. It is synchronous. There is no `FutureForm` parameter: the evaluator does no I/O, and concurrency is the wrapper's concern. `keyhive_core` holds the implementation behind a `RwLock` (or the `Local` equivalent); readers take the read guard and call `&self` methods in parallel, writers take the write guard briefly.

### `Inserted`

```rust
pub enum Inserted {
    New,
    Duplicate { existing: Digest<Certificate>, revoked_by: Option<Digest<Revocation>> },
}
```

`insert` cannot fail on bad input: the `Verified` witness has already excluded it. `Duplicate` carries enough for the caller to explain a silent collision. A revocation whose target is not (yet) in the set is stored like any other certificate and is `New`; it contributes nothing until the target arrives, and insertion order never matters.

### `AuthGraph`

The reference implementation: in-memory, `impl Keyline`. Plain maps of plain data; no `Rc`, no `Cell`, so `Send + Sync` hold without effort. It MAY memoize stratum-1 results (records, coverage) between inserts, since those are monotone in the set; any memo is invalidated on `insert` and never requires a write lock to read.

## Evaluation

Evaluation is a pure function of the set. The strata below are the canonical order the model document describes — all delegations, then all revocations, then the check — made executable: stratum 1 replays the proxy network of delegations, stratum 2 applies every revocation to it, and a query is the invocation being checked. The reference implementation is this program executed literally; anything faster MUST agree with it on every set.

```
Stratum 0 — facts
  del(h, iss, aud, sub, can)     one per delegation, h its digest
  rev(k, h)                      one per revocation

Stratum 1 — positive pass, blind to revocations
  reaches(s, s, Admin)                                       every subject grounds itself
  reaches(s, aud, min(l, can)) :- reaches(s, iss, l), del(_, iss, aud, s, can)
  record(k, n)   :- reaches(n, k, Admin)                     k ever held Admin over n
  record(k, k)                                                 own node always counts
  covered(h, n)  :- rev(k, h), record(k, n)

Stratum 2 — live pass, negation over stratum 1 only
  live(s, s, Admin)
  live(s, aud, min(l, can)) :- live(s, iss, l), del(h, iss, aud, s, can),
                                route(s, iss) avoids every n with covered(h, n)
```

`access(s, a)` is the maximum `l` with `live(s, a, l)`. `is_live(h)` is whether `del(h, …)` participates in any `live` derivation.

Notes on the program:

- _Stratum 1 is global; stratum 2 is per-subject._ `record(k, n)` must see every subject, because Bob's Admin over `Members` is what lets him cut things on `Doc`'s routes. `live` is grounded at one subject's root and ranges over that subject's routes.
- _Both passes are the same rule._ Stratum 2 is stratum 1 plus a guard. The reference implementation is one bounded widest-path search parameterized by an exclusion set; stratum 1 runs it with the empty set.
- _Negation appears once, over fully computed lower strata._ Revocations target delegations, never other revocations, so `covered` never depends on `live`. This is what makes the result independent of insertion order.
- _Cycles resolve to the least fixed point._ Revisiting a node assumes dead. Assuming live would make ungrounded cycles self-certifying.
- _Aggregation is a bucketed BFS._ Four levels, so the widest-path pass over un-revoked certificates is linear. Each covered certificate pays one route search with its exclusion set.
- _Un-grounded certificates cost storage only._ Evaluation forward-chains from root edges and never visits them.

The model document's [Computation] section explains why the shortcut "delete revoked edges, then compute reachability" is wrong, not merely slow.

## Encoding

`Digest<T>` and the signature both cover `canonical_bytes(payload)`. For this branch, `canonical_bytes` is a fixed-width concatenation:

```
Delegation:  iss ‖ aud ‖ sub ‖ can:u8 ‖ seen_tag:u8 ‖ seen?
Revocation:  iss ‖ revoke
```

where `seen_tag` is `0` with no following bytes when `seen` is absent and `1` followed by 32 bytes when present.

This is a placeholder. Keyhive is moving to a bespoke codec after this branch; when it lands, `canonical_bytes` is replaced by the codec's encoding and every hash changes, which the API break already absorbs. The placeholder exists so that the crate is `no_std` from the start (no `bincode`) and so that the evaluator and its tests have stable hashes to build against.

One requirement the codec MUST preserve: absent `seen` has exactly one encoding, distinct from every present value. The model document's "one meaning, one encoding" invariant depends on it.

## Crate Layout and Features

```
keyline/
  src/
    lib.rs          //! model summary, prose convention, links to design/keyline/
    id.rs           Id
    access.rs       Access
    delegation.rs   Delegation
    revocation.rs   Revocation
    certificate.rs  Certificate, canonical_bytes
    keyline.rs      the Keyline trait, Inserted
    graph.rs        AuthGraph
    graph/          eval.rs (stratified evaluator), index.rs
    conformance.rs  #[cfg(feature = "test_utils")] the shared test suite
```

- `#![no_std]` + `extern crate alloc`; `#![forbid(unsafe_code)]`.
- Depends on `keyhive_crypto` (for `Digest`, `Signed`, `Verified`) and `ed25519-dalek` (for `VerifyingKey`). Nothing else at runtime.
- `std` feature (default on): `HashMap`/`HashSet` via `beekem::collections`-style aliases, `thiserror`. Without it, `BTreeMap`/`BTreeSet`.
- `test_utils` feature: the conformance suite and the unverified `Verified` constructor.
- `serde` feature: derives on the public types for `keyhive_core`'s internal use (archives). Not the wire format.
- No `parallel` feature yet. If one comes, it is native-only (`rayon`); Wasm stays single-threaded because `wasm-bindgen-rayon` needs `SharedArrayBuffer`, COOP/COEP headers, and a worker pool. The evaluator is written so the independent units (records per issuer, route search per covered certificate) are plain iterators.

Follows the workspace's `beekem` conventions: `foo.rs` + `foo/`, manual impls instead of `derivative`, `tracing` behind `std`.

## Conformance Suite

Every backend runs the same tests against `impl Keyline`. The suite is exported behind `test_utils` and uses `bolero` for the properties:

_Laws._

- Order independence: for any set and any two insertion orders, every query agrees.
- Idempotence: inserting a certificate twice leaves every query unchanged.
- Monotone denial: adding a certificate never revives a delegation that was dead. (Adding a delegation can revive by late binding; adding a _revocation_ never grants.)
- Attenuation: `access(s, a) ≤ can` for every delegation naming `a`; `access` along any single route equals the min of its hops.
- Widest path: `access(s, a)` equals the max over routes of min along each, computed independently by brute force on small graphs.
- Digest stability: same set (any order) gives the same `digest()`; different sets differ.

_Scenarios._ The seven findings and the running scenario from [edge-cases], encoded as fixtures: rotation moots but never un-applies; concurrent mutual revocation leaves both standing; ex-admin cuts cover only the frozen record; root edge is undeniable; retention of the subject key allows re-rooting; renunciation is total; `seen` re-issue heals with the same downstream hashes.

_Negative._ A revocation naming an unknown hash is `New` and changes no answer. A duplicate reports the covering revocation if one exists.

## Integration Sketch

Not part of this branch; recorded so the crate's shape is checked against its one consumer.

- `keyhive_core` holds `Arc<RwLock<AuthGraph>>` (or `Rc<RefCell<_>>` for `Local`) on `Keyhive`.
- `Group::members()`, `Document::members()`, `Membered::transitive_members()` become `keyline.members(id)` with ID conversion.
- `add_member` builds a `Delegation`, signs it with the active signer, `verify()`s it (cheap, and it exercises the same path as ingest), and `insert`s.
- `revoke_member` builds one `Revocation` per delegation to cut. Whether to also cut everything the member issued (explicit removal) is a `keyhive_core` policy, per the model document's removal tiers.
- Events for sync carry `Verified<Certificate>`; ingest is `insert`.
- BeeKEM membership is `members(doc).filter(|(_, a)| a >= Read)`. The coupling of revocation to key rotation remains an open design item in the model document.

## Resolved Here

| Model-document open item | Resolution                                                                                                    |
|--------------------------|---------------------------------------------------------------------------------------------------------------|
| Delegation below Admin   | Anyone may delegate; attenuation is the only rule. Admin matters for service records only.                    |
| `seen` vs nonce          | `seen`. Rationale above.                                                                                      |
| Silent collision UX      | `Inserted::Duplicate { revoked_by }` gives the caller what it needs to prompt.                                |

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
