# The `keyline` Crate

This document explains the Rust crate that implements the [Keyline model][keyline]. The model document says what authority _is_; this one says what the code exposes, what it assumes, and what it leaves to the layer above. The contract a backend is checked against is executable: the `Keyline` trait and the [conformance suite](#conformance-suite).

_Keyline_ is the design, `keyline` is the crate, and `Keyline` is the trait.

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

The crate sits beside `beekem`: both are engines over untyped keys, and neither is meant to be exposed to users. `keyhive_core` keeps its `Individual` / `Group` / `Document` handles and converts IDs at the boundary when a handle needs a membership or reachability answer, the same way `keyhive_core::cgka::Cgka` wraps `beekem::Cgka`. The typed handles are the [Ghosts of Departed Proofs][gdp] witnesses; `keyline` is the untyped thing they are proofs about. See [Integration](#integration).

## Types

Field names follow one rule. Participants and references are nouns: `issuer`, `audience`, `subject`, `power`, `citation`. A revocation is a signed directive, so its directives are imperative verbs: `revoke` this delegation, `retain` these watermarks. Read aloud, a revocation says "Alice: revoke `#d1`, retain `{doc: heads}`".

### `Id`

`keyhive_crypto::id::Id`: a newtype over the 32-byte compressed form of an `ed25519_dalek::VerifyingKey`, with a canonical codec (`Encode`, `Decode`, `StreamDecode`). It started in `keyline` and moved down so that Beekem and `keyhive_core` can use the same validated key on the wire. Every principal, role, document, and group is an `Id`. `keyline` attaches no meaning to which is which.

`Id::from_bytes` accepts only the canonical encoding of a curve point outside the small-order subgroup. A non-canonical encoding would give one key two `Id`s, and a small-order key verifies forged signatures. `InvalidId` says which check failed.

`keyhive_core`'s typed identifiers (`IndividualId`, `GroupId`, `DocumentId`) and Beekem's `MemberId` and `TreeId` wrap `Id`, so converting between them cannot fail; a key is validated once, where it enters.

### `Power`

```rust
pub enum Power { Relay, Read, Edit, Admin }
```

Totally ordered, `Relay < Read < Edit < Admin`. Attenuation along a route is `min`; combination across routes is `max`. The type belongs here rather than in `keyhive_core` because the ordering is part of the graph semantics, not of the API layer.

Order and encoding are separate. The lattice is `Power::rank()`; the wire tag is an ASCII letter (`L` for reLay, `R`, `E`, `A`), one byte. Neither is derived from the other: `Admin` is the top of the order and the lowest of the four bytes, which a unit test pins. This keeps the level set extensible. A level added later takes any free byte and sits wherever its rank puts it, so no existing certificate's bytes change and no digest moves. With consecutive integer tags, inserting a level would renumber `Admin` and invalidate every `revoke` and `citation` pointer in every stored set.

### `Delegation`

```rust
pub struct Delegation {
    pub audience: Id,
    pub subject:  Id,
    pub power:    Power,
    pub citation: Option<Digest<RevocationId>>,
}
```

`RevocationId` is an uninhabited marker. `Revocation` is generic over its watermark type (below), and naming it as `Digest<Revocation<W>>` would make `Delegation` generic over a type it never uses.

The issuer is not a field. It is the key that signs, carried in the signed envelope ([`Signed<T>`](#signedt-and-verifiedt)) and read as `Verified::issuer()`. The edge rides the issuer's standing over `subject`.

| Field      | Meaning                                                                                                                             |
|------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `audience` | Receives `min(power, issuer's effective power over subject)`.                                                                       |
| `subject`  | Scope. A delegation the subject itself signs is a root edge. A role key as `subject` is membership in that role.                    |
| `power`    | Requested level; clamped, never raised.                                                                                             |
| `citation` | The revocation being re-issued past. Gives a delegation identical to a revoked one a fresh digest. Evaluation ignores it. Absent means first issuance. |

A delegation is the Granovetter introduction from object capabilities; the [model document](README.md#intuition) draws it. One difference matters for the rules: anyone can name anyone as `audience`, and the audience never consents. That is one reason revocation by the audience exists, and it is why the [gift-cert attack](evaluation-notes.md#single-queries-and-the-gift-cert-attack) is possible.

Anyone may issue a delegation over any subject. The issuer's effective power over `subject` clamps the result; issuing needs no Admin.

Admin matters for revocation, in two tiers. You can always revoke a delegation you issued: revocation by the issuer needs no standing. Holding Admin over a node lets you act as that node for revocation: your revocations cover anything on routes through it, all the way down. "Act as" is revocation-side only. Admin over `N` does not let you sign as `N`; you delegate authority _over_ `N` by signing a delegation with `subject: N`, clamped by your own level.

`citation` names a revocation rather than using a random nonce, so that an accidental duplicate issuance is one certificate, not two; see [alternatives](alternatives.md#a-random-nonce-instead-of-citation). It names the revocation, not the revoked delegation; see [The `citation` Field](README.md#the-citation-field).

### `Revocation`

```rust
pub struct Revocation<W> {
    pub revoke: Digest<Delegation>,
    pub retain: BTreeMap<Id, W>,
}
```

As for a delegation, the issuer is the signer, carried in the envelope; its admin reach scopes the effect.

| Field    | Meaning                                                                                          |
|----------|--------------------------------------------------------------------------------------------------|
| `revoke` | The delegation being withdrawn, by its digest.                                                   |
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

### Certificates

```rust
pub enum Certificate<W> {           // a signed statement, as received
    Delegation(Signed<Delegation>),
    Revocation(Signed<Revocation<W>>),
}

pub enum VerifiedCertificate<W> {   // what `insert` takes
    Delegation(Verified<Delegation>),
    Revocation(Verified<Revocation<W>>),
}

pub enum CertificateId {            // what the set is keyed by
    Delegation(Digest<Delegation>),
    Revocation(Digest<RevocationId>),
}
```

What gets signed is the delegation or the revocation itself, each as its own [kind](#domain-separation). A certificate is the sum of those two signed forms, not a signature over a sum, so each statement has one identity: the digest of its signed payload. That digest is the set key (`CertificateId`), and it is what `revoke` and `citation` name. `Certificate::verify` verifies whichever kind it holds. `W` is fixed for each set as `Keyline::RetentionWatermark`. `Certificate` equality is `Signed`'s, bytes and signature; compare ids for "same statement".

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

`keyhive_crypto::digest::Digest<T>`: BLAKE3, 32 bytes, phantom-typed. `keyline` obtains a statement's digest as `Digest::of(&issuer, &Encoded<T>)`, which requires `T: Kinded` and hashes the same bytes its signature covers ([Domain Separation](#domain-separation)), or as `Digest::of_bytes` for a hash-only kind with no issuer, such as the set digest. The `std`-gated `Digest::hash` (which needs `bincode`) is not used; its `T: Serialize` bound sits on `hash()` alone.

### Domain Separation

The keys that sign Keyline certificates also sign in other protocols, such as key agreement operations and prekey operations. If one byte string were valid in two formats, one signature would be valid in both. So every signed statement travels as a frame that starts with Keyhive's tag, and its signature covers the frame up to the signature:

```
frame              "KH" ‖ kind:u8 ‖ version:u8 ‖ issuer:32 ‖ payload_len:bijou64 ‖ payload ‖ signature:64
signed and hashed  the frame without its signature
```

The kind is the type's permanent number in one registry for the whole workspace, `keyhive_crypto::signable::Kind`; a retired number is never reused. Kinds are ASCII letters by convention, so a frame reads `KHD…` in a hexdump; any byte may be used once the letters run out. `I` is reserved, because an archive starts with `KHIV`. No common file format starts with `KH` at offset 0. The version is the version of the type's encoding, a byte starting at `0x00`.

| Type             | Kind      | Used for                          |
|------------------|-----------|-----------------------------------|
| `CgkaOperation` (Beekem) | `C` (`0x43`) | signing, and its digest   |
| `Delegation`     | `D` (`0x44`) | signing, and its digest           |
| `Revocation<W>`  | `R` (`0x52`) | signing, and its digest           |
| `CertificateSet` | `S` (`0x53`) | the set digest only; never signed: `"KH" ‖ kind ‖ version ‖ bytes` |

A type with a kind implements `keyhive_crypto::signable::Kinded` (`KIND`, `VERSION`). `Signable` is `Kinded + Encode + Decode`, with a blanket impl: what can be signed and verified. `CertificateSet` is `Kinded` but has no codec, so it cannot be signed. The two kinds of certificate are separated by their kinds, which is also why their digests can share one key type without a tag. The free function `signable::message::<T>` builds the bytes a signature covers, and `Digest::of` hashes exactly those bytes, so a signature and a digest always cover the same input; being a free function, no implementation can override it. Because the tag, kind, version, issuer and length are part of the frame, everything stored except the signature is signed: a frame whose kind, version, issuer or length was changed does not verify. The signed bytes are one contiguous span from the frame's first byte, so a digest is BLAKE3 over that span. Each type declares its kind next to its definition, and `keyline/tests/invariants.rs` checks that they are distinct. Separation from a protocol that signs unprefixed bytes, such as the prekey operations still signed through serde today, relies on that protocol's formats.

### `Signed<T>` and `Verified<T>`

```rust
pub struct Signed<T> {
    issuer:    Id,                         // who signed
    encoded:   Encoded<T>,
    signature: ed25519_dalek::Signature,   // over message::<T>(&issuer, encoded.as_bytes())
}

pub struct Verified<T> {
    payload: T,          // decoded once, canonical form checked
    signed:  Signed<T>,  // retained so the certificate can be forwarded as received
}

impl<T: Signable> Signed<T> {
    pub fn verify(self) -> Result<Verified<T>, VerifyError>;
}

impl<T: Signable> Verified<T> {
    pub async fn sign<F: FutureForm, S: AsyncSigner<F>>(value: &T, signer: &S) -> Result<Self, SignError>;
    pub fn sign_sync<S: SyncSignerBasic + Verifiable>(value: &T, signer: &S) -> Result<Self, SignError>;
}
```

Who signed is part of the envelope, the same for every type, and the issuer is among the signed bytes. `verify` checks the signature against that key and no other. In order, it:

1. decodes the payload;
2. re-encodes it and requires exactly the received bytes, so a `Verified<T>` is always canonical;
3. runs `verify_strict` over `message::<T>(&issuer, bytes)` with the issuer's key.

A frame whose issuer was replaced does not verify, and neither does one signed by a key other than the issuer it names. Because the issuer is in the envelope rather than the payload, any reader can verify any entry, even one of a version it cannot decode. Signing makes the signer's key the issuer; a key that is not a valid `Id` (not canonical, or of small order) is refused with `SignError::InvalidIssuer`. `verify_strict` rejects the small-order and malleable signatures that plain `verify` accepts; a unit test builds such a forgery and checks that it fails.

Signing goes through `keyhive_crypto`'s signer traits, the same ones `keyhive_core` uses, so the signing key can be non-extractable: WebCrypto, an HSM, or a KMS behind `AsyncSigner`, or an in-memory key behind `SyncSignerBasic`. The signer sees only `message::<T>`, so a caller cannot forget the prefix. `sign` returns a `Verified<T>` rather than a `Signed<T>`: it verifies what the signer returned, so a signer that produces a bad signature fails at the issuer, not at every peer that receives the certificate. Tests pin this with a signer that drops the tag, kind and version, a failing signer, and one whose key cannot be an issuer, through both the async (`Local` and `Sendable`) and the sync signer traits.

Outside the `conformance` and `test_utils` features, `verify`, `sign` and `sign_sync` are the only public constructors of `Verified<T>`, and all three check the signature. The digest is taken from the same bytes the signature covers, so nothing re-encodes a payload to identify it. A `Verified<T>` computes it once, at verification, and keeps it: the value is immutable, and a backend looks digests up on every step of a search. It shares its `Signed<T>` in an `Arc`, as `Certificate<W>` does, so a store hands out certificates without copying their bytes; `VerifiedCertificate<W>` shares its `Verified<T>` the same way, so a batch clones for the price of reference counts. `Verified::assume`, behind `keyhive_crypto`'s `unchecked` feature, lets `test_utils::assume_verified` build fixtures without paying for signing; `conformance` turns `unchecked` on. With either feature enabled the witness therefore proves nothing, so enable them only from dev-dependencies. One scenario goes through `sign_sync` for every certificate so the shortcut cannot hide a discrepancy.

`Signed<T>` equality is by issuer, bytes _and_ signature. RFC 8032 signing is deterministic, so one key signing one payload twice yields equal values. A signer that picks its nonce another way produces a different, equally valid signature: a different `Signed<T>` with the same digest. A `Keyline` set is keyed by digest, so it holds such a pair as one certificate; the `second_signature_is_the_same_certificate` scenario pins this.

These two types live in `keyhive_crypto::verified`, with `Encode`, `Decode` and `StreamDecode` for the wire frame above. `keyhive_crypto::signed`'s serde-based `Signed<T>` is still what `keyhive_core`'s other signed types use; the codec migration moves them over.

## The `Keyline` Trait

```rust
pub struct Version(u64);                     // local to one store, opaque, monotone
pub struct Versioned<T> { pub version: Version, pub value: T }
pub type Query<'a, F, T, E> = <F as FutureForm>::Future<'a, Result<Versioned<T>, E>>;

pub trait Keyline<F: FutureForm> {
    type RetentionWatermark: Encode + Decode;
    type Error: core::error::Error;

    fn version(&self) -> F::Future<'_, Result<Version, Self::Error>>;
    fn insert(&self, batch: Vec<VerifiedCertificate<Self::RetentionWatermark>>)
        -> F::Future<'_, Result<Version, Self::Error>>;

    fn contains(&self, cert: CertificateId) -> Query<'_, F, bool, Self::Error>;
    fn get(&self, cert: CertificateId) -> Query<'_, F, Option<Certificate<Self::RetentionWatermark>>, Self::Error>;
    fn certificates(&self) -> Query<'_, F, Vec<Certificate<Self::RetentionWatermark>>, Self::Error>;
    fn revocations_of(&self, delegation: Digest<Delegation>) -> Query<'_, F, BTreeSet<Digest<RevocationId>>, Self::Error>;
    fn delegations_to(&self, subject: Id, audience: Id) -> Query<'_, F, BTreeMap<Digest<Delegation>, (Id, Delegation)>, Self::Error>;
    fn effective_power(&self, subject: Id, audience: Id) -> Query<'_, F, Option<Power>, Self::Error>;
    fn members(&self, subject: Id) -> Query<'_, F, BTreeMap<Id, Power>, Self::Error>;
    fn is_live(&self, delegation: Digest<Delegation>) -> Query<'_, F, bool, Self::Error>;
$1    fn subjects(&self) -> Query<'_, F, BTreeSet<Id>, Self::Error>;
    fn closure(&self, subject: Id) -> Query<'_, F, Vec<Certificate<Self::RetentionWatermark>>, Self::Error>;
    fn digest(&self) -> Query<'_, F, Digest<CertificateSet>, Self::Error>;
}
```

| Item                 | Meaning                                                                                                                         |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `RetentionWatermark` | The `retain` watermark type. Evaluation never reads it. A backend that does not care picks `()`.                                |
| `Error`              | What the backend's storage can fail with. `Infallible` in memory.                                                               |
| `version`            | The current version, for cheap staleness checks.                                                                                |
| `insert`             | Add a batch atomically. Idempotent. Returns the version after: greater than every version read before if the batch added any. |
| `contains`           | Whether a certificate with this id is in the set. Ingest checks this before paying for signature verification.                  |
| `get`                | The certificate as received, for serving events and archives.                                                                   |
| `certificates`       | Every certificate, in id order, for archives.                                                                                   |
| `revocations_of`     | Revocations that name the delegation, covering or not. Explains a silent `citation` collision.                                  |
| `delegations_to`     | Every delegation from `subject` to `audience`, live or not, each with its issuer: what revoking `audience`'s access must name.   |
| `effective_power`    | `audience`'s effective power over `subject`: max over live routes of min along each. `None` if unreachable.                     |
| `members`            | Every `Id` other than `subject` itself with a live route to `subject`, with its effective power. The materialized view.         |
| `is_live`            | Whether `delegation` survives evaluation.                                                                                       |
$1| `subjects`           | The subject of every delegation in the set, live or not: everything the set says something about. Monotone in the set.        |
| `closure`            | The subject's [closure](README.md#what-a-replica-must-hold), in id order: what sync sends.                                      |
| `digest`             | A digest of the set, comparable across replicas. `CertificateSet` is an uninhabited marker.                                     |

Every query is defined purely in terms of the set. That is what makes the trait a backend contract: an implementation over DBSP, Postgres, or anything else is correct if and only if it gives the same answers as the reference implementation for the same set. The conformance suite (below) is how a backend shows that.

The trait is shaped for those backends, not for the in-memory one. A database answers with I/O, so every method returns a future, in the `F: FutureForm` of the caller (`Sendable` or `Local`). Connections drop and transactions abort, so every method returns a `Result`. Sync and archive loading arrive in batches, and an incremental engine wants them whole, so `insert` takes a batch and applies it atomically. Every method takes `&self`: each backend owns its concurrency control, as a database has transactions and `MemoryKeyline` a lock.

Each query is atomic on its own and returns the version it read. There are no views (a consistent state shared by several queries): no lock or transaction ever leaves the store, so callers have no rules to follow to avoid deadlocks, and a database backend holds no connection between queries. Where a caller combines queries, it does not need a view: positive queries are monotone, so a `yes` read at one version stays true; closures only grow, so a union of closures from adjacent versions is still a valid set to send. The version comes back with each answer, not from a separate call, so that a cache can never stamp an old answer as fresh. `Version` is a concrete newtype over `u64`, because every backend has one at hand (a write counter, a log position, a step), and a concrete type lets a caching layer hold versions without a type parameter.

### Insert

`insert` cannot fail on bad input: the `Verified` witness has already excluded it; it fails only if the backend's storage does. It returns the version after the batch. If the batch added a certificate, that version is greater than every version read before the call; a batch of duplicates may leave it unchanged, so duplicate gossip does not invalidate caches. The set growing does not mean an answer changed: a new certificate may be dead on arrival. A caller that must react to membership changes (to drive BeeKEM key rotation) diffs `members(subject)` before and after, serializing its inserts so that the diff is exact; an evaluator that reports deltas is a later optimization.

A duplicate is also how a silent `citation` collision shows up: an issuer who re-mints a revoked delegation without `citation` produces a certificate already in the set (`contains` is true), and `revocations_of` reports which revocations named it, so the layer above can prompt for a re-issue with `citation` set.

A revocation whose target is not (yet) in the set is stored like any other certificate and contributes nothing until the target arrives; insertion order never matters.

### `MemoryKeyline`

The reference implementation, in its own crate (`keyline_memory`), in two layers. `State<W>` is the set and a synchronous evaluator. It holds each verified certificate once, in an `Arc` (payload, signed form and digest together), and its indexes (the adjacency the search walks, and revocations by target) share those `Arc`s. It has `insert_all(&mut self)`, queries on `&self`, no async and no lock, which is what the oracles and most tests want. `MemoryKeyline<W>` puts it behind one `async_lock::RwLock` and implements `Keyline<F>` for both future forms. Queries hold the read lock for their whole evaluation, so they run concurrently; inserts mutate in place under the write lock. The lock is a leaf, taken and released inside each method and never handed to a caller, so it cannot deadlock, and `async-lock`'s `RwLock` is write-preferring, so queries cannot starve an insert. Being a separate crate, it is written against `keyline`'s public API alone, as any other backend must be. Both are generic over the watermark type `W` with no default.

`State` caches the evaluation (strata 1 and 2) in a `OnceBox`: the first query after an insert computes it, every query until the next insert that changes the set shares it, and that insert drops it. Each query then runs one search rooted at its subject. Stratum 1 is computed over every subject on the replica rather than over the queried subject's closure, so the first query after an insert costs what the whole replica costs. Structure that no query's closure contains, such as delegations an outsider roots at their own keys, is still searched. Rooting stratum 1 at the closure is a later optimization. That suits the deployment it is for, an embedded or Wasm replica holding a document's [closure](README.md#what-a-replica-must-hold), and not a relay holding many documents, which wants a backend that materializes the monotone stratum.

It is also not demand-driven. `effective_power(s, a)` materializes `s`'s whole row and indexes into it, so a point query costs what the full view costs. Magic sets would fix that, at the price of the property that makes a bottom-up evaluator safe: forward chaining from the subject never visits a fact it cannot ground, so an attacker's ungrounded structure costs nothing. A demand-driven evaluator must earn that back with the ordering obligation in [evaluation notes §7](evaluation-notes.md#7-threat-model-evaluation-cost-as-a-dos-surface). The reference implementation stays simple; a faster backend is what the trait and the conformance suite are for.

## Evaluation

Evaluation is a pure function of the set. The strata below are the canonical order the model document describes (all delegations, then all revocations, then the check), made executable: stratum 1 replays the proxy network of delegations, stratum 2 applies every revocation to it, and a query is the invocation being checked. The reference implementation is this program, with five answer-preserving shortcuts listed in `keyline_memory::state`'s docs (dropping coverage that touches no route, sharing contexts, one unexcluded pre-filter search, uncovered edges usable from the first round of the live fixed point, and `cap = power` for uncovered edges). Any faster backend must agree with it on every set.

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
- _Admin reach is composed._ `admin_reach(k, n)` is Admin standing over `n` however derived. Bob, an Admin member of `Owners`, has `Owners` in his reach and, because `Owners` is Admin over `Doc`, `Doc` as well, and every role `Owners` administers. Seniors adjudicate inside junior roles without an explicit `subject: Junior` delegation. The price is that an Admin-rooted document is in the reach of everyone who ever held Admin in the root role, so any of them can revoke the root edge and brick the document, permanently. That is accepted; see [Griefing](README.md#griefing). A last-hop ("direct") definition was rejected; see [alternatives](alternatives.md#direct-last-hop-admin-reach).
- _Admin over a document buys nothing but kill power._ Delegation is open to anyone, clamped by attenuation; membership management is Admin over the _role_. The only thing Admin over `Doc` itself gates is reach over `Doc`'s routes, so the rooting level chosen at creation decides who can destroy the document and nothing else; see [patterns, Rooting Level](patterns.md#rooting-level).
- _A query needs the subject's closure, not only its certificates._ Write `C(s)` for `s` and every node with standing over `s` in the positive graph (revocations ignored, so every node that has ever had standing). It has to be the positive graph because coverage is computed there: a closure built from live standing could miss part of a revoker's reach and keep a revoked delegation live. A query about `s` reads stratum-1 rows rooted in `C(s)`: Bob's Admin over `Members` is what lets him revoke delegations on `Doc`'s routes, so `admin_reach` must see `Members`, which is in `C(Doc)` because `Members` has standing over `Doc`. Coverage needs nothing outside `C(s)` either: the covered nodes that matter have standing over the revoked delegation's subject, which is itself in `C(s)`, so they are too. Stratum 2 is likewise grounded at one subject and ranges over `C(s)`; "per-subject" means rooted at one subject, not confined to one subject's certificates. `MemoryKeyline` computes stratum 1 over every subject on the replica, which over-approximates `C(s)` (see [`MemoryKeyline`](#memorykeyline)).
- _The route for `h` is rooted at `subject(h)`, not at the querying subject._ `route(subject, issuer, h)` lives entirely in `h`'s own subject's graph. How some other subject `S` reaches `subject(h)` is irrelevant to whether `h` is live. Supplying a role into `S` (a `{issuer: Dan, audience: Members, subject: S}` edge) gives Dan power over that supply edge (revoke it and every member loses `S` at once) but none over `Members`' roster, which never routes through him. To revoke delegations inside `Members`, `Members` must be in your reach. This holds even when Dan reaches `S` at Admin through some other role: `S` is in his reach, `Members` is not. (Checking the hop's coverage against the `S`-rooted derivation instead was considered and rejected: it would let anyone who feeds authority into a role revoke individual roster entries of that role.)
- _Both passes are the same rule._ `reaches` is `level(·, ·, ⊥, ·)` with every edge live and every cap equal to its `power`. The reference implementation is one bounded widest-path search over the composed graph, parameterized by an exclusion set; stratum 1 runs it with the empty set.
- _Both fixed points are least fixed points._ Existence (`route`, `live`) assumes a revisited node is dead, so ungrounded cycles cannot certify themselves. Caps rise from `Relay`: a live covered edge conveys at least `Relay`, because liveness found a grounded derivation that avoids its covered set, and each round raises it to `min(power, issuer's level on that derivation)`. Starting from the bottom means a cap is only as high as some grounded derivation supports. Two covered edges on each other's avoiding derivation therefore cannot lift each other, which a greatest fixed point descending from `power` would allow (the `mutually_covered_edges_cannot_lift_each_other` scenario). The ascent is finite (four levels, finitely many edges). The two are separable because existence never reads a cap.
- _Covered edges are clamped, not just gated._ A covered edge conveys at most the level its issuer holds _on a derivation that avoids the covered nodes_, not the issuer's global level. Example: Dan is an Admin of role `Mods`, which is supplied into `Doc` at Edit (so `Doc` is not in Dan's reach); Eve is a Mod (Edit over `Doc` via `Mods`) and also holds a direct Read over `Doc` from `Owners`; Eve delegates Admin over `Doc` to Frank (`h`); Dan revokes `h`. `admin_reach(Dan) = {Dan, Mods}`, so `h` is dead on the derivation through `Mods` and live on the one through `Owners`. Frank gets `min(Read, Admin) = Read`: Eve's standing as a Mod does not flow through the edge Dan revoked, while her independent Read does. Gating alone (existence via the avoiding derivation, level from Eve's global Edit) would hand Frank the very authority the revocation was about. Clamping yields the same live set and levels `≤` the gated reading everywhere: ambiguity resolves toward less authority.
- _Clamping is a relaxation of route-consistency._ The exact reading (a single derivation in which every edge's own covered set is avoided by that derivation's prefix) is a path-with-forbidden-pairs problem and is not known to be polynomial, and a reference semantics an adversary can make exponential with crafted certificates is a denial-of-service vector. `cap(h)` avoids `h`'s covered set but takes the edges it traverses as already-live facts, each justified by its own derivation. See [alternatives, route-consistent levels](alternatives.md#route-consistent-levels).
- _Negation appears once, over fully computed lower strata._ Revocations target delegations, never other revocations, so `covered` never depends on `live`. This is what makes the result independent of insertion order.
- _Coverage that touches no route is dropped._ A route for `h` transits only nodes with standing over `subject(h)`, so a covered node without such standing changes nothing, and `h` behaves as if uncovered. `MemoryKeyline` drops `h` from coverage when none of its covered nodes has that standing, so a revocation by a key with no reach over its target's subject costs storage only. It keeps the exclusion set whole otherwise, so the set still depends only on who revoked `h` and grouping still shares one context per signer set. Both oracles keep all coverage, so agreement checks that dropping changes no answer.
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

This is not a cost claim: evaluation is polynomial with small constants, and a document with 180 members answers in about a millisecond. Nor is it caused by revocations: the difficulty is entirely in stratum 1, where `subject`-as-scope means the edges usable in a subject's graph are themselves derived facts. Coverage and replay are a join and an anti-join over a finished relation. A Keyline with no revocations has the same shape.

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
Delegation:  audience ‖ subject ‖ power:u8 ‖ citation_tag:u8 ‖ citation?    power is one of L R E A
Revocation:  revoke ‖ count:bijou32 ‖ entry*
  entry:     subject ‖ len:bijou32 ‖ W
Certificate: "KH" ‖ kind:u8 ‖ version:u8 ‖ issuer:32 ‖ payload_len:bijou64 ‖ payload ‖ signature:64
             kind is D (delegation) or R (revocation)
```

In `Delegation`, `citation_tag` is `0` with no following bytes when `citation` is absent, and `1` followed by 32 bytes when present. `power` is one of the four ASCII tags. Fixed-width layouts are canonical by construction, so `decode` only has to check length, tag membership, and that each `Id` is a valid point (an invalid one is reported by field name). `0x00` is not a valid `power`, so a zeroed buffer fails to decode.

`Delegation` and `Revocation` encodings are the payloads of their frames. `Certificate` is the wire form of a signed statement: its `Signed<T>` frame. The payload length makes frames self-delimiting, so certificates can be written back to back and read with `StreamDecode`. `Certificate::decode` checks the framing only (`NotKeyhive`, `UnexpectedKind` and `UnsupportedVersion` come from the header, and an invalid issuer from the next 32 bytes, all before the payload is read) and keeps the payload as received; `Certificate::verify` decodes the payload, checks that it is canonical, and checks the signature. Encodings need not be self-delimiting, so any composite must frame its variable-length fields, as `Revocation` does. The `serde` feature also derives `Serialize`/`Deserialize` on the public types, for a caller that wants a format of its own; that is not Keyline's wire format.

`retain` is the only variable-length field, so it is the only place where canonicality is not free. `decode` enforces it with four rules:

1. Entries ascend by subject with no repeats, so a map has one ordering (`DecodeError::UnsortedKeys`).
2. Counts and lengths are [bijou32] varints, which have one encoding per number by construction: the tag byte fixes the length, and each length's range of values is disjoint from the others, so there is no overlong form to reject.
3. The input must be consumed exactly, so there is no slack to hide bytes in.
4. `W::decode` rejects a non-canonical value.

Offsets are computed with checked arithmetic, because a declared length near `u32::MAX` overflows `usize` on 32-bit targets, and a count larger than the remaining input could hold is rejected before the loop. Values below 252 take one byte, so an empty `retain` costs one byte and typical watermark lengths one each.

This is the first step of Keyhive's bespoke codec: hand-written, canonical `Encode` / `Decode` impls in `keyhive_codec`'s traits, with bijou varints for variable-length integers. Later steps may replace the hand-written impls (for example with derive macros in `keyhive_codec`); if the bytes change, every digest changes and the type's `VERSION` moves on. `Encoded<T>`, `Signed<T>`, `Verified<T>`, and the `Keyline` trait do not change. Known-answer tests pin one delegation, one revocation and one set digest, so any change to the bytes is deliberate.

## Crates

```
keyhive_codec        Encode, Decode, Encoded<T>, DecodeError. Depends on thiserror; serde optional.
      ▲
keyhive_crypto       Id, Digest<T>, Digest::of(&Encoded<T>), signable (Kind, Kinded, Signable),
                     verified (Signed/Verified over Encoded). Its serde-based Signed<T> remains.
      ▲
keyline              Id, Power, Delegation, Revocation, Certificate, the Keyline trait,
                     the conformance suite.
      ▲
keyline_memory       MemoryKeyline, the reference backend, against keyline's public API.
      ▲
keyhive_core         consumes keyline and a backend; never sees raw bytes.
```

`keyhive_codec` holds only the traits and `Encoded<T>` because the dependency direction is only right if it sits at the bottom: `beekem` will implement the same traits when it migrates, and `beekem → keyline` would be wrong. It contains no BLAKE3; hashing an `Encoded<T>` is `keyhive_crypto`'s job.

## Crate Layout and Features

```
keyline/
  src/
    lib.rs           //! model summary, naming convention, links to design/keyline/
    power.rs         Power
    delegation.rs    Delegation, its encoding and kind
    revocation.rs    Revocation, RevocationId, its encoding and kind
    certificate.rs   Certificate, VerifiedCertificate, CertificateId
    contract.rs      the Keyline trait, CertificateSet, set_digest
    test_utils.rs    Statement, deterministic ids, unsigned and signed fixtures, fuzz helpers
    test_utils/
      conformance.rs                  the cast, helpers, keyline_conformance! macro
      conformance/gen.rs              CertSet generator
      conformance/laws.rs             bolero properties
      conformance/oracle.rs           shared oracle types
      conformance/oracle/naive.rs     value-form oracle
      conformance/oracle/threshold.rs threshold-form oracle
      conformance/scenarios.rs        named cases, generic over C: Backend
  tests/
    invariants.rs    crate-wide invariants (distinct kinds)
    signing.rs       Signed/Verified with keyline payloads: signer paths, frame, forgeries

keyline_memory/
  src/
    lib.rs           MemoryKeyline: State behind an RwLock, the Keyline impl, its conformance run
    state.rs         State: storage, stratified evaluator, evaluation cache
    collections.rs   (private) Map/Set aliases: HashMap with std, BTreeMap without
  benches/
    bench_evaluate.rs
```

- `#![no_std]` + `extern crate alloc`; `#![forbid(unsafe_code)]`. `keyline`, `keyline_memory`, `keyhive_codec` and `keyhive_crypto` build for `wasm32-unknown-unknown` with `--no-default-features` (checked by `ci-no-std`). Targets without atomic compare-and-swap (e.g. `thumbv6m-none-eabi`) fail in `tracing-core`. `keyline` uses `keyhive_crypto`'s `Id`, `Digest<T>`, `signable`, `verified`, and `Verifiable`. Moving them down to `keyhive_codec`, or to a crate beneath it, would be the cleaner layering, for the same reason that put `Encode`/`Decode` at the bottom.
- `keyline` depends on `keyhive_codec` (traits, `Encoded`), `keyhive_crypto` (`Id`, `Digest`, `Kinded`, `Signed`/`Verified`, `Verifiable`, the signer traits), `ed25519-dalek` (`VerifyingKey`, `Signature`), `future_form` (the `Sendable`/`Local` form of an async signer), `bijoux` (bijou32), `tracing`, and `thiserror` 2 (`no_std`-capable, without default features). Every version is set once, in the root `[workspace.dependencies]`. Optional: `serde`, `arbitrary`, and, for the test features, `bolero` and `sha2`. `keyline_memory` depends on `keyline`, `keyhive_codec`, `keyhive_crypto` and `tracing`.
- `std` feature (default on): the `std` features of `tracing` and `thiserror`, and in `keyline_memory` `HashMap`/`HashSet` for the evaluator's maps (`BTreeMap`/`BTreeSet` without it).
- `conformance` feature (`keyline`): the fixtures and the conformance scenarios, without `std`, plus `ed25519-dalek/hazmat` for the fixture that signs with a non-standard nonce. Enough for a backend to run every scenario in a `no_std` build.
- `test_utils` feature: `conformance` plus the generator, the oracles, the `bolero` laws and property tests, and `serde` (so the serde round-trip tests run wherever the full suite does). Implies `arbitrary`, which implies `std` (`derive(Arbitrary)` expands to a `thread_local!`). Both features let `assume_verified` build a `VerifiedCertificate` without a signature check, so enable them only from dev-dependencies. `keyline_memory`'s `test_utils` turns on `keyline/test_utils`.
- Testing is split by feature, and no configuration silently skips the evaluator. `cargo test -p keyline_memory` runs every conformance _scenario_ against `MemoryKeyline`; `--no-default-features` runs the same set against the `no_std` build, since the crates never link `std` and only the harness does; `--features test_utils` adds the `bolero` laws. `cargo test -p keyline` runs the codec, crypto and oracle tests. `nix run .#ci-test` (menu: `test:host`) runs the whole workspace with `test_utils`, as hosted CI does; `ci-no-std` runs the `no_std` set.
- `serde` feature: derives `Serialize`/`Deserialize` on the public types, for a caller that wants a format of its own. Not Keyline's wire format.
- No `parallel` feature yet. If one comes, it is native-only (`rayon`); Wasm stays single-threaded because `wasm-bindgen-rayon` needs `SharedArrayBuffer`, COOP/COEP headers, and a worker pool. The evaluator is written so the independent units (admin reach per issuer, route search per covered certificate) are plain iterators.

The crate follows the workspace's `beekem` conventions: `foo.rs` + `foo/`, manual impls instead of `derivative`, `tracing` in every configuration with its `std` feature behind ours. Library types take no defaulted type parameters: a backend states its watermark type.

Instrumentation: `insert` logs each certificate at `debug` (kind, endpoints, whether the revocation target is known, duplicates); `evaluate` is a `debug` span reporting set size, contexts, live/dead counts and clamped edges; the two fixpoint loops emit a `trace` line per round; queries are `trace` spans. `Signed::verify` logs failures at `debug` with the digest. Nothing is logged at `info` or above: the crate has no events a deployment must see.

## Conformance Suite

Every backend runs the same tests against `impl Keyline<F>`. The suite is exported behind `test_utils` as plain functions generic over a `Backend`: the store type, the future form it is used at, and a `block_on` that drives its futures. Scenarios and laws talk to the store through a synchronous `Harness`, which also checks the version contract on every call: each answer reports the version the last insert returned (the suite runs nothing concurrently), and an insert that adds a certificate returns a greater version. `Polled<K, F>` is the `Backend` for a store whose futures are ready on their first poll, which needs no executor and runs without `std`; a backend that does real I/O implements `Backend` with its own executor. One macro call writes a `#[test]` for each scenario and law:

```rust
mod conformance {
    use future_form::Local;
    use keyline::test_utils::conformance::Polled;

    keyline::keyline_conformance!(Polled<my_crate::MyKeyline<()>, Local>);   // as keyline_memory does, at both forms
}
```

_Generator._ `test_utils::conformance::gen::CertSet` draws from a pool of eight deterministic identities:

- a root edge per subject (one to three), at Admin or Edit;
- up to ten free-form delegations over any node in the pool, so some land on roles and some are ungrounded;
- at most one planted shape that random wiring rarely produces: the clamping shape (a role supplied into a subject, an admin of it, a member of it with an independent delegation over the subject, that member's delegation to a third party, and the admin's revocation of it); two clamps chained so that each covered edge lies on the other's avoiding derivation; a role chain three deep, half the time all at Admin with a revocation that relies on reach composed through all three roles; or the clamping shape inside a role supplied into the subject;
- occasionally a revocation of a delegation that is not in the set;
- up to four revocations naming delegations already present, a third of them by the target's issuer and a third by its audience, each carrying zero to two retention watermarks;
- up to two re-issues past a revocation, and sometimes a revocation of a re-issue.

Random 32-byte keys would give nothing but ungrounded edges.

_Oracles._ Two transcriptions of the program, sharing no code with each other or with any backend. `oracle::naive` runs the value form above as Jacobi iteration over tuple maps, with caps as a second fixed point. `oracle::threshold` runs the threshold form rule for rule, with one context per covered certificate and no cap fixed point. Both keep only `(issuer, revoke)` from each revocation, so neither can read a watermark. A backend must agree with both, and a law with no backend (`oracles_agree`) checks that the two forms in this document say the same thing. Both share their inputs with every backend (`Delegation::digest`, `Power`'s order, the generator), so bugs there are the unit tests' job; a known-answer test pins one delegation's encoding and digest. With the chained-clamp shape in the generator, a backend whose caps are a greatest fixed point fails the threshold law within CI's iteration budget.

_Laws_ (`bolero`, over generated sets):

- Oracle agreement: `members` over the pool and `is_live` for every delegation agree with `oracle::naive` (without revocations, and with) and with `oracle::threshold`.
- Order independence: a uniformly shuffled order and the reversed order both give the same `digest`, the same levels over the pool, the same live set, and the same `members`.
- Idempotence: re-inserting every certificate adds nothing and changes nothing.
- Revocations only deny: for each revocation in a set, the set without it has levels `≥` everywhere and a live set `⊇`.
- Revocation by a party is total: a revocation signed by its target's issuer or audience kills the target.
- `retain` is inert: emptying every `retain` map changes no answer.
- Digest identifies the set: permutation-invariant; dropping any non-duplicated certificate changes it.
- Query consistency: `effective_power(s, s) = Some(Admin)` for every `s`; `members(s)` is `effective_power(s, ·)` minus `s`; `contains` holds for every inserted certificate and fails for one left out; `revocations_of(h)` is exactly the revocations in the set with `revoke = h`, whether or not `h` is present.
- `positive_power` is stratum 1: it agrees with `oracle::naive`'s reach over the set without its revocations, and adding any certificate never lowers it.
- Listings match the set: `certificates` lists exactly the set in id order, `get` finds every member and nothing else, `delegations_to(s, a)` is exactly the set's delegations from `s` to `a`, and `subjects` is exactly the set of delegation subjects.
- The closure is sufficient: a store holding only `closure(s)` agrees with the full store on `members(s)`, `positive_power(s, ·)`, and the liveness of every delegation about `s`; dropping a certificate never grows a closure.
- Batches equal singles: one batch, or two split anywhere, answer as one certificate at a time.
- Interleaving is invisible: querying after every insert, then finishing, answers as building the set fresh. This is the law a cache that is not reset correctly fails.

Every law builds its backend through a helper that checks each `insert` reports whether its certificate was new, and through the `Harness`, which checks versions. A unit test checks that the macro lists every scenario and law. At `W = ()` a `retain` entry carries a subject but no watermark bytes, so `MemoryKeyline` re-runs both oracles, the inert-`retain` law, and digest identity with `W = Vec<u8>`.

_Scenarios._ Named cases derived from the [edge-cases] findings, the model document and the patterns, including:

- rotation escapes a frozen admin reach while the revocations made in office stand;
- concurrent mutual revocations both take effect, and in an Edit-rooted document an root-role duel still kills both memberships signed at creation;
- ex-admin revocations cover only the frozen admin reach;
- an root-role admin of an Admin-rooted document can revoke the root edge, while an Edit-rooted document's root edge is irrevocable;
- revocation by the issuer and revocation by the audience are total; a non-admin's revocation is confined to their own node;
- `citation` re-issue heals, reviving everything downstream under its original digest;
- membership carries whatever the role reaches, including documents added later;
- an Admin member of a role that holds Admin over another role revokes delegations inside it without an explicit delegation;
- supplying a role into a document gives power over the supply edge and none over the roster, and a role's admin cannot revoke the supply into it, because the audience is not on a route;
- coverage is the union over every revocation of a delegation;
- the patterns hold as described: pinning, a caretaker, and the Steward (rotating the officers leaves former officers nothing);
- a covered edge conveys only what its issuer holds on the avoiding derivation (the `Mods` example), and two covered edges on each other's avoiding derivation cannot lift each other's level;
- the gift-cert attack from the [evaluation notes](evaluation-notes.md#gift-cert-scenario): an unconsented delegation into an attacker's ladder, which removing the attacker takes out of the document, which a same-key re-add revives and a fresh key does not (though supplying the ladder again under any key regrounds the attacker through it), and which the victim severs by revoking it as audience;
- a second valid signature over a certificate already present is the same certificate;
- two revocations differing only in `retain` are two certificates with the same effect;
- a document's closure holds every node that has had standing over it (a revoked member included), and nothing about unrelated subjects;
- `delegations_to` names dead delegations as well as live ones.

_Negative._ A revocation naming an unknown digest is new and changes no answer. A duplicate adds nothing, and `revocations_of` reports what named it.

## Integration

`keyhive_core` evaluates membership with Keyline; nothing else decides who may do what. The shape:

- _The store._ `Keyhive` holds a `K: Keyline<F, RetentionWatermark = ContentHeads<T>>` together with the lock that serializes its writes, so that a fork shares both. Every membership read (`members`, transitive members, standing, `reachable_docs`) is a Keyline query, with no conversion at the boundary: `keyhive_core` identifies principals by `keyhive_crypto::id::Id`, as Keyline does.
- _Creation._ `generate_group` and `generate_doc` sign the subject's root edges (`Admin` to each creator) with the fresh subject key, then discard it.
- _Grants._ `add_member` checks the issuer's `effective_power` (refusing a delegation above it, `AddMemberError::Escalation`), signs a `Delegation` with the active signer (an `AsyncSigner`, so WebCrypto keys work), and inserts it.
- _Revocation._ `revoke_member` revokes each `delegations_to(resource, member)`: every one if the issuer holds `Admin`, otherwise those it issued. Each revocation's `retain` holds the content heads of every held document the resource is or stands over, as the application last set them with `set_content_heads`; a document with none set is left out. A member with no delegation from the resource is refused (`NotADirectMember`): it reaches the resource through a group or document, which is what to revoke. With `retain_all_other_members`, the same batch re-issues from the revoker the delegations the removed member issued, at no more than the revoker's own power (_adoption_). A grant or adoption that would repeat a revoked delegation cites that revocation, and the latest revocation of each re-issue in turn.
- _Sync._ Events carry `Certificate<ContentHeads<T>>`; ingest is `verify`, then `insert`.
- _BeeKEM._ A document's readers are its Keyline members at `Read` or above whose prekeys this replica holds. Every local write reconciles each held document's tree with its readers under the insert lock: an add for each new reader whose prekeys this replica holds, a remove for each lost reader the tree holds, each citing the certificate it routes through. A CGKA operation is accepted only from a principal with the standing it needs. A replica knows a document from its authorized CGKA operations, and builds its tree only once invited; a relay stores the operations without one.

## Deferred

- Whiteout: `keyhive_core` records content heads (`ContentHeads<T>`) in `retain`, but deciding what they _mean_ for the revoked key's content is a content-layer question. That includes the policy for documents the map does not name, and how to combine concurrent revocations of one delegation.
- The bespoke codec.
- Incremental evaluation and memoization: only once the conformance suite pins semantics.


<!-- Links -->

[Computation]: README.md#computation
[bijou32]: https://github.com/inkandswitch/bijou
[edge-cases]: edge-cases.md
[gdp]: https://kataskeue.com/gdp.pdf
[keyline]: README.md
