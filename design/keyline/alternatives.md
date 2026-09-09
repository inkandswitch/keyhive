# Keyline: Roads Not Taken

Design choices that were considered and rejected, with the reason and the condition under which the decision should be reopened. Each entry is short; where a longer argument exists it is linked. The point of the file is that the next person to have one of these ideas finds the reason in one place before re-deriving it.

## Certificate Shape

### A `sub` (jurisdiction) field on `Revocation`

_Proposal._ `{iss, sub, revoke}`: the cut applies only on routes through `sub`, not through every node in the issuer's service record. Earlier drafts called the field `from`, then `via`.

_Would buy._ Narrow denial with one key (ban in room A, keep in room B). Legibility: the certificate names where the act was exercised. Symmetry with `Delegation`. A one-node exclusion set per revocation.

_Rejected because._ Rotation would re-sign the deny list. A cut pinned to `Members` does not cover `Members′` after rotation, so every standing denial must be re-issued after every rotation, forever. Under record scoping a surviving admin's record grows as they are re-rostered, and their old cuts follow automatically; the griefer's record froze, so theirs do not. The explicit field taxes the honest admin on the routine path (rotation is the recommended hygiene) to buy flexibility on a rare one. It also introduces an inert-by-mistake state (naming a node the target never routes through) that record scoping cannot produce, and it is the narrower of the two denials where the design resolves ambiguity toward less authority. Narrow denial is available today by signing with a capacity key per role administered.

_Reopen if._ Narrow denial turns out to be common. The compatible extension is `sub: Option<Id>` with `None` meaning the whole record; `None` has one encoding, so the [`seen`](#a-random-nonce-instead-of-seen) invariant carries over. Long form: [edge-cases, `via` on revocations](edge-cases.md#via-on-revocations--collapsed-into-the-issuer).

### A random nonce instead of `seen`

_Proposal._ Replace `seen: Option<Digest<Delegation>>` with random bytes so an issuer need not know which revoked certificate it is re-issuing past.

_Would buy._ No silent-collision UX; no dependency on having synced the revocation.

_Rejected because._ It flips the fail direction. Two accidental issuances of one grant become two independently live certificates; revoking one leaves the other; a missed duplicate is a lingering grant. With `seen`, identical re-issue collides to one hash (payload and, Ed25519 being deterministic, signature), one revocation covers every copy, and an unaware re-issue silently does not take. The collision is detectable: `insert` returns `false` and `revocations_naming` reports what named the duplicate. Long form: [edge-cases, `nonce` vs `seen`](edge-cases.md#nonce-vs-seen--seen-won-on-fail-direction) and [implementation, why `seen`](implementation.md#why-seen-and-not-a-nonce).

_Reopen if._ Never on its own merits; only if a use case needs many live copies of one grant, which would be a different feature.

### A `proof` field on `Delegation`

_Proposal._ Each delegation names the certificate(s) justifying it, as UCAN and today's `keyhive_core::Delegation` do.

_Would buy._ Certificate-local verification: check a chain without holding the set.

_Rejected because._ It makes a certificate's meaning depend on its issuer's sync state — two replicas producing "the same" grant with different proofs — and turns healing into re-issuance: a severed subgraph cannot re-energize as the same certificates, because the proofs are dead. Chain discovery by the verifier (SDSI) gives late binding, redundant routes, order independence, and healing with provenance. Witness hints on the transport recover the verification shortcut without putting the route in the certificate.

_Reopen if._ Verification without the set becomes a hard requirement (e.g. a constrained verifier that cannot hold a subject's certificate set). Even then, prefer transport-level witnesses.

### A `from` (jurisdiction) field on `Delegation`

_Proposal._ Name the capacity a delegation is exercised in.

_Rejected because._ Every job it did is an arrangement of nodes: scoping is `sub`, acting in a capacity is a dedicated key per capacity, pinning is a sub-scoped intermediary, jurisdiction-narrow denial is signing with the narrow key. An optional field whose absence aliased "the issuer" produced two encodings for one act, two hashes, and a revocation that killed one twin and missed the other. Long form: [edge-cases, `from` on delegations](edge-cases.md#from-on-delegations--eliminated).

_Reopen if._ A capacity cannot be expressed as a node. None found so far.

### Revocations that target revocations

_Proposal._ Let `revoke` name a `Digest<Revocation>` so a mistaken denial can be undone.

_Rejected because._ It starts the regress (who may revoke the un-revocation?), requires an authority rule for un-revokers, and needs an ordering to settle revoke/un-revoke/re-revoke races — causal metadata or merge-order dependence. Repair is by re-grant with `seen`: access returns because live authority signed something new, never because a denial was un-applied. Declining the feature costs one workflow and deletes the tower. Long form: [README, Revocations Cannot Be Revoked](README.md#revocations-cannot-be-revoked).

_Reopen if._ Never; the invariant "no merge may un-apply a denial" depends on it.

### An adoption certificate

_Proposal._ A third kind, `{iss, adopt: Digest<Delegation>}`: the named delegation is live if the adopter has live authority at or above its `can` over its `sub`, regardless of the original issuer's standing. Keeps the original certificate alive under a new sponsor.

_Would buy._ Persistence of a grant past its issuer's removal while preserving the original's hash and provenance.

_Rejected because._ Re-grant already gives persistence from the surviving side, and everything below the re-granted node revives by late binding with provenance intact. Adoption would preserve one certificate's hash at the cost of a third certificate kind and a second liveness rule. Long form: [README, Persistence Past Removal](README.md#persistence-past-removal).

_Reopen if._ Downstream references to a specific delegation hash (rather than to a key) become common enough that re-issuing changes something observable.

## Semantics

### Issuer-side durability (`durable` flag, embedded witness, proof snapshot)

_Proposal._ Let a delegation stay live after its issuer loses standing, by recording that the issuer was authorized at issuance.

_Rejected because._ Without a clock the only timeless fact is whether the issuer was _ever_ authorized, and that lets a booted issuer mint new durable grants afterwards; "before the boot" and "after the boot" are the same bits. The ex-admin sharp edge is tolerable because it is deny-only; this would be the same edge with grant power. Distinguishing the two needs the causal metadata the design avoids. Long form: [README, Persistence Past Removal](README.md#persistence-past-removal).

_Reopen if._ Causal metadata enters the system for other reasons (see whiteout). Then revisit alongside [per-issuer causal streams](#per-issuer-from-causal-streams-option-2).

### Delegator-independence (ocap's reference semantics)

_Proposal._ Dropping your standing leaves the grants you issued intact, as dropping an ocap reference leaves the copies intact.

_Rejected because._ It depends on a moment of transfer that a weakly consistent system without finality does not have. The two timeless replacements are "issuer ever authorized" (independence recovered, fail-open) and "issuer currently authorized" (issuer-recursive, fail-closed). Keyline takes the second for grants and the first for revocations. Long form: [README, Intuition & Lineage](README.md#intuition--lineage).

_Reopen if._ Never in this consistency model.

### Admin-only delegation

_Proposal._ Only holders of `Admin` over `sub` may issue delegations; edges issued by `Read`/`Edit`/`Relay` holders are never live.

_Would buy._ Every roster change is an admin act; a cleaner governance story.

_Rejected because._ It pushes people toward key-sharing when they want to hand a document to a second device or an ephemeral worker, which is strictly worse than an attenuated grant. Attenuation already clamps what a non-admin can hand on. Admin is required for third-party revocation reach, where the asymmetry is justified by fail-closed. Decided in [implementation, Delegation](implementation.md#delegation).

_Reopen if._ A deployment needs roster changes to be an audit-visible admin act; that is a policy the layer above can enforce without changing the semantics.

### Path-scoped revocation validity ("epochal permanence", option 1)

_Proposal._ A revocation is valid only while its issuer stands on the route it cuts; retraction of the issuer's standing retires their cuts.

_Rejected because._ It violates the invariant that no merge may un-apply a denial: resurrection windows, retraction as a resurrection lever, and a perpetual deny-list re-signing cycle. It is not a stable point; it decomposes into the two designs it tried to sit between. Long form: [edge-cases, Option 1](edge-cases.md#option-1-path-scoped-revocation-with-retraction-strata-epochal-permanence).

_Reopen if._ Never.

### Per-(issuer, `from`) causal streams (option 2)

_Proposal._ Each issuer keeps a causal stream per capacity; revocation validity is judged against the stream's order, so "before the boot" and "after the boot" become distinguishable.

_Would buy._ Bounded backdating; issuer-side durability becomes sound; whiteout gets the metadata it needs.

_Rejected because._ Temporal evaluation over historical graphs; causal metadata on every certificate; the timeless core dies, and with it the "set digest is a perfect cache key" property. Kept as the fallback shape. Long form: [edge-cases, Option 2](edge-cases.md#option-2-per-issuer-from-causal-streams).

_Reopen if._ Whiteout forces causal metadata into the system anyway. Then this is the design to adopt rather than bolting ordering onto the timeless one.

### Subtract-first evaluation

_Proposal._ Delete revoked edges from the graph, then compute reachability. One pass.

_Rejected because._ Revocations would then affect each other's authority, and the result would depend on merge order: applying `r1` (Brooke cuts Bob) before checking `r2` (Bob cuts a grant) rejects `r2`; the reverse order lands it. Stratification computes service records where no revocation can see any other. Long form: [README, Why the Strata Are Mandatory](README.md#why-the-strata-are-mandatory).

_Reopen if._ Never; this is a correctness requirement, not a trade.

### Greatest fixed point on cycles

_Proposal._ On revisiting a node during route search, assume live.

_Rejected because._ Ungrounded cycles become self-certifying: a ring of keys delegating to each other with no root edge would grant themselves authority. Least fixed point (assume dead on revisit) is the only sound choice. Noted in [README, Cost](README.md#cost).

_Reopen if._ Never.

### Gated-only levels on covered edges

_Proposal._ A covered delegation is live iff some derivation to its issuer avoids the covered nodes, and then conveys `min(can, issuer's global level)`. The avoiding derivation decides existence only.

_Would buy._ One widest-path pass for levels; exclusion-set searches return a boolean.

_Rejected because._ It leaks the authority the cut was about. If `B` is Admin over `Doc` through role `Mods` and separately Read through `Owners`, and a `Mods` admin revokes `B`'s grant to `C`, the gated reading hands `C` Admin: `B`'s Mod standing flows through the very edge the Mod admin cut, because only existence consulted the exclusion set. Clamping the edge to the level reachable on the avoiding derivation gives `C` Read, yields the same live set, and is `≤` gated everywhere. Long form: [implementation, Evaluation](implementation.md#evaluation).

_Reopen if._ Never on its own merits; it is strictly more permissive than clamping for the same cost class.

### Route-consistent levels

_Proposal._ Evaluate exactly: a derivation is valid iff, for every edge on it, that derivation's own prefix avoids the edge's covered set; effective access is the max over valid derivations of the min along each.

_Would buy._ No relaxation at all; the model's prose ("dead on every route that transits…") taken literally.

_Rejected because._ Validity of a step depends on the whole prefix, so the search state is a node _and_ the set of nodes visited. This is a path-with-forbidden-pairs problem (the unordered form is NP-complete) and no polynomial algorithm is known for the ordered form either. A reference semantics whose cost an adversary controls by crafting certificates is a denial-of-service vector. Clamping ([implementation, Evaluation](implementation.md#evaluation)) keeps per-edge exclusion sets but treats the edges a derivation traverses as already-live facts, which makes it a pair of polynomial fixed points.

_Reopen if._ A polynomial algorithm for the ordered forbidden-pairs case turns up, or the graphs in practice are small enough that the exact search is bounded and the difference is observable.

## Crate

### Async `Keyline` trait

_Proposal._ `async fn` on the trait via `future_form`, so reads can await.

_Rejected because._ The evaluator does no I/O; async buys an `F` parameter and `Send`-bound ceremony for nothing. Concurrency comes from the wrapper: `keyhive_core` holds the implementation behind a `RwLock`, and N readers hold the read guard and call `&self` methods in parallel.

_Reopen if._ A backend needs to page the certificate set in from storage during evaluation (e.g. IndexedDB). Even then, consider making the backend load eagerly and keep the trait synchronous.

### Signature verification inside `insert`

_Proposal._ `Keyline::insert` verifies the Ed25519 signature and rejects bad certificates.

_Rejected because._ It duplicates verification `keyhive_core` does at ingest and puts `ed25519-dalek`'s verifier in the evaluator's dependency set. `insert` takes a `Verified<Certificate>` witness whose only public constructor is `Signed::verify`, so unchecked certificates cannot reach the set. Decided in [implementation, `Verified<T>`](implementation.md#verifiedt).

_Reopen if._ A backend is used without `keyhive_core` in front of it and needs to be safe standalone. Then add a verifying wrapper, not a trait change.

### Splitting `keyline` into a traits crate and an implementation crate

_Proposal._ `keyline_core` (types, trait, semantics) and `keyline_memory` (the reference evaluator).

_Rejected because._ One trait plus one implementation in one crate is the minimum that still lets a second backend exist. The types and normative semantics must live with the trait regardless, and the in-memory evaluator has no dependencies worth isolating. The conformance suite, exported behind `test_utils`, is what actually lets a second backend prove itself.

_Reopen if._ A second backend appears.

### Parallel evaluation with `rayon`

_Proposal._ Fan out stratum-1 record computation and per-covered-certificate route searches across threads.

_Rejected for now because._ Wasm is a first-class target and `wasm-bindgen-rayon` needs `SharedArrayBuffer`, COOP/COEP headers, and a worker pool. The evaluator keeps the independent units as plain iterators so a native-only `parallel` feature can be added without restructuring.

_Reopen if._ Native evaluation cost becomes a problem on real graphs.

### `minicbor` as the interim encoding

_Proposal._ Canonical CBOR for the certificate types, hashed with BLAKE3.

_Rejected because._ Keyhive is moving to a bespoke codec after this branch; adopting a second interim encoding would mean two migrations. A fixed-width placeholder needs no dependency and is replaced wholesale when the codec lands. Decided in [implementation, Encoding](implementation.md#encoding).

_Reopen if._ The codec is delayed indefinitely.
