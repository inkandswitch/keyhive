# Keyline

Keyline describes the core authority graph of Keyhive: who can do what, to which subjects, and on whose authority. It is the substrate that the rest of Keyhive (membership, CGKA, encryption) hangs off of.

The adversarial scenarios that shaped the revocation rule are worked end to end in [edge-cases](edge-cases.md).

## Design Goals

Keyline is a *state-based CRDT*. Any two replicas that have seen the same set of delegations and revocations compute the same authority graph, regardless of the order they received them in. There is no sequencing, no consensus, and no "current" version — just a grow-only set of signed statements, merged by union. This buys us the usual local-first properties: replicas can be offline indefinitely, sync in any order over any transport, and never conflict.

## Nodes

All nodes in the graph are Ed25519 verifying keys. At this level there is _no distinction_ between individuals, groups, and documents; they are all merely keys that can appear as the issuer, source, or target of a delegation. This uniformity is deliberate. Higher layers of Keyhive assign meaning to particular keys (this one is a person, that one is a document), but the authority graph itself doesn't care. A delegation from a "document" to a "group" and a delegation from one "person" to another are the same kind of edge, checked the same way.

## Delegations

A delegation is a signed statement that grants one node some level of access over a subject, on the authority of another node. Concretely:

| Field     | Type                             | Notes                                                            |
|-----------|----------------------------------|------------------------------------------------------------------|
| Magic     | bytes                            | Magic bytes / schema identifier                                  |
| Issuer    | Ed25519 verifying key            | The key that signs this delegation                               |
| From      | Ed25519 verifying key            | Whose authority is being extended; the edge's anchor            |
| To        | Ed25519 verifying key            | The recipient of the delegated authority                         |
| Subject   | Ed25519 verifying key            | What the authority is *about*                                    |
| Can       | `Relay \| Read \| Edit \| Admin` | Access level                                                     |
| Signature | Ed25519 signature                | Over all of the above                                            |

All four keys are always explicit, even in the common cases where `From = Issuer` (delegating one's own authority) or `Subject = From` (a delegation about the anchor itself, e.g. a membership). An earlier draft made `From` and `Subject` optional with those defaults, and it was a bug: `{from: None}` and `{from: issuer}` would mean the same thing but hash differently, so one semantic edge could exist as two certificates — and a revocation by hash would kill one twin and miss the other. Required fields make certificates canonical by construction; the few extra bytes are absorbed by batching and compression.

A delegation reads: *Issuer asserts that To may exercise Can over Subject, by way of From's authority.* Useful special cases, now directly legible from the fields:

- `from = iss`: the issuer delegates their own authority.
- `sub = from`: a *constitutional* edge — membership in the anchor itself.
- `iss = from = sub`: a root edge (see [Root Edges and the Apex][apex]).

### Why `from` is One Hop, Not a Path

`from` is an *anchor*, not a route. It names which single authority the issuer exercises (disambiguating when they hold several) and whose jurisdiction the resulting edge sits in — both inherently single-valued. How the issuer reaches `from`, and how `from` reaches the subject, is the verifier's reachability search.[^hop-rejected]

[^hop-rejected]: A `Vec` of hops was considered and rejected: it would be a partial proof chain, reimporting the brittleness the [no-proof design][no-proof-field] removes. If the named path died while another live path existed, the delegation would either die with it (forfeiting redundant-path resilience) or survive it (making the extra hops advisory data that pointlessly perturbs the hash). Path information for verification speed or audit is welcome as unsigned transport-level hints — it does not belong in the certificate.

### Access Levels

`Can` is a totally ordered ladder:

```
Relay < Read < Edit < Admin
```

| Level | Grants                    | Notes                                                                                  |
|-------|---------------------------|----------------------------------------------------------------------------------------|
| Relay | Sync and relay ciphertext | Cannot decrypt; makes untrusted relays (e.g. [Subduction]) first-class citizens of the graph |
| Read  | Decrypt content           |                                                                                        |
| Edit  | Write new content         |                                                                                        |
| Admin | Manage membership         | Delegate and revoke                                                                    |

## Revocations

A revocation removes a previously issued delegation, identified by hash:

| Field     | Type                    | Notes                                     |
|-----------|-------------------------|-------------------------------------------|
| Magic     | bytes                   | Magic bytes / schema identifier           |
| Issuer    | Ed25519 verifying key   | The key that signs this revocation        |
| From      | Ed25519 verifying key   | The jurisdiction the denial is exercised in |
| Revoke    | `Hash<Delegation>`      | The delegation being revoked              |
| Signature | Ed25519 signature       | Over all of the above                     |

Revocations don't undo history — the revoked delegation remains in the set — they add a denial that the authority check takes into account. This is what keeps the whole structure a state-based CRDT: both delegations and revocations are add-only, and merging is set union.

Revocations come in two species, distinguished by who signs them:

- *Tombstones* — self-authorized, global in effect: a *retraction* (`iss = delegation.iss`, unmake what you signed) or a *renunciation* (`iss = delegation.to`, shed what names you). Validity is signature equality; no graph check. The delegation is dead on every route, forever.
- *Blocks* — third-party, jurisdiction-scoped in effect: `From` names a jurisdiction, and the target delegation can no longer derive liveness through any route containing it. A block is a *deep cut*: it may target a certificate anchored far below the jurisdiction it is exercised in.

Who may issue a block, and what its downstream effects are, is covered under [Revocation Semantics] below.

## Graph Semantics

Delegations form a directed graph: each one is an edge carrying an access level. Authorization is a *reachability* question over that graph.

### No Proof Field

Note that there is no "proof" field on delegations or revocations. A delegation doesn't name the chain that justifies it — it merely asserts an edge, and justification is computed at check time.

This means that at authorization-checking time, `to` gains access to `subject` as long as there is *some* unbroken (unrevoked) path between the subject and `to`, where every hop is validly signed and every issuer along the path themselves has (sufficient) control over the subject.

A few consequences follow:

- *Late binding.* A delegation issued before its issuer had authority becomes effective the moment the issuer gains it, and stops being effective if the issuer loses it. Edges are facts; authority is derived.
- *Redundant paths are a feature.* If access is delegated to the same key via two chains and one chain is revoked, the other keeps working. There's no single brittle proof to invalidate by accident.
- *Order independence.* Because justification is recomputed from the full set, it doesn't matter in what order a replica learned the edges — exactly the property the CRDT framing demands.

### Edges are Certificates

A drawn edge underdetermines the graph. Two delegations with identical `from`, `to`, `subject`, and `can` but different issuers are distinct certificates with distinct hashes and distinct fates. Each delegation's liveness hangs on *its own issuer's* standing (see [Liveness]), so "the edge from Members to Carol" may denote several certificates, some live and some dead, at the same moment. The issuer is part of an edge's identity.

### Liveness

A delegation is *live* iff:

1. it has not been tombstoned (retracted or [renounced][renunciation]), and
2. its issuer currently reaches the subject through `from` with sufficient authority, using only live delegations, along a route avoiding every jurisdiction validly [blocked][revocation semantics] for this delegation.

The recursion is grounded at root edges: delegations anchored at (and signed by) the subject itself, which are live unless revoked. Authority is then derived monotonically outward from the roots.

Block validity is evaluated separately, against the *revocation-free* graph (see [Permanence]); the liveness recursion then treats the set of valid denials as fixed. Two strata, no negation inside either, unique fixed point.

Because condition 2 is evaluated at check time, liveness is *late-bound*: a delegation dies implicitly the moment its issuer loses standing, and springs back to life if the issuer regains it. Nothing about an individual certificate records whether it is live — liveness is a property of the certificate *in the context of the full set*.

```
        ┌─────────┐
        │ Subject │ (e.g. a document key)
        └────┬────┘
             │ Admin                • Alice reaches Subject with Admin
        ┌────▼────┐                 • Bob reaches Subject via Alice,
        │  Alice  │                   attenuated to Edit
        └────┬────┘                 • Carol reaches Subject via Bob,
             │ Edit                   attenuated to Read
        ┌────▼────┐
        │   Bob   │
        └────┬────┘
             │ Read
        ┌────▼────┐
        │  Carol  │
        └─────────┘
```

### Attenuation

Paths through the graph attenuate to the *lowest* power in the chain. If Alice holds `Admin`, delegates `Edit` to Bob, and Bob delegates `Admin` to Carol, Carol's effective access is `Edit`: the meet (minimum) of every hop along the path.

When multiple paths exist, the effective access is the best available path — the maximum over paths of the minimum along each path (a classic widest-path/bottleneck computation).

### Revocation Semantics

#### Who May Block

> A block naming jurisdiction *N* is valid iff its issuer could ever have issued a *delegation* anchored `from: N` at `Admin` level — that is, ever reached the subject through *N* with `Admin` — evaluated against the *revocation-free* graph.

One anchoring rule governs both certificate species: `from` means the same thing on a grant and on a block — the jurisdiction the act is exercised in. Evaluating against the revocation-free graph means the issuer must have *ever* held that position, not hold it now; see [Permanence] for why.

The block's effect is scoped to its jurisdiction: the target can no longer derive liveness through routes containing *N*. If *N* sits on none of the target's routes, the block is inert — a no-op, not an error. Scoping the *effect* rather than the validity is the load-bearing choice: denials stay permanent (monotone) while their reach stays confined to a rotatable jurisdiction. Power over an act comes from having served in its venue, never from having touched its subject.

Route geometry does two jobs that earlier drafts needed a separate independence condition for:

- *Seniority falls out for free.* You cannot cut the branch you stand on: a block on an edge *above* your jurisdiction is inert, because that edge's route never transits your jurisdiction. Deep cuts only run "downward."
- *Peers can block each other.* Two admins of the same node are each anchorable there, and each other's membership certificates route through it. Combined with permanence, concurrent mutual blocking means both fall and stay fallen; the branch's parent repairs by [rotation][rotating a role] — though under [constitutional flatness] the parent holds supply, not constitutional membership, so it re-rosters via a successor node rather than re-adding directly.

Self-authorized denials need no anchorability at all: retraction and [renunciation] validate by signature equality, as global tombstones.

#### Renunciation

> A revocation is unconditionally valid — as a global tombstone, no graph check — when its issuer is the `to` of the revoked delegation. (Its sibling, *retraction* — `iss = delegation.iss` — is equally unconditional and needs no defense: a signature is authority over its own statements.)

Without this carve-out, the anchoring rule produces *Hotel California* semantics: a plain grantee holds no Admin anchorability anywhere, and could not shed even a `Read` grant that names them.

Renunciation is unconditional — no senior sign-off, no preconditions — for three reasons:

- *Key compromise is the decisive case.* When a key leaks, it is the only signer guaranteed to be available at the moment it matters. Requiring an appeal upward imposes an unbounded, partition-shaped delay during which the thief acts freely — and at a sole-owner apex there is no upward at all: without renunciation, apex compromise means the attacker holds the document forever with no remedy. (The thief can also renounce; that is the least dangerous thing they can do with the key, and deny-only besides.)
- *It follows from the fail-closed axiom.* Shedding authority can never grant, escalate, or touch a third party's independent standing. "Ambiguity resolves toward less authority" implies renunciation.
- *Prohibition would not prevent the harms attributed to it.* A load-bearing node can strand its downstream anyway: retract every grant it issued (always allowed), or simply lose the key (passive stranding, no revocation required). Banning renunciation removes only the honest exit while leaving every dishonest and accidental equivalent intact.

A caveat: renunciation is *not* the pure ocap capability drop. In ocap, dropping your reference leaves the copies you introduced intact; here, liveness is issuer-recursive, so renouncing a membership also unwinds everything you issued through it. Renunciation is drop *plus retroactive unwinding of your introductions* — an operation with externalities the ocap analogy hides.

Those externalities are answered by the strongest counter-tradition: *authority as stewardship*. Load-bearing authority is a duty to those downstream — a trustee cannot simply resign and let the trust burn. Keyline adopts stewardship at the *protocol* layer while keeping the semantics unconditional:

- *Succession discipline.* Renouncing a load-bearing position SHOULD be preceded by handoff: confirm a successor (apex membership can always grow), let peers re-parent your issued grants (the same [re-parenting sweep][rotating a role] rotation uses), *then* renounce. Because the apex is append-only-growable, an orderly succession path always exists before the exit — and never after.
- *Stranding is repairable except in one case.* A renouncing leaf strands nothing; a load-bearing member's dead grants are re-parented by survivors; a severed subtree is re-granted from above. The sole unrecoverable case is a *sole apex member* renouncing: everything dies and nothing can ever be re-granted.
- *Burn-after-reading.* That last case is intentional, irreversible document destruction, and should be named as such — not discovered. Note that prohibiting renunciation would not prevent it (retracting all grants, or destroying the key, bricks the document just as thoroughly): sole-apex fragility is inherent to sole-apex, not to renunciation.

#### Permanence

Delegations and revocations have deliberately *asymmetric* justification requirements — one principle applied twice:

> Ambiguity resolves toward less authority.

| Statement | Justification required | When the issuer is booted |
|---|---|---|
| Delegation (grant) | *Ongoing* — recomputed at every check | Their grants die (transitive cascade) |
| Block (denial) | *Ever* — held at any point | Their blocks stand, forever — within their jurisdiction |

Both arms fail closed. The alternative for denials — late-bound validity, like delegations — would mean booting an admin *resurrects everyone that admin ever removed*: revoke the security officer, readmit the attackers. Worse, it makes denial validity non-monotone: a later merge can un-apply an already-applied denial, so access is restored by *delivery order* rather than by anyone's signature. The invariant permanence protects:

> Once a replica has applied a denial, no merge may un-apply it. Every access-restoring transition requires a fresh signature from live authority — never message scheduling alone.

Permanence is also forced by the absence of global ordering. A block signed by a booted admin is bit-for-bit indistinguishable whether signed before or after the boot, so "their old blocks stay, their new ones don't" is not an expressible rule. Causal predecessors would not fix this: a dishonest ex-admin backdates by omitting heads. Absent trusted time, permanence is forced, not chosen.

What *is* chosen is the block's scoped effect, and it is what makes permanence affordable: validity is permanent, but reach is confined to the named jurisdiction — and jurisdictions rotate. A rotation does not invalidate an old block (nothing ever does); it *moots* it, by routing authority through a fresh node the block does not name. Any revived access arrives via a new, signed supply edge — an authorized act, not a reordering. Permanent validity plus disposable jurisdictions is the whole trade.

The two-phase evaluation this induces is itself a benefit: block validity is computed first, by monotone reachability over the revocation-free graph; delegation liveness second, treating the valid-denial set as fixed. See [Liveness].

#### Transitive Effect

Revocation cascades, but *implicitly*: cutting Alice's membership does not enumerate or tombstone anything she issued. Instead, every delegation she issued fails the [liveness] check the next time it is evaluated, and everything issued downstream of those fails in turn. The cascade is a consequence of recomputing liveness, not an action taken at revocation time.

An explicit cascade would make a revocation's meaning depend on which delegations its issuer had synced when issuing it — two replicas would produce "the same" revocation with different effects, destroying order independence. Implicit cascade keeps revocations self-contained: one hash, one signature, same meaning everywhere.

Redundant paths interact correctly with the cascade for the same reason: if Carol was granted access by two independent issuers and one is revoked, the other grant is unaffected, because each certificate's liveness is evaluated on its own.

#### Death, Revocation, and Resurrection

A delegation can be dead without being revoked. If Alice is booted from Members, the delegations she issued through Members die *implicitly* — no revocation names them.

> [!WARNING]
> If the same verifying key is later re-added, its previously issued delegations spring back to life.

This follows directly from late-bound liveness: edges are facts, authority is derived. Two practices blunt the sharp edge:

- *Fresh-key discipline.* "Re-adding Alice" should mean adding a *new* verifying key of hers. Keyhive already assumes key multiplicity per agent (device keys, prekeys), so this is cheap. The old key never regains standing, and its certificates stay dead.
- *Explicit blocks on boot.* An admin who wants an agent's issued delegations dead regardless of future re-adds should block them explicitly, not rely on the implicit cascade. Thanks to [permanence], an explicit block survives even a re-add of the same key — provided its jurisdiction still stands on the route.

The alternative — having a membership revocation automatically tombstone everything issued through it — was considered and rejected: it requires the revoker to enumerate a downstream set that depends on their sync state, which breaks the CRDT property that motivates Keyline in the first place.

#### The Ex-Admin Sharp Edge

Permanence has a price:

> An ex-admin retains block power over the jurisdictions they ever served in, forever.

Booted from Members, Bob can still validly block certificates via `from: Members` — including grants issued years later, so long as their routes transit Members. Three things bound the damage: blocking is deny-only (he can never grant or escalate); the power is confined to his *service record* — a fact every block carries in its signed `from` field; and durable ejection is available by *rotation*: mint a fresh role node, re-anchor grants there, abandon the old node ([Rotating a Role]).

This upgrades rotation from remedy to hygiene:

> Removing an admin from a role SHOULD be followed by rotating the role node — otherwise the removal is not durable against griefing.

Which is BeeKEM's PCS discipline surfacing at the authority layer:

|                              | BeeKEM (keys)                      | Keyline (authority)              |
|------------------------------|------------------------------------|----------------------------------|
| What a removed party retains | Old key material                   | Ever-justified block power       |
| Why removal alone fails      | Can still decrypt old-path secrets | Can still sign valid blocks      |
| The fix                      | Rotate keys on the path (PCS)      | Rotate the role node             |
| Cost                         | $O(\log n)$ path rotation          | Mint a key + re-anchor grants    |

In both cases: you cannot un-know someone; you can only move to where they have never been. Under jurisdiction-scoped blocks, "where they have never been" is a theorem rather than a discipline:

- *The boundary is frozen, by construction.* The ex-admin's mintable jurisdictions are fixed at ejection: a freshly minted node post-dates him on every graph, so no block he can ever sign names it. Rotation is not merely repair — it is permanent escape, and it costs one layer, not the subtree. His reach into deeper jurisdictions exists only where a role he served in appears in another jurisdiction's constitution; see [Constitutional Flatness].
- *Visibility does not matter.* The ex-admin can sync every certificate ever minted; blocks against routes that no longer exist are inert. His power ends at rotation regardless of what he has seen — there is no whack-a-mole, because there is nothing left to hit. (An earlier draft leaned on hash-visibility to bound griefing; that bound is fiction under set-reconciliation sync, which enumerates missing hashes to any peer. The jurisdiction scope replaces it with something that holds.)
- *The subject is out of reach — for everyone.* The subject appears as `sub` on every supply edge but as `from` in exactly one certificate: the root edge. Keying block power on the jurisdiction *served* rather than the subject *reached* is what makes this safe — every admin who ever served anywhere has ever-reached the subject, and the subject is the one node that cannot rotate. Power keyed on reach would hand each of them a permanent whole-document kill; power keyed on service cannot name the subject at all.

One correction to the tempting intuition that rotation leaves the old node harmlessly dead: it leaves it *dormant*. See [Reconnection and Sealing][sealing].

### Computation

Evaluation is graph-global rather than certificate-local: no certificate can be verified in isolation, only against a set. This sounds expensive; the structure above makes it tame, and the evaluation *order* is load-bearing, not formal hygiene.

#### Why the Strata Are Mandatory

The tempting shortcut — delete all revoked edges, then compute reachability — is wrong, not merely slow, because revocations themselves need authority checking, and checking them against the already-subtracted graph makes revocations affect each other's validity. Concretely:

- `r1`: Brooke blocks Bob's membership `#m_Bob` via `from: Members`
- `r2`: Bob blocks some grant `#d_x` via `from: Members`

Subtract-first, applying `r1` before checking `r2`: Bob has no standing, so `r2` is rejected. Reverse order: `r2` lands. Two replicas, same set, different results — the merge-order dependence Keyline exists to eliminate. Stratification restores determinism: stratum 1 evaluates every revocation against the full positive (revocation-free) graph, where no revocation can see any other; only then does stratum 2 subtract.

Two properties fall out of stratum 1's construction:

- *Validity is monotone-stable.* Stratum 1 consults only delegations, and the positive graph only grows. New information can flip a revocation invalid → valid (its justification chain finally syncs in), never valid → invalid. Once a revocation is valid on any replica, it is valid on every replica with a superset, forever.
- *Denials are mutually invisible.* `r2` stays valid after `r1` lands, because `r2`'s justification is checked in a graph where `#m_Bob` still exists as a fact. Blocking the blocker does not undo their blocks — [permanence], the stratified evaluation order, and "check denials against the positive graph" are the same fact viewed from three sides. Blocks target delegations, never other blocks, so mutual invisibility is structural rather than imposed.

The only invalidation-shaped state is *void ab initio*: a revocation whose issuer's justification has never been seen simply does not activate. It sits in the set and may activate later when the justifying delegations arrive — the monotone direction.

#### Cost

- *Per-subject scoping.* Every query ranges over one subject's certificate set — a group's history, not a global web.
- *Stratum 1 is append-only cheap.* Monotone means merges evaluate deltas only, and validated revocations are cached forever.
- *Stratum 2 recomputes exactly what dies.* A newly valid revocation invalidates the transitive cone downstream of the cut — the same set of certificates whose liveness semantically changed. Work is proportional to actual change.
- *Widest-path is linear.* Four access levels admit a bucketed BFS from the root edges; no priority queue.
- *Blocks price per dispute.* Liveness negates the binary predicate `blocked(cert, node)`, so blocked certificates need route searches with per-target exclusions. Unblocked certificates — the vast majority — evaluate in the shared pass; the overhead is one filtered search per blocked certificate plus the cascade of actual deaths. A jurisdiction accumulating blocks is one under dispute, and rotation — already the hygiene response — moots the blocks and restores the fast path.
- *Junk never enters the fixpoint.* Evaluation forward-chains from root edges outward, so ungrounded certificates (spam, dead subtrees) cost storage but no computation. The same discipline matters for cycles: a naive top-down recursive check diverges on a cycle, and the correct cycle-cut is *assume dead on revisit* — which computes the least fixed point. Assuming live computes the greatest, and makes ungrounded cycles self-certifying: a one-line bug with a security consequence.
- *Timeless is the cheap option.* Ordering-aware revocation would require temporal reachability over a time-indexed family of historical graphs, plus causal metadata on every certificate. Here there is exactly one graph, ever, and results are a pure function of the set — the set digest is a perfect cache key.

#### Witness Hints

The [no-proof design][no-proof-field] pushes path information out of the certificate, but nothing stops transport from carrying it: a peer asserting a conclusion may attach the witness path, and checking a claimed path costs only its length. Soundness never depends on the hint — a wrong hint falls back to search — so it is pure optimization: witness-carrying gossip, verify-cheap, search-rare.

#### Partial Visibility

The honest cost of graph-global evaluation is possession, not computation: a replica cannot confirm a revocation whose justification path it has not synced. The safe default is to *provisionally honor* unconfirmed revocations — over-applying a denial is fail-closed — and confirm on fuller sync. Compare [revoking the unseen][caretakers].

## Root Edges and the Apex

Subjects bootstrap their own authority. At creation, the subject key signs exactly one delegation — `{iss: Doc, from: Doc, to: Owners, sub: Doc, can: Admin}` — to a freshly minted apex role, and the subject's signing key is destroyed (cf. Keyhive's `EphemeralSigner`). The subject's *identity* is its verifying key, permanent; its *authority* immediately lives elsewhere.

```
┌─────┐  Admin (sole root edge)  ┌────────┐        ┌─────────┐
│ Doc │◄─────────────────────────│ Owners │◄───...──│ Members │◄── ...
└─────┘  key destroyed after     └────────┘        └─────────┘
         signing this one cert    rotatable…        …all the way down
```

### The Sole Root Edge Protects Itself

Who can block `Doc → Owners`? A block requires anchorability at a jurisdiction on the edge's route — and the root edge's route is itself, anchored at Doc. Nobody was ever in a position to anchor a delegation at Doc: its constitution is one root edge naming a role, signed by a key that no longer exists. `from: Doc` is unmintable, by anyone, ever — and retraction is equally impossible, for the same reason. The apex edge is structurally undeniable, a consequence of the anchoring rule rather than a special case.

> [!IMPORTANT]
> Destroy the subject key after the ceremony, or guard it as the recovery instrument it is: a retained subject key can retract the root edge and re-root the document (below) — total power, in both directions.

### The Apex is Append-Only (Unless the Subject Key Survives)

Rotation works at every layer except the top. Rotating Owners requires a new root edge (`from: Doc`), and with the subject key destroyed, none can ever be minted. Meanwhile every ever-apex-admin retains block power via `from: Owners` — and every route in the document transits Owners — so apex ejection is never durable. There is no surviving senior to appeal to: the apex's parent destroyed itself at the creation ceremony.

| Layer | Removal semantics |
|---|---|
| Apex role (Owners) | Append-only trust — membership can grow; ejection is never durable |
| Every layer below | Fully rotatable — durable ejection via mint-and-re-anchor |

A *retained* subject key (cold storage, threshold-split) changes this under jurisdiction-scoped blocks: it can retract the old root edge and mint `Doc → Owners′` — and the old apex admins' blocks all name `from: Owners`, which the new hierarchy's routes never transit. True apex rotation, durable ejection included, at the custody cost of a key that can do the same *to* you. The ceremony's choice is between an append-only apex (destroy the key) and a re-rootable document (guard the key); there is no third option.

### Mutual Assured Destruction at the Apex

Apex peers can block each other's memberships via `from: Owners`, and both blocks of a concurrent duel are independently justified — so under [permanence], both stand: mutual destruction is deterministic, not prevented.[^mad] Below the apex this is survivable, though under [constitutional flatness] the senior holds supply rather than constitutional membership, so it adjudicates by rotation: mint a successor node, re-roster whichever party (or neither) with fresh keys.

At the apex there is no senior. If all apex members revoke one another, every human's standing in the graph — all of which traces through some apex member's late-bound issuance — dies in the cascade, and no one can ever mint new apex members (that requires *live* Admin over the apex). The authority graph is permanently bricked: replicas keep their data, but no new grant will ever be live again.

Mitigations:

- *A single-owner apex has no peers, and therefore no duel.* This sharpens the minimal-apex guidance below.
- *Structural grants signed by role keys survive.* Edges signed by an ephemeral role key at the creation ceremony ground through the irrevocable root edge, not through any member, so they outlive apex destruction. What the ceremony signs directly determines what survives the worst case.
- *A retained subject key* enables repair, at its usual custody cost (above).

Guidance: keep the apex minimal — ideally one key per human owner, or just the creator — and conduct all day-to-day administration and membership churn in second-layer roles, where rotation works. The apex is a root CA / recovery key: chosen once, rarely exercised, effectively permanent.

[^mad]: "Mutual assured destruction," from Cold War deterrence theory. The analogy is structural, not decorative: symmetric annihilation capability *is* the governance mechanism among peer admins (nobody strikes first because retaliation is guaranteed and permanent), and the apex — having no higher authority to enforce any treaty — remains in a state of nature. Deterrence-by-symmetry is what you get when revocation is permanent and unordered.

## Patterns

None of the following require mechanism beyond delegations and revocations; they are conventions over the primitives.

### Roles

A "role" is just a node: mint a key, delegate authority *to* it, and delegate authority *over* it to its administrators. Because nodes are undifferentiated keys, a role participates in the graph exactly like an individual.

```
              ┌────────┐
     Admin    │ Brooke │    Admin
   ┌──────────┤        ├──────────┐
   ▼          └────────┘          ▼
┌─────────┐        Admin       ┌─────┐
│ Members │───────────────────►│ Doc │
└─────────┘   (iss: Brooke)    └─────┘
 ▲   ▲
 │   └──────── Bob   (Admin, sub: Members)
 └──────────── Alice (Admin, sub: Members)
```

Here Brooke holds the root Admin on Doc, has delegated Doc-Admin to the Members role, and administers the role itself. Alice and Bob are members: they hold Admin over the *Members node*, and reach Doc transitively through the role's grant.

The role's signing key can be ephemeral: create the key, sign the initial edges, discard it. Thereafter, the role's admins act on its behalf using `from` (below).

### Acting Through a Role: the `from` Field

When Alice delegates Doc access to Carol, she signs personally but attributes the authority to the role she reaches Doc through:

```
        ┌───────┐
        │ Alice │
        └───┬───┘
            │
      ╔═════╧════════════╗
      ║ #d1: Delegation  ║
      ║   iss:  Alice    ║
      ║   from: Members  ║
      ║   can:  Edit     ║
      ║   sub:  ● ┄┄┄┄┄┄┄╫┄┄┄┄► Doc
      ╚═════╤════════════╝
            │
            ▼
        ┌───────┐
        │ Carol │
        └───────┘
```

Anchoring at the role (rather than at herself, with `from: Alice`) is a governance choice, not an access choice: Carol gets Edit either way, but a Members-anchored edge sits in the role's jurisdiction — any Members admin may revoke it. Anchoring at Alice would leave only Alice-or-senior able to manage it. *Anchor grants at the role they flow through* is the recommended default.

Note what anchoring does *not* do: it does not decouple the grant's fate from its issuer. `#d1` points at Members, but it lives and dies with Alice's standing ([Liveness]).

### Caretakers

The ocap caretaker pattern — interpose a cuttable proxy between grantor and grantee — needs no dedicated mechanism: a caretaker is a single-purpose role. Mint a node `C`, route the grant through it, and give the kill switch to whoever should hold it:

```
┌─────────┐  Edit   ┌───┐  Edit   ┌───────┐
│ Members │────────►│ C │────────►│ Carol │
└─────────┘         └───┘         └───────┘
                      ▲ Admin
                   ┌──────┐
                   │ Dave │
                   └──────┘
```

This buys three things the bare revoke-by-hash rule cannot express:

- *Assignable revocation rights.* Dave — who holds no authority over Members or Doc — can cut `C`'s outgoing edges. The kill switch became a grantable capability.
- *Pre-installed cut points.* Revoking the single edge into `C` severs everything downstream at once, with no enumeration.
- *Revoking the unseen.* `Revoke` names a delegation by hash, which requires having seen it. With partial visibility, a subtree may be known to exist without its certificates being held. A caretaker at the trust boundary lets you sever the whole subtree by retracting or blocking the one edge you *do* hold.

Unlike ocap caretakers, a certificate node is inert — it cannot filter, log, or rate-limit. Only the revocability transfers.

### Rotating a Role

Durable ejection from a role is achieved by abandoning the role node, not by revoking the member (see [The Ex-Admin Sharp Edge]):

1. Mint `Members′` (ephemeral key: sign the setup edges, discard).
2. Re-issue the role's inbound grants to `Members′`; revoke the old ones.
3. Re-add the surviving members to `Members′`.
4. For hygiene, explicitly block the ejected member's certificates via `from: Members` — permanent, so the denial survives any future re-grant of the old node.

The cost is collateral: every delegation issued `from: Members` dies with the old grant chain — including grants by *surviving* members, possibly issued concurrently with the rotation. These certificates are *dead, not lost*: they remain in the set, attributable to issuers who still stand in `Members′`, so a client can detect its own dead grants on sync and re-sign them with `from: Members′` — an automatic re-parenting sweep. Only grants whose issuers never return need another admin's intervention.

The sweep must be *selective*: re-issue the grants that were live immediately before the cut, excluding anything denied and anything from dead issuers. Rotation is whitelist reconstruction, not blacklist migration — the old layer's deny-state is expressed at the new layer by *not re-issuing*, so no revocations are recreated. A pleasant corollary: rotation is semantic tombstone compaction. The deny-list of a jurisdiction never has to grow across epochs; each rotation resets the layer to purely positive form, and the old tombstones remain in storage but stop carrying meaning.

#### Cost: One Layer, Not the Subtree

Only certificates *anchored at the rotated node* need re-issuing. Everything deeper — grants anchored at child roles, and their children — never mentions the rotated node at all (no proof field), so those certificates keep their hashes: they merely go dormant when their issuers' standing lapses, and revive by late binding the moment the one supply edge `Members′ → Child` is re-issued. Because the deep certificates keep their hashes, the blocks naming them via *un-rotated* jurisdictions keep biting — that deny-state migrates automatically, with zero action. Blocks that named the rotated node itself go *moot* for re-anchored certificates and must be re-scoped to the successor if still wanted; they are enumerable from the set (every block naming the old node), so tooling can compute the carry-over deny-list mechanically.

$$\text{rotation cost} = O(\text{certs anchored at the rotated node})$$

not $O(\text{downstream subtree})$.[^x509] The precondition is [Constitutional Flatness]: if the rotated role appears in child constitutions, those jurisdictions are contaminated and must rotate too.

[^x509]: Contrast proof-chain systems: an X.509-style certificate hardwires its intermediates into the chain, so rotating one intermediate CA forces re-issuing the entire subtree below it. The no-proof field — adopted for CRDT/order-independence reasons — is what makes Keyline jurisdictions cheaply disposable, and disposable jurisdictions are the entire mitigation story for permanence's sharp edges. The design's three big choices (no proofs, permanence, rotation-as-hygiene) each make the others affordable.

#### Reconnection and Sealing

Revocation kills certificates, not futures: the revoked inbound grant `#g1` can never return, but a *fresh* grant `#g3` to the abandoned node is a new hash, untouched by the old revocation. And the abandoned node is not empty — its constitutional structure is self-grounded (memberships have `sub = Members`, chaining to Members' own root edge, never touching Doc) and so never died. If anyone with live authority re-grants to the old node, every dormant grant whose issuer still holds a live membership there re-energizes at once — and the re-energized jurisdiction is again grief-able by its ever-admins. "Dead" means "dead while everyone remembers not to reconnect," which makes institutional memory a security control. Three tiers of enforcement, cheapest first:

| Tier | Mechanism | Protects against |
|---|---|---|
| Boot + move (the standard flow) | Revoke inbound grants, mint the successor, re-add survivors | All current authority; the ex-admin can never follow |
| Burned-node detection (tooling) | The revocation of `#g1` is a permanent, signed record that the node was deliberately cut; a client about to grant *to* such a node warns loudly | Accidental reconnection — the realistic vector |
| Sealing (hardening) | Explicitly block every constitutional edge via the old node: seniors block peers, then renounce their own ([renunciation] covers the last one out) | Even deliberate reconnection revives nothing — no issuer there will ever have standing again |

Sealing makes the dormancy permanent: minting new memberships requires *live* Admin over the node, which no key holds or can ever regain. Reserve it for abandoning a [spine][the spine] after a griefing spree, or long-lived documents crossing admin generations where warnings may be ignored.

### The Spine

Rotation churn can be avoided almost entirely by splitting a role into a stable *jurisdiction* node and a rotatable *membership epoch* node:

```
┌────────┐ Admin ┌───────┐ Admin ┌────────────┐
│ Owners │──────►│ Spine │◄──────│ Mod-epoch1 │◄── Alice, Bob (Admin)
└────────┘       └───┬───┘       └────────────┘
                     │ Admin           rotates: epoch1 ✂ → epoch2 (Bob only)
                     ▼
                  ┌─────┐          Grants are issued from: Spine,
                  │ Doc │          never from: epoch-N
                  └─────┘
```

Members attach to the epoch node; all outward grants anchor at the spine (`from: Spine`). To eject Alice, rotate only the epoch: revoke the epoch's grant, mint `epoch2`, re-add everyone but Alice.

Now consider Bob's invite `{iss: Bob, from: Spine, to: Dave}` issued *concurrently* with the rotation. Its liveness requires only that Bob currently reaches Doc through Spine — which held via `epoch1` before the merge and holds via `epoch2` after. The invite never flickers: no re-issue, no repair sweep. Alice's spine-anchored grants die correctly, because *her* standing is gone. The late-bound liveness that produces [zombies][resurrection] is what makes this pattern work.

The trade-off: a stable jurisdiction accumulates ever-admins. Alice ever-held Admin over Spine (via `epoch1`), so under [permanence] she can grief spine-anchored certificates forever:

| Grants anchored at… | Rotation churn | Ex-admin griefing surface |
|---|---|---|
| Epoch node | Everything re-issued on every rotation | Clean slate each epoch |
| Spine | None — grants survive rotation automatically | All ever-members, forever |

A reasonable default: anchor at the spine for convenience and degrade gracefully — griefing is signed and attributable, and the response to an actual spree is re-anchoring onto a fresh spine, paying the churn cost once, when provoked, rather than on every rotation.

### Constitutional Flatness

Whether ever-admin power *cascades* is a topology choice, made when a child role's constitution is written:

```
NESTED (contaminating)                 FLAT (contained)

Mod1 ──Admin, sub:TeamX──► TeamX      Mod1 ──Admin, sub:Doc──► TeamX
  every ever-admin of Mod1               parent holds only the SUPPLY:
  ever-holds Admin over TeamX            TeamX's inbound grant. TeamX's
                                         constitution names individuals
                                         (Dave, Erin) — never Mod1
```

Under nesting, every ever-admin of Mod1 ever-held Admin over TeamX (the positive-graph chain: membership → Mod1's `sub: TeamX` edge), so by [permanence] they can revoke TeamX-anchored certificates forever — and since deep certificates keep their hashes across rotations, rotating Mod1 does *not* escape them. The exit price is rotating the entire contaminated subtree. Causality cannot fix this (a dishonest ex-admin backdates by omitting heads); topology can:

> Never grant `sub: ChildRole` to an upstream role. Parents govern children by controlling their inbound grants, not by joining their constitutions. Constitutional membership is permanent contamination; supply control is not.

The parent loses nothing that matters: it retains *supply control* — the child's inbound grant is anchored at the parent, so the parent can cut it (killing the whole child subtree) and re-grant to a successor. Total, coarse governance without ever entering the child's constitution. This is the same encapsulation the anchor rule already provides for revocation, now revealed as a griefing containment requirement: with flat constitutions, ever-Admin is non-transitive by construction, and an ex-admin's grief scope is exactly the nodes he was directly a member of.

Nested administration — a parent that can fix a child's internals directly — remains expressible, but it buys convenience with contamination, and should be priced on the label.

### Memberships, Not Grants

The patterns above converge on a recommended shape: humans never receive `sub: Doc` grants at all. They receive *memberships in roles, at a level*; the only `sub: Doc` edges in the graph are the supply lines connecting roles to documents.

```
        ┌─────┐
        │ Doc │◄──────── supply (sub: Doc) ────────┐
        └─────┘                                    │
                    ┌────────┐   supply    ┌──────────────┐
                    │ Owners │───────────► │  Moderators  │
                    └────────┘  (sub:Doc)  └──────────────┘
                        ▲                     ▲     ▲     ▲
             membership │          membership │     │     │ membership
            (can:Admin) │         (can:Admin) │     │     │ (can:Edit)
                        │                     │     │     │
                     Brooke                Alice   Bob   Carol
```

Two edge species only: *memberships* (`sub = from =` the role, at any level) and *supplies* (role → role or document). Carol's Edit-level membership reaches Doc at $\min(\text{Edit}, \text{supply})$ — [attenuation] already provides per-member ceilings within a group, so "invite at a level" needs zero new mechanism. What the shape buys:

- *Griefing containment.* Revocation power requires Admin over an anchor, so a Read- or Edit-level member never contaminates the node: no ever-power, ever. The griefer set shrinks from "everyone ever attached" to "ever-*admins* only." Inviting a thousand editors adds zero grief surface.
- *Rotation is exactly the roster.* There is no scattered population of `sub: Doc` certificates anchored at the role to chase down — there never were any. Re-adding survivors *is* the re-issuance.
- *One membership, N documents.* A role's supply portfolio can cover many subjects, each path attenuated independently. Future supplies propagate automatically by late binding: the membership certificates never change, and never even know the new document exists.
- *Offboarding is one revocation.* Cutting a membership severs the entire portfolio — the failure mode enterprise ACL systems sweat hardest (orphaned per-resource grants) cannot occur, because per-resource grants on humans do not exist.
- *One-off grants are singleton roles.* "Exactly Dave, exactly this document" = a [caretaker][caretakers] role with Dave as sole member and one supply. Every grant is a membership; individual grants are memberships in roles of one.

Two costs, honestly: invitation becomes an admin act (adding a member is a constitutional edge, requiring live Admin over the role — an Edit member cannot invite; the escape valve is handing them a singleton caretaker to re-share from). And a role's portfolio is a blast radius: membership is all-or-nothing across it, so portfolio boundaries are access-control decisions, not org-chart decorations.

## Griefing

Anyone upstream can deny access downstream — and "upstream" includes *ever*-admins of upstream jurisdictions. The griefer set has an exact characterization: a grantee's access dies iff every live route is cut, and X can cut a route iff it transits a jurisdiction X was ever Admin-anchorable in. So:

> X can grief Y ⟺ every live route from Y to the subject transits at least one jurisdiction in X's service record.

Three consequences:

- *The set grows with depth and fan-in.* A chain of depth $d$ through roles of $m$ admins each exposes $O(d \cdot m)$ potential griefers per path.
- *It grows monotonically in time.* "Ever-admin" is append-only.
- *Availability is a min-cut problem.* Redundant paths defend only if *jurisdictionally disjoint* — a second path through the same role adds nothing, since the same admins cut both. Access is widest-path over $(\max, \min)$; grief-resistance is min-cut over jurisdictions. Hardening means path diversity across disjoint anchor sets.

Why this is survivable:

- *Deny-only.* A griefer can never read, write, or escalate.
- *Only admins are in the set.* Under [Memberships, Not Grants][memberships], Read- and Edit-level members never hold Admin over any anchor and acquire no ever-power. The griefer set is the ever-*admins*, not everyone ever attached.
- *Bounded by local-first.* Revocation confiscates nothing: the grantee keeps their replica and everything already decrypted. Griefing severs new content keys and authorized sync — real, but not data loss.
- *Attributable and repairable.* Revocations are signed; a spree is a self-incriminating audit trail, and any surviving senior admin re-grants and rotates the griefer out.
- *Blast radius and griefer count are inversely related.* Upstream cuts kill whole subtrees, but upstream jurisdictions have fewer ever-admins, and route geometry bars everyone standing on the edge from cutting it. The most damaging cuts are available to the fewest, most identifiable parties. The apex can grief everything — but that is just ownership, true of any rooted authority system.
- *Rotation ends it.* A block's reach is fixed at signing time by its `from` field, so a griefing spree is answered by rotating the named jurisdiction — one layer, permanent escape, and every block the griefer ever signed goes inert.

The tension is inherent: revocation power *is* denial power. Any design with decentralized durable removal hands every remover a griefing capability. Keyline chose durable (fail-closed); jurisdiction scoping and rotation hygiene shrink the surface, and no semantics tweak eliminates it.

## Worked Example

The running scenario, start to finish. Setup as in [Roles]: Brooke roots Doc, administers Members; Alice and Bob are members.

*1. Alice delegates to Carol.* Alice issues `#d1 = {iss: Alice, from: Members, to: Carol, sub: Doc, can: Edit}` (diagram above). Carol's effective access is Edit: the minimum along Doc ← Brooke's grant ← Members ← Alice's standing, attenuated by the grant itself.

*2. Brooke boots Alice.* Brooke issues `Block {iss: Brooke, from: Members, revoke: #m_Alice}` against Alice's membership edge. Valid: Brooke is Admin-anchorable at Members. Effective: the membership's only route runs through Members. Effects, all by liveness recomputation:

- Alice loses Admin over Members, hence over Doc.
- `#d1`'s issuer loses standing, so Carol's Edit dies — *transitively, though nothing named `#d1`*.
- `#d1` remains in the set: dead, not revoked.

*3. Brooke re-grants Carol.* Brooke issues `#d2 = {iss: Brooke, from: Members, to: Carol, sub: Doc, can: Edit}`. She reaches Members with Admin, so `from: Members` is hers to exercise. `#d1` and `#d2` render as the same edge — Members ─Edit─► Carol — but are distinct certificates with independent fates: `#d2` hangs on Brooke's standing and is unaffected by Alice's history.

*4. The zombie.* If Alice's same key is ever re-added to Members, `#d1` silently revives and Carol holds two live grants. See [Death, Revocation, and Resurrection][resurrection] for why this is accepted and how practice avoids it.

## Open Questions

- *Whiteout.* Carol wrote content while validly authorized; after the cascade her authorization is gone. Whether her past writes remain materialized is a content-layer question (see causal encryption), but Keyline should expose enough to answer "was this issuer live at the time of this write?" — which, absent causal metadata on delegations, it currently cannot. Rotation sharpens this: a grantee may exercise access on replicas that have not yet merged a revocation, so "authorized-then, dead-now" writes are unavoidable in the concurrency window.
- *Relay and revocation.* Cutting a `Relay` edge stops future authorization but not decryption by parties holding key material. Effective removal requires the revocation to trigger key rotation (BeeKEM) at the layer above; the coupling point needs specifying.

- *Re-scoping blocks across rotation.* A block naming a rotated node goes moot for certificates re-anchored at the successor. Denials still wanted must be re-scoped — mechanically enumerable (every block naming the old node), but the sweep needs tooling and a policy for who re-signs.

- *Delegation below Admin.* The [attenuation] example implies any grantee can extend the chain, clamped by min; the access-level table reserves "delegate" for Admin. Block validity sides with the table (Admin-anchorability). The delegation side needs the same decision made explicitly.

Resolved earlier drafts' questions: concurrent mutual revocation is settled by [permanence] (both parties fall and stay fallen; the parent repairs by rotation), and "does a grantee survive their grantor's removal" is settled by [liveness] (no — unless they hold a jurisdictionally independent redundant path).

<!-- Links -->

[apex]: #root-edges-and-the-apex
[attenuation]: #attenuation
[caretakers]: #caretakers
[constitutional flatness]: #constitutional-flatness
[liveness]: #liveness
[memberships]: #memberships-not-grants
[no-proof-field]: #no-proof-field
[permanence]: #permanence
[renunciation]: #renunciation
[resurrection]: #death-revocation-and-resurrection
[revocation semantics]: #revocation-semantics
[roles]: #roles
[rotating a role]: #rotating-a-role
[sealing]: #reconnection-and-sealing
[subduction]: https://github.com/inkandswitch/subduction
[the ex-admin sharp edge]: #the-ex-admin-sharp-edge
[the spine]: #the-spine
