# Keyline Edge Cases

Companion to the [Keyline design][keyline]. These notes record the adversarial analysis that produced the current design, in two convergences: first the revocation rule (one scenario worked end to end, Findings 1–7 and the candidate repairs), then the certificate format itself (the field eliminations, at the end of this document). The findings are kept as the arguments-of-record; terminology mid-document reflects the generation under analysis (`from`/`via`-scoped blocks), which the [second convergence][the second convergence: field elimination] later collapsed into service-record scoping.

## The Running Scenario

Alice holds root Admin on `doc1`. She supplies Admin to a moderator role; moderators supply a member role; grants chain down from there.

```
┌──────┐ root  ┌───────┐
│ doc1 │◄──────│ Alice │
└──────┘       └───┬───┘
                   │ #s1 {iss: Alice, from: Alice, to: mods1, sub: doc1, can: Admin}
               ┌───▼───┐
               │ mods1 │◄── Bob, Carol, Mallory (Admin, sub: mods1)
               └───┬───┘
                   │ #s2 {iss: Carol, from: mods1, to: members1, sub: doc1}
               ┌───▼──────┐
               │ members1 │◄── Dan {iss: Carol, from: members1, sub: members1}
               └───┬──────┘
                   │ #d1 {iss: Dan, from: members1, to: Eve, sub: doc1}
               ┌───▼───┐    #d2 {iss: Eve, from: Eve, to: Frank, sub: doc1}
               │  Eve  │──► Frank
               └───────┘
```

Events, all concurrent or nearly so:

1. Alice revokes `#s1`, mints `mods2`, adds Bob and Carol (omitting Mallory), and a mods2 member issues `#s4 = {from: mods2, to: members1, sub: doc1}` — rotation by omission.
2. Bob issues `#r2` revoking `#d1` (cutting Eve) — legitimate moderation.
3. Mallory issues `#r3` revoking `#d2` (cutting Frank) — grief.

## Finding 1: Upstream Scoping and Anchor Scoping Cannot Both Hold

Bob's cut of Eve and Mallory's cut of Frank are _structurally identical acts_: a member of an upstream jurisdiction tombstones a certificate anchored below their own jurisdiction — a _deep cut_ (transitive revocation). Any validity rule that accepts one deep cut accepts the other.

|                    | Bob cuts Eve    | Mallory cuts Frank      |
|--------------------|-----------------|-------------------------|
| Upstream rule      | valid — desired | valid — unbounded grief |
| Anchor-scoped rule | invalid         | invalid — contained     |

Under the _upstream rule_ (revoker must be upstream of the revoked edge, evaluated against the revocation-free graph), both revocations are valid, both are permanent, and both are immune to the concurrent rotation: stratum 1 sees `#s1` as a fact forever, so each issuer's justification holds regardless of merge order. This is the strata doing their job — and the grief doing its worst.

Under _anchor scoping_ (revoker must Admin-reach the target's anchor) with [constitutional flatness][keyline-flat], neither deep cut is valid: nobody in the mods layer ever Admin-reaches `members1`. Eve's removal must then go through Dan (her issuer), through the supply holder (cut `#s4`, rotate), or through a local `members1` admin. Anchor scoping does not satisfy the requirement that motivated deep cuts ("Bob can break Members → Carol") — it quietly reproduces the retract-and-rotate model while still paying for permanence and strata.

## Finding 2: Grief Contaminates Through the Revocation-Free Graph

Under the upstream rule, the revocation-free graph never forgets `#s1` and `#s2`. So the path `doc1 ← Alice ← mods1 ← members1 ← anything` exists forever as a justification for Mallory's deep cuts — _including against certificates issued after her ejection_. Rotating `mods1 → mods2` ends her power over mods-anchored certificates but leaves her ever-upstream of every doc1-facing certificate anchored at `members1`, present and future. Re-granting Frank produces `#d3`; she deep-cuts it on sight; repeat without end.

The ending move is rotating `members1` itself — a fresh node whose lineage never touches `mods1` on any graph. In general:

> Under the upstream rule, durably ejecting an admin requires rotating _every node that ever drew supply through a jurisdiction they administered_.

This falsifies the main document's rotation cost claim for the upstream rule: escape is $O(\text{ever-downstream cone})$, not $O(\text{certs anchored at the rotated node})$. The one-layer cost model holds only under anchor scoping — which forfeits Bob-cuts-Eve (Finding 1).

## Finding 3: The Visibility Bound Does Not Hold

The main document bounds ex-admin grief by visibility: a deep cut names a hash, so the griefer must sync each certificate to kill it — retail whack-a-mole, not a wholesale ban. In practice the bound is nearly worthless:

- _Set reconciliation is a hash oracle._ Certificate sets propagate by comparing digests; any peer or relay Mallory reconciles with enumerates the hashes she is missing. Handing out hashes is the sync protocol's job.
- _Relays are untrusted by design._ `Relay`-level nodes carry the graph without decrypting. A deep cut needs no plaintext, only hashes. One relay suffices.
- _One colluder suffices,_ and certificates must circulate widely to be checkable at all — selectively hiding them contradicts the availability the CRDT design buys.

The retail/wholesale distinction collapses to a latency gap: an ejected admin's effective power under the upstream rule is a standing wholesale ban with a one-sync-cycle delay — nearly the pattern-revocation capability the main document explicitly rejected. What survives of the mitigation list: deny-only, roster-untouchable (constitutional edges never flow through the contaminated supply), attributable (cold comfort against a party with nothing left to lose), and rotation-as-escape at the Finding 2 price.

## Finding 4: Re-Supply Revives Wholesale; Tombstones Are the Only Denial That Survives

When `#s4` re-supplies the existing `members1` node, revival is _wholesale, not selective_: every dormant `members1`-anchored certificate whose issuer still stands re-energizes at once by late binding. Nobody chooses. Deny-state survives by two different mechanisms depending on layer:

| Layer                                             | Mechanism                                              | Property                                                                                                     |
|---------------------------------------------------|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| At the rotated node (`mods1 → mods2`)             | Fresh hashes; deny = selective omission from the sweep | Requires the sweeper to have synced the revocations — an unsynced tombstone means a faithful, wrong re-issue |
| Below the rotation boundary (`members1` and down) | Hashes unchanged; existing tombstones keep biting      | Automatic, zero action — but only _explicit_ tombstones. Implicit (cascade) deaths revive with the supply    |

Corollary: a death that must survive re-supply must be tombstoned explicitly. Omission works only at a layer whose hashes are being regenerated.

## Finding 5: Revocation Never Disarms

In every variant considered, tombstoning an admin removes what they have, never what they can deny:

|                       | Removes access (grants die) | Removes denial power (grief ends) |
|-----------------------|-----------------------------|-----------------------------------|
| Regular revocation    | yes                         | no — ever                         |
| Retraction / rotation | yes, collaterally           | yes — the only thing that does    |

The reason is structural and shared: revocation validity must ignore tombstones (mutual invisibility) or concurrent revocations become merge-order dependent. So a booted admin's boot is invisible to the validity check on their subsequent revocations. Only removing the supply line they ride — retraction, hence rotation — ends denial power. Every removal of an admin is therefore incomplete until the follow-up rotation, in every design on the table.

## Finding 6: MAD at Every Flat Role

Peer admins of `mods1` can tombstone each other's memberships, and mutual invisibility guarantees the _second strike_: a tombstoned Bob's revocation of Mallory still validates against the tombstone-free graph. Symmetric capability plus assured retaliation is mutual assured destruction — the equilibrium, not merely the possibility of a duel. A first strike gains nothing durable.

But below the apex, MAD is _adjudicated_: destruction is survivable by rotation, and the senior decides the re-roster. This changes the game in three ways:

- _Deterrence is diluted._ An admin who expects the senior's favor may strike deliberately — the duel is an appeal to authority, trial by combat with Alice as judge. Apex MAD is absolute precisely because there is no judge.
- _Flatness disarms the judge's scalpel._ Under constitutional flatness Alice holds supply over `doc1`, not `sub: mods1` — she _cannot re-add anyone_ to a bricked `mods1`. The main document's "the branch's senior adjudicates, re-adding whichever party" is wrong for flat topologies: the senior's only repair is rotation. A total duel bricks the node exactly like apex MAD, one layer down.
- _Any single admin can force a rotation at will_ — revoke all peers, absorb the retaliation, node bricked. Deny-only and attributable, but it makes rotation frequency partly adversary-controlled.

## Finding 7: Offline and Adversarial Are Indistinguishable

From the remover's seat, an issuer who has not retracted a problem grant looks the same whether they are offline for years or colluding with the grantee. Local-first makes long absence the common case, not the corner. Three consequences for any rule without deep cuts (anchor-scoped variants, retract-and-rotate):

- _Cooperative removal has an unbounded liveness dependency._ "Ask the issuer to retract" waits on a specific key with no deadline. This is the same partition-shaped-delay argument the main document uses to justify unconditional [renunciation][keyline-renounce], pointed the other way: removal semantics that require a particular party to be reachable are not semantics, they are hopes. The unilateral path — cut coarse at your own jurisdiction and rebuild — is therefore the real removal primitive; issuer cooperation is an optimization when available.

- _The unilateral path is collective punishment._ One misbehaving grantee deep in a personal chain (`Eve → Frank → Greg → Heidi → Ingrid`, boot Heidi) and the coarse cut darkens every innocent in the segment. Late binding makes the chain atomic: re-granting any old key revives everything below it, so the rebuild needs _fresh keys_ for everyone between the cut and the target's issuer. Online innocents are dark until re-keyed; offline innocents are dark-on-return. A deep cut punishes one user; a coarse cut punishes the subtree. Role-based topology ([memberships, not grants][keyline-memberships]) avoids this by construction — booting a roster member is surgical — so the cost falls precisely on person-to-person delegation chains.

- _Removal is never a fact in the set._ Without a deep tombstone, excluding Heidi durably requires that the burned old keys never regain standing — an obligation held in tooling and institutional memory indefinitely, across admin generations, whose failure mode is silent revival of the removed party (a zombie chain). The certificate-level hygiene tool for exactly this hazard — explicit revocation on boot (Finding 4) — is definitionally unavailable: creating that tombstone _is_ a deep cut.

So deep cuts have a second job beyond surgical precision: they make removal a durable, syncable fact rather than a memory. Any design that drops them must either accept burn-list memory as a permanent security control or re-admit some deep-cut form — which routes back into the junction below.

## Candidate Repairs

Three rules were explored for keeping Bob-cuts-Eve while containing Mallory. The first two work but cost heavily; the third is the current leading candidate.

### Option 1: Path-Scoped Revocation with Retraction Strata ("Epochal Permanence")

A revocation is valid iff its issuer controls a node on the target's justification path, evaluated against the positive graph _minus retractions_. Retraction — revoking a certificate you yourself signed — is valid by signature equality alone, needing no graph check. Three strata keep it deterministic:

```
stratum 0: retractions (validity = signature equality; base facts)
stratum 1: third-party revocations, checked against positive − retracted
           (tombstones mutually invisible)
stratum 2: subtract everything; compute liveness
```

Rotation = retract the supply + reissue the deny-list under the new path. Mallory's power ends _completely_ at the mods rotation — no cone rotation — because her justification rode a supply line that stratum 1 no longer sees. Permanence becomes epochal: ex-admin power lives exactly as long as the supply line it rides.

Downsides, in severity order:

1. _Denial validity becomes non-monotone — fail-open._ Retractions void standing revocations retroactively. On any replica that receives the retraction and `#s4` before the reissued tombstones, Eve is live. A relay (or Eve) can engineer this ordering. Old permanence had the property that no delivery order could resurrect a revoked party; option 1 mints a resurrection window at every rotation, and rotation is routine.
2. _Retraction becomes a resurrection lever._ An ex-member retracts a load-bearing supply they issued while standing; every stratum-1 revocation that rode it is void; after repair via a fresh line, the grants revive by late binding while the voided denials stay void (unless the original revokers sit on the new path). Retraction — the supposedly deny-only, self-evidently-authorized primitive — acquires a grant-restoring side effect chosen by the attacker.
3. _The deny-list must be re-signed at every rotation, forever._ Reissued tombstones ride the new path, so the next rotation voids them again. Grants fail loud when dropped; denials fail silent. A single forgotten tombstone is an invisible revival. Denials also acquire lineage fragility: each reissue hangs on its reissuer's continued path-control.
4. _Within an epoch, nothing improves._ Stratum 1 ignores tombstones, so every old sharp edge — grief until rotation, mutual invisibility, MAD — persists inside the epoch. Option 1 pays old costs during epochs plus the reissue tax at boundaries.
5. _Fan-in inverts the min-cut defense._ Any live on-path controller can deep-cut a certificate, including one sustained by a disjoint jurisdiction's supply. Redundant supply lines defend availability but multiply the parties who can deny — the same topology choice pulls in opposite directions.
6. _Incremental evaluation degrades._ "Validated revocations are cached forever" fails (valid → invalid transitions exist); a retraction cascades bidirectionally: voids revocations, revives certificates, recomputes liveness, possibly re-validates other revocations.

Option 1 is not a stable fourth point in the design space: its revocation arm alone is old Design A (Mallory intact), its retraction arm alone is retract-and-rotate, and the combination makes third-party denials topology-contingent — the fail-open primitive.

### Option 2: Per-(issuer, from) Causal Streams

Each (issuer, anchor) pair's operations form a hash-linked DAG; rotation retains heads, so deny-state migrates with zero reissue. Ordering makes "her old revocations stand, her new ones don't" expressible — the rule the main document holds inexpressible without ordering.

The backdating objection (an ex-admin omits heads to claim their revocation predates the boot) is weaker than the main document assumes, because _the revoked hash is itself a causal timestamp_: a revocation must name its target, and naming a certificate proves the revocation postdates it. If new grants causally dominate the boot event, any revocation naming a post-boot certificate is self-evidently post-boot, whatever heads it claims. Residual grief: one backdated sweep over certificates that existed before the boot — bounded, one-time, repaired by reissuing those certificates with post-boot causal positions.

Costs: the timeless core dies. Evaluation is no longer a pure function of an unordered set — no set-digest cache key, order-aware validity per pair, worse partial-visibility behavior (a revocation cannot be judged without its stream context), and fork/equivocation semantics for dishonest streams. If the whiteout question (see [Keyline open questions][keyline-open]) eventually forces causal metadata into the system anyway, option 2 pays a bill that was coming regardless; if whiteout stays content-layer, option 2 dirties an otherwise clean auth layer.

A trap to refuse if option 2 is chosen: punishing equivocation. Detecting a forked stream and invalidating it voids the forker's _legitimate_ old revocations — non-monotone denial validity through the back door. Accept both branches; the named-hash bound already confines what forking buys.

### Option 3: Jurisdiction-Scoped Blocks — Scope the Effect, Not the Validity

The options above, and the whole 2×2 grid of "revoker ⟨ever/currently⟩ controls a node ⟨ever/currently⟩ on the target's path," scope a revocation's _validity_ by topology — and every cell lands on Mallory, fail-open, or causal order. The escape is to scope the _effect_ instead. First, the invariant the path-scoped family violates, which any candidate must satisfy:

> Once a replica has applied a denial, no merge may un-apply it. Every access-restoring transition requires a fresh signature from live authority — never delivery order alone.

(Total fail-closed is unavailable: eventual consistency means unseen denials apply late, and late binding means implicit deaths revive. But the first is bounded by sync and the second is gated by an authorized signature. The disqualifying failure mode is denial undone by message scheduling.)

#### The Rule

A _block_ is `{iss: R, from: N, revoke: Hash<Delegation>, sig}`:

- _Validity._ R may issue a block naming `from: N` under exactly the condition that R could have issued a _delegation_ anchored `from: N` — ever, evaluated on the revocation-free graph. One anchoring rule for both certificate species: `from` means the same thing on a grant and on a block — the jurisdiction the act is exercised in.
- _Effect._ The target certificate can no longer derive liveness through any route containing N. Not a tombstone: a per-(certificate, jurisdiction) subtraction. If N is on none of the target's routes, the block is inert — a no-op, not an error.

Retraction (issuer kills their own certificate) and renunciation (the `to` sheds what names it) remain _global_ tombstones with signature-equality validity. The denial family splits cleanly: self-authorized denials are global; third-party denials are jurisdiction-scoped.

#### Against the Prior Failures

- _Monotone (the invariant holds)._ Block validity is permanence: evaluated on the positive graph, monotone-stable, cacheable forever. Rotation _moots_ Bob's `(from: mods1, revoke: #d1)` rather than voiding it — Eve's revival requires Alice's freshly signed supply creating a genuinely new route, which is the ordinary redundant-path rule (new paths must be cut separately), not a denial un-applied by merge order. No reordering of a fixed set changes any evaluation.
- _Mallory is contained in space, by construction._ Her blocks can only name jurisdictions she could ever anchor in — her service record: `{mods1}`. Post-rotation, every live route runs through `mods2`, which post-dates her on every graph. Finding 2's cone contamination is gone — the "frozen boundary" is a theorem, because the block carries its jurisdiction in a signed field. Finding 3 is mooted: she can sync every hash in the world and block them all via `mods1`; all inert.
- _Root-safe — the `from`/`sub` asymmetry._ `doc1` appears as `sub` on every supply edge (that is what supply is) but as `from` in exactly one certificate: the root edge. Anchoring a delegation at `doc1` was never possible for anyone — its constitution is one root edge to a role whose key was destroyed — so blocking `from: doc1` is unmintable, ever, by anyone. The old independence-condition theorem (the sole root edge protects itself) becomes a fact about an empty roster. The warning that motivates this: had validity keyed on ever-reaching the _subject_ instead, every admin who ever served anywhere would hold a permanent, unrescuable, whole-document kill — every path terminates at the one node that cannot rotate. Authority flows _through_ jurisdictions; blocking power comes only from membership _in_ them.
- _Deep cuts work._ Bob blocks `(#d1, mods1)`: effective within the epoch; after rotation he re-scopes to `mods2`. The re-scope liturgy survives but downgraded: blocks are never dead-on-arrival (a late-arriving block still bites on every replica that has not merged the rotation, and is merely moot afterward), never voided, and the carry-over deny-list is enumerable from the set itself (every block naming the rotated node).
- _Healing and provenance intact._ Deep certificates keep their hashes; blocks subtract (certificate, node) pairs; late binding revives everything not explicitly denied. Wholesale revival + retail denial, preserved.
- _Local validation._ Anchorability at N is checkable against N's own constitutional certificates — under flatness, roster membership — with no global path search. Partial-visibility friendly.

#### Stratification

The two-strata semantics survives unchanged in shape and gets slightly cleaner. Base facts: certificates, plus tombstones valid by signature equality (retraction, renunciation) — no graph check at all. Stratum 1: block validity, a purely positive reachability question (anchorability on the revocation-free graph); blocks target delegations, never other blocks, so mutual invisibility is trivial rather than imposed. Stratum 2: liveness, with negation only over stratum-1 output — the negated predicate is now binary, `blocked(cert, node)`, instead of unary `revoked(cert)`, making liveness a route search with per-target node exclusions. Still a least fixed point, still assume-dead-on-revisit for cycles, still a pure function of the set. The one real cost is algorithmic, not semantic: per-target route filtering complicates sharing a single widest-path pass across all targets; blocks are sparse, so compute globally and patch blocked targets.

#### Residue

Within-epoch grief is unchanged — Mallory blocks routes through `mods1` until the rotation lands; rotation remains the response. MAD at flat roles is unchanged (Finding 6). Ever-apex admins can block everything, since every route transits Owners — the apex being the apex; keep it minimal. Nesting expands anchorability transitively, so constitutional flatness stays load-bearing — but the failure is bounded even then: contamination reaches nested child roles, never `doc1`, because no topology can put anyone in a position to anchor at the subject.

## The Junction

Every path through the scenario arrives at the same choice about third-party denials — and in particular about deep cuts:

| | Third-party denial | Mallory | Deep cuts (Bob cuts Eve) | Formal core | Signature costs |
|---|---|---|---|---|---|
| Design A, upstream rule | unconditional (permanence) | griefs the ever-downstream cone until it is all rotated | yes | timeless, 2 strata | grief unbounded by visibility (Finding 3) |
| Design A, anchor-scoped | unconditional, roster-local | contained to nodes she was constitutionally in | no | timeless, 2 strata | pays for permanence without the feature it bought |
| Option 1 | conditional on live topology | ends at rotation | yes, until the path rotates | timeless, 3 strata | fail-open windows; resurrection lever; perpetual re-signing |
| Option 2 | ordered (pre-boot only) | one bounded backdated sweep | yes | causal DAGs per pair | ordering metadata; purity lost |
| Retract & rotate (Design B) | none | zero | no — via Dan or rotation | timeless, semipositive | coarse removal collectively punishes (Finding 7); peer-removal gap |
| Jurisdiction-scoped blocks (option 3) | permanent in validity, scoped in effect | contained to her service record, by construction | yes — re-scoped per rotation | timeless, 2 strata | re-scope on rotation (moot, not void); apex block power; epoch grief until rotation |

Unconditional denials buy durable removal and cost permanent grief. Conditional denials cost fail-open resurrection. Ordered denials cost the timeless core. No denials cost removal ergonomics. Option 1 is not a stable point — it decomposes into a mix of the first and last. Option 3 is the genuine fourth point, reached by scoping a denial's _effect_ rather than its _validity_: denials stay unconditional (monotone, permanent) while their reach is confined to a jurisdiction. It preserves the timeless core, deep cuts, healing-with-provenance, and spatial containment as a theorem. Option 3 was adopted — and then simplified further by the second convergence below, which eliminated the explicit jurisdiction field in favor of the issuer's service record and dissolved option 3's one residual cost (re-scoping blocks on rotation).

## The Second Convergence: Field Elimination

A second pass interrogated every certificate field. Each elimination follows the same move: where a certificate format wants a *mode*, the graph wants a *vertex*.

### `from` on delegations — eliminated

The field did three jobs; each has a node-based replacement that is structurally stronger:

| Job | Replacement | Why stronger |
|---|---|---|
| Venue (which admins can moderate the act) | `sub`-scoping: a membership-shaped cert (`sub: Role`) grounds every route at the role, so the role's admins always reach it | Venue coincides with subject; no separate field to get wrong |
| Pinning (act dies with my standing in a jurisdiction, regardless of my other routes) | Sub-scoped intermediary (`M2`): route the grant through a node whose inbound is `sub`-pinned | The pin is topological — leakage onto the issuer's other standings is inexpressible, not just forbidden |
| Capacity filing ("what did Dan do as a mod") | Capacity key (`D_m`): a dedicated keypair whose only inbound is a pinned membership | Enumeration is `iss: D_m`; collective kill is one cut on the capacity key's inbound; leakage onto personal standing is topologically impossible |

The decisive argument against keeping `from`: rotation. Certificates anchored by a field die when the anchor rotates and must be enumerated and re-signed — the sweep exists *because* the field exists (the field creates the breakage, then sells the tool to fix it). With no anchor field, member grants ride whatever membership is live: rotation re-issues exactly the roster, and everything survivors issued re-grounds automatically. Rotation cost fell from $O(\text{certs at the node})$ to $O(\text{roster})$, and the spine pattern became unnecessary — every grant is spine-like natively.

What was checked before cutting: the total-kill guarantee (a block on an unpinned cert is per-route and future-open — the issuer gaining a new route revives the target silently; answered by pinning-via-`sub` for certs that want total killability), and the multi-hatted issuer case (Dan with a personal route: his `sub`-pinned acts still die with the pinned standing). An *optional* `from` (pin bit) was considered and rejected: required or cut, period.

### `nonce` vs `after` — `after` won on fail-direction

Ed25519 is deterministic and certs are content-addressed: an identical re-issuance is byte-identical — the *same certificate*, still covered by any revocation naming it. Healing a mistaken removal on the same terms by the same issuer is impossible without a freshness field. The candidates:

- *Nonce:* unconditional freshness. Failure mode: accidental duplicates are independently live certs, each needing separate coverage at removal — a missed one is a lingering live grant. **Fails open.**
- *`after: Hash<Delegation>`* (optional; omitted on first issuance): freshness on demand, dedup by default, and the heal is an accountable act ("re-granted, knowing of the revocation"). Failure mode: an issuer unaware of a revoked twin re-mints the same hash and the grant silently doesn't take — visible on sync, fixed by re-chaining. **Fails closed.**

"Ambiguity resolves toward less authority" decides it. Constraints: optional, where absence means "no predecessor claimed" — the anti-optionality rule bans absence *aliasing* a present value (the `{from: None} ≡ {from: iss}` bug), and with no sentinel, `after`'s absence has no present-value twin: one meaning, one encoding; zero semantics (not supersession, not ordering — issuer-supplied predecessors must never carry trust, or backdating-by-omission returns); bogus values harmless.

### `via` on revocations — collapsed into the issuer

Option 3's block named its jurisdiction explicitly. Two refinements removed the field:

1. *Node, not hash.* A `via` naming a specific delegation hash fails "edges are certificates": the drawn edge Members→Dan may be several certs plus future re-adds, and hash-via covers exactly one — whack-a-mole against ordinary roster churn. Blocks speak about *venues*, so `via` must be a node.
2. *Any node I control, not one I name.* Scoping the effect to the issuer's whole *service record* — every node they were ever Admin-anchorable at — matches the actual intent ("out of everything I govern"), and dissolves option 3's residual cost: a surviving admin's record grows as they are re-rostered into successor nodes, so their old revocations cover the successors automatically. **The carry-over deny-list liturgy stopped existing.** A griefer's record froze at ejection, so their cuts stay pinned to dead nodes. Coverage drift exists but only grows — fail-closed. Narrow denial (ban in room A, not room B) is signing with the narrow capacity key: the field became the identity slot.

With the scope derivable from `iss`, the revocation is `{iss, revoke, sig}`.

### The self-axiom — tombstones become corollaries

Add `record(K) ⊇ {K}` (every key governs its own node) and note that a cert's endpoints are on all of its routes. Then a revocation by the target's issuer or recipient is automatically *total* — retraction and renunciation stop being special cases with their own validity rule; one rule covers everything. Granted in passing: any intermediate, at any level, can refuse to let their own standing carry a third party's cert — deny-only, hop-confined, and strictly weaker than renouncing, which anyone could already do.

### Probed and kept: the Admin gate

"Should Edit members revoke others at ≤ their level?" was tested and rejected. Delegating ≤ your level is constructive and self-scoped; revoking a third party's cert is an act on the graph — governance, categorically. Level-relative revocation would have destroyed the headline containment theorem (*inviting a thousand editors adds zero grief surface*), created editor-tier MAD among a large unvetted population, and made every conveyance level a governance level. The tier structure stands: anyone over their own hop, signers over their own certs, ever-admins over their estates.

### The evaluator

The final semantics stratify as one engine run twice:

```
stratum 0: all certs
stratum 1: liveness fixpoint IGNORING ALL REVOCATIONS → record(K) → covered(cert, node)
stratum 2: liveness with per-cert node exclusions      (the only negation)
```

Records computed on the raw graph preserve permanence, mutual invisibility, and kill the resurrection lever in one stroke: every stratum is monotone, every arrow points fail-closed, and the set digest remains a perfect cache key.

### Final certificate shapes

```
Delegation: {iss, aud, sub, can, after: Option<Hash>, sig}
Revocation: {iss, revoke, sig}
```

Every scoping mechanism is a key or a node — capacities are dedicated keys, jurisdictions are rosters, pinning is `sub`, denial scope is the signer's record. Each surviving field defeated an elimination attempt; each eliminated field's jobs moved into the graph.

<!-- Links -->

[keyline]: README.md
[keyline-flat]: README.md#constitutional-flatness
[keyline-memberships]: README.md#memberships-as-the-only-shape
[keyline-open]: README.md#open-questions
[keyline-renounce]: README.md#renunciation
[the second convergence: field elimination]: #the-second-convergence-field-elimination
