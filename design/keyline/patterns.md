# Keyline Patterns

Companion to the [Keyline design][keyline]. None of the following require mechanism beyond delegations and revocations; they are arrangements of nodes. Where a certificate format would use a field, the graph uses a vertex.

> All problems in computer science can be solved by another level of indirection.
>
> — attributed to [David Wheeler](https://en.wikipedia.org/wiki/David_Wheeler_(computer_scientist))


## Roles

A "role" is just a node: mint a key, grant authority _to_ it (supplies), and grant authority _over_ it to its members (memberships). Because nodes are undifferentiated keys, a role participates in the graph exactly like an individual.

```
              ┌────────┐
     Admin    │  Dan   │    Admin (root)
   ┌──────────┤        ├──────────┐
   ▼          └────────┘          ▼
┌─────────┐   supply {iss: Dan, aud: Members, sub: Doc, can: Admin}
│ Members │──────────────────────►┌─────┐
└─────────┘                       │ Doc │
 ▲   ▲                            └─────┘
 │   └──────── Bob   {iss: Dan, aud: Bob,   sub: Members, can: Admin}
 └──────────── Alice {iss: Dan, aud: Alice, sub: Members, can: Admin}
```

The role's signing key is ephemeral: create the key, sign any ceremony edges, discard it. The role never signs again — authority flows _into_ it via supplies (signed by whoever holds the supplied authority) and _through_ it via memberships. Members at Admin manage the roster; members at Edit or Read merely transit ([`sub` is a scope][sub is a scope, not an endpoint]). "Invite at a level" is just a membership with a `can` ceiling — attenuation does the rest.

## Pinning: Sub-Scoped Intermediaries

To grant while _submitting the grant to a jurisdiction's oversight_ — dies with your standing there, killable by its admins — route it through a node pinned by `sub`:

```
Dan grants Eve, submitted to Members:

  mint M2
  {iss: Dan, aud: M2,  sub: Members, can: Edit}    pinned: routes ground at Members
  {iss: Dan, aud: Eve, sub: M2,      can: Edit}    Eve's membership in M2
```

Any Members admin can cut `Dan → M2` totally (all its routes transit Members); the whole construction dies with Dan's Members-standing regardless of his other routes. Pinning is voluntary submission — trading resilience for governability — and it is a topology choice, made per grant.

## Caretakers

The ocap caretaker — interpose a cuttable proxy between grantor and grantee — is a single-purpose role. Mint `C`, route the grant through it, hand the kill switch to whoever should hold it:

```
┌─────────┐  Edit   ┌───┐  Edit   ┌───────┐
│ Members │────────►│ C │────────►│ Carol │
└─────────┘         └───┘         └───────┘
                      ▲ Admin
                      |
                   ┌──────┐
                   │ Dan  │
                   └──────┘
```

- _Assignable revocation rights._ Dan — no authority over Members or Doc — has `C` in his admin reach and can cut every edge grounded there. The kill switch became a grantable capability.
- _Pre-installed cut points._ `C` has one roster edge (`sub: C`, to Carol); cutting it severs everything downstream, no enumeration. The supply edge _into_ `C` stays its issuer's to cut: the recipient of an edge is not on its route.
- _Revoking the unseen._ `Revoke` names a hash, which requires having seen it. A caretaker at a trust boundary lets you sever a whole unseen subtree by cutting the one edge you _do_ hold.

Unlike ocap caretakers, a certificate node is inert — it cannot filter, log, or rate-limit. Only the revocability transfers. In the ocap reading, every Keyline node is a forwarder that may decline to forward: revocation _in its entirety_ is forwarders declining — at their own hop (self), across their admin reach, or at a purpose-built proxy (caretaker).

## Rotating a Role

Durable ejection from a role is achieved by abandoning the role node (see [The Ex-Admin Sharp Edge]):

1. Mint `Members′` (ephemeral key; discard).
2. Re-issue the role's supplies to `Members′`; retract the old ones.
3. Re-add the surviving members — _the roster is the entire sweep_.
4. For hygiene, explicitly revoke the ejected member's certificates — permanent, so the removal survives any future re-add of the old key.

Because delegations carry no anchor field, nothing except the roster is attached to the rotated node. Members' grants ride their memberships: the moment a survivor is re-rostered, everything they issued re-grounds through `Members′` automatically. Same certificates, same hashes, zero re-signing. Deny-state migrates the same way. Deep certificates keep their hashes, so explicit revocations keep biting, and surviving admins' revocations extend to `Members′` on their own (records grow with re-rostering). The ejected admin's record froze at a node that no longer routes anything.

$$\text{rotation cost} = O(\text{roster})$$

Proof-chain systems pay $O(\text{certificates anchored at the node})$ and need a "spine" pattern to avoid re-anchoring churn; with no anchor field, every grant behaves spine-like natively.[^x509]

[^x509]: Contrast proof-chain systems: an X.509-style certificate hardwires its intermediates, so rotating one intermediate CA re-issues the entire subtree below it. No proofs (CRDT/order-independence), permanence, and rotation-as-hygiene each make the others affordable: disposable jurisdictions are the entire mitigation story for permanence's sharp edges.

### Reconnection and Sealing

Revocation kills certificates, not futures: a cut supply can never return, but a _fresh_ grant to the abandoned node is a new hash. And the abandoned node is not empty — its constitution is self-grounded and never died. If anyone with live authority re-supplies the old node, every dormant membership re-energizes at once, and the re-energized jurisdiction is again grief-able by its ever-admins. "Dead" means "dead while everyone remembers not to reconnect" — institutional memory as a security control. Three tiers, cheapest first:

| Tier                            | Mechanism                                                                                                                        | Protects against                                     |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| Boot + move (standard)          | Retract supplies, mint successor, re-roster                                                                                      | All current authority; the ex-admin can never follow |
| Burned-node detection (tooling) | The supply retraction is a permanent signed record that the node was cut; warn loudly on grants _to_ such nodes                  | Accidental reconnection — the realistic vector       |
| Sealing (hardening)             | Explicitly revoke every constitutional edge: seniors cut peers, then renounce their own ([renunciation] covers the last one out) | Even deliberate reconnection revives nothing         |

## Constitutional Flatness

Whether ever-admin power _cascades_ is a topology choice, made when roles are wired together:

| | Nested (adjudicable) | Flat (contained) |
|---|---|---|
| Wiring | `{aud: Mod1, sub: TeamX, can: Admin}` — an upstream role in TeamX's constitution | `{aud: TeamX, sub: Doc}` supply, or a ≤Edit membership |
| TeamX's constitution | Names Mod1 | Names individuals (Eve, Frank) — never an upstream role |
| Consequence | Every Mod1 admin, ever, holds Admin over TeamX: they can adjudicate inside it (cut any roster entry, without a separate grant), and that power is permanent — revocation coverage over everything TeamX-grounded, surviving rotation of Mod1 | Upstream admins never hold Admin over TeamX; their control is the supply line: total, coarse, and cleanly severable |

Admin reach is composed: it contains every node its holder ever held Admin over, directly or through a role. Granting an upstream role Admin over a child role therefore puts the child in every upstream admin's reach — permanently, since reach never shrinks — and rotating the parent does not escape it. That is the point of nesting when seniors are meant to adjudicate inside junior roles, and the cost when they are not. Choose per role:

> Nest when the parent's admins should be able to cut inside the child. Keep the constitution flat when the child should be governable only wholesale: parents then control the supply (cut and re-grant to a successor) and never enter the child's roster. Nesting is permanent; supply control is not.

Transit-level nesting (a child role holding an Edit-level membership in a parent) is safe either way: only holding Admin over a node enters reach, so an Edit membership adds nothing. Under flat constitutions an ex-admin's reach is exactly the rosters they sat on. The same choice applied at the top is the [rooting level][rooting level]: a document supplied at Admin puts itself in every apex admin's reach; supplied at Edit, it is in nobody's.

## Rooting Level

Admin over a document gates exactly one thing: reach over the document's routes. Delegation needs no level, and membership is governed by Admin over the _role_, so the level the ceremony's root edge carries is a choice about who can destroy the document, and nothing else.

| Root edge                                       | Doc is in the admin reach of       | Root edge deniable by                                       | Retained subject key                                                                     |
|-------------------------------------------------|------------------------------------|-------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `{iss: Doc, aud: Owners, sub: Doc, can: Admin}` | every Admin member of Owners, ever | any of them; one revocation bricks the document | cannot escape: old admins' reach covers `Doc → Owners′` too |
| `{iss: Doc, aud: Owners, sub: Doc, can: Edit}` | nobody | nobody | re-roots cleanly: old admins' reach holds Owners, which the new hierarchy never transits |

Edit-rooting costs nothing in capability: humans reach the document at Edit, which is all the conveyance there is, and govern it through Admin over its roles. It is the shape for a document whose owners should be able to leave without taking it with them. Admin-rooting is the shape when the owners _are_ the document — a personal document, a two-party agreement — and being able to end it unilaterally is the point. The power it grants is not new: a root admin can already eject every peer and lose their own key.

A document's rooting level is fixed at the ceremony (the root edge cannot be replaced without the subject key) and is visible to anyone holding the set, so it is a published fact about the document rather than a policy.

## Memberships as the Only Shape

With no anchor field, the schema enforces the shape: humans hold _memberships in roles, at a level_; the only `sub: Doc` edges are supplies. Every grant is a membership; individual grants are memberships in [caretaker][caretakers] roles of one.

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
                      Dan                  Alice   Bob   Carol
```

What the shape buys:

- _Griefing containment._ Admin reach is built from holding Admin over a node, so Read- and Edit-level members acquire no ever-power. Inviting a thousand editors adds zero grief surface.
- _Rotation is exactly the roster_ — see [Rotating a Role].
- _One membership, N documents._ A role's portfolio covers many subjects; future supplies propagate by late binding without touching a single membership certificate.
- _Offboarding is one revocation._ Cutting a membership severs the whole portfolio; orphaned per-resource grants cannot occur, because per-resource grants on humans do not exist.

Two costs: invitation is an admin act (a membership is a constitutional edge; an Edit member cannot invite — the escape valve is a singleton caretaker to re-share from), and a role's portfolio is a blast radius: membership is all-or-nothing across it, so portfolio boundaries are access-control decisions, not org-chart decorations.


<!-- Links -->

[keyline]: README.md
[caretakers]: #caretakers
[renunciation]: README.md#renunciation
[roles]: #roles
[rotating a role]: #rotating-a-role
[sub is a scope, not an endpoint]: README.md#sub-is-a-scope-not-an-endpoint
[the ex-admin sharp edge]: README.md#the-ex-admin-sharp-edge
[rooting level]: #rooting-level
