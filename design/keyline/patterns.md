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
┌─────────┐   supply {issuer: Dan, audience: Members, subject: Doc, power: Admin}
│ Members │──────────────────────►┌─────┐
└─────────┘                       │ Doc │
 ▲   ▲                            └─────┘
 │   └──────── Bob   {issuer: Dan, audience: Bob,   subject: Members, power: Admin}
 └──────────── Alice {issuer: Dan, audience: Alice, subject: Members, power: Admin}
```

The role's signing key is ephemeral: create the key, sign the creation edges, discard it. The role never signs again. Authority flows _into_ it via supplies (signed by whoever holds the supplied authority) and _through_ it via memberships. Members at Admin manage the roster; members at Edit or Read merely transit ([`subject` is a scope][subject is a scope, not an endpoint]). "Invite at a level" is just a membership with a `power` ceiling, and attenuation does the rest.

## Pinning: Sub-Scoped Intermediaries

To issue a delegation that answers to a role's admins (it dies with your standing in that role, and the role's admins can kill it), route it through a node pinned by `subject`:

```
Dan grants Eve, submitted to Members:

  mint M2
  {issuer: Dan, audience: M2,  subject: Members, power: Edit}    pinned: routes ground at Members
  {issuer: Dan, audience: Eve, subject: M2,      power: Edit}    Eve's membership in M2
```

Any Members admin can revoke `Dan → M2` totally (all its routes transit Members); the whole construction dies with Dan's Members-standing regardless of his other routes. Pinning is voluntary submission, trading resilience for governability, and it is a topology choice made per delegation.

## Caretakers

The ocap caretaker (a revocable proxy between issuer and audience) is a single-purpose role. Mint `C`, route the delegation through it, and hand the kill switch to whoever should hold it:

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

- _Assignable revocation rights._ Dan has no authority over Members or Doc, but he has `C` in his admin reach and can revoke every edge grounded there. The kill switch became a grantable capability.
- _Pre-installed revocation points._ `C` has one roster edge (`subject: C`, to Carol); revoking it severs everything downstream, with no enumeration. The supply edge _into_ `C` stays its issuer's to revoke: the audience of an edge is not on its route.
- _Revoking the unseen._ `revoke` names a hash, which requires having seen it. A caretaker at a trust boundary lets you sever a whole unseen subtree by revoking the one edge you _do_ hold.

Unlike ocap caretakers, a certificate node is inert: it cannot filter, log, or rate-limit. Only the power to revoke transfers. In the ocap reading, every Keyline node is a forwarder that may decline to forward, and all revocation is forwarders declining: at their own hop (self), across their admin reach, or at a purpose-built proxy (caretaker).

## Rotating a Role

Durable removal from a role is achieved by abandoning the role node (see [The Ex-Admin Sharp Edge]):

1. Mint `Members′` (ephemeral key; discard).
2. Re-issue the role's supplies to `Members′`; revoke the old ones.
3. Re-add the surviving members. The roster is the entire sweep.
4. For hygiene, explicitly revoke the removed member's certificates. Revocations are permanent, so the removal survives any future re-add of the old key.

Delegations name no intermediate node, so nothing except the roster is attached to the rotated node. Members' delegations ride their memberships: the moment a survivor is re-rostered, everything they issued re-grounds through `Members′` automatically. Same certificates, same hashes, zero re-signing. Deny-state migrates the same way. Deep certificates keep their hashes, so explicit revocations keep biting, and surviving admins' revocations extend to `Members′` on their own (their admin reach grows with re-rostering). The removed admin's reach froze at a node that no longer routes anything.

$$\text{rotation cost} = O(\text{roster})$$

Proof-chain systems pay $O(\text{certificates that cite the node})$ and need a "spine" pattern to avoid re-issuing them at every rotation. Delegations name no intermediate node, so every delegation already behaves like a spine.[^x509]

[^x509]: Contrast proof-chain systems: an X.509-style certificate hardwires its intermediates, so rotating one intermediate CA re-issues the entire subtree below it. No proofs (CRDT/order-independence), permanence, and rotation-as-hygiene each make the others affordable: disposable roles are the main mitigation for permanence's sharp edges.

### Reconnection and Sealing

Revocation kills certificates, not futures: a revoked supply can never return, but a _fresh_ delegation to the abandoned node is a new hash. And the abandoned node is not empty: the role's own membership edges are grounded at the role itself and never died. If anyone with live authority re-supplies the old node, every dormant membership revives at once, and anyone who ever held Admin in the role can grief it again. Abandonment holds only as long as nobody reconnects the node. The defenses, cheapest first:

| Tier                            | Mechanism                                                                                                                                                                        | Protects against                                     |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| Remove + move (standard)        | Revoke supplies, mint successor, re-roster                                                                                                                                       | All current authority; the ex-admin can never follow |
| Burned-node detection (tooling) | The supply revocation is a permanent signed record that the node was abandoned; warn loudly on delegations _to_ such nodes                                                       | Accidental reconnection, the realistic vector        |
| Sealing (hardening)             | Explicitly revoke every membership edge of the role: seniors revoke peers' memberships, then revoke their own as audience ([revocation by the audience] covers the last one out) | Even deliberate reconnection revives nothing         |

## Constitutional Flatness

A role is _flat_ when its own membership edges (the `subject: Role` delegations at Admin that say who runs it) name individuals, and _nested_ when one of them names an upstream role. The choice decides whether the power of anyone who ever held Admin upstream _cascades_ into the role, and it is made when roles are wired together:

|                       | Nested (adjudicable)                                                                                                                                                                                        | Flat (contained)                                                                                                    |
|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Wiring                | `{audience: Mod1, subject: TeamX, power: Admin}`: an upstream role among TeamX's admins                                                                                                                     | `{audience: TeamX, subject: Doc}` supply, or a ≤Edit membership                                                     |
| TeamX's Admin members | Include Mod1                                                                                                                                                                                                | Individuals only (Eve, Frank), never an upstream role                                                               |
| Consequence           | Everyone who was ever a Mod1 admin holds Admin over TeamX. They can adjudicate inside it (revoke any roster entry without a separate delegation), and that power is permanent: it survives rotation of Mod1 | Upstream admins never hold Admin over TeamX. Their control is the supply line: total, coarse, and cleanly severable |

Admin reach is composed: it contains every node its holder ever held Admin over, directly or through a role. Granting an upstream role Admin over a child role therefore puts the child in every upstream admin's reach permanently, since reach never shrinks, and rotating the parent does not escape it. That is the point of nesting when seniors are meant to adjudicate inside junior roles, and the cost when they are not. Choose per role:

> [!TIP]
> Nest when the parent's admins should be able to revoke memberships inside the child. Keep the child flat when it should be governable only wholesale: parents then control the supply (revoke and re-grant to a successor) and never enter the child's roster. Nesting is permanent; supply control is not.

Transit-level nesting (a child role holding an Edit-level membership in a parent) is safe either way: only holding Admin over a node enters reach, so an Edit membership adds nothing. When roles are flat, an ex-admin's reach is exactly the rosters they sat on. The same choice applied at the top is the [rooting level][rooting level]: a document supplied at Admin puts itself in every apex admin's reach; supplied at Edit, it is in nobody's.

## Rooting Level

Admin over a document gates exactly one thing: reach over the document's routes. Delegation needs no level, and membership is governed by Admin over the _role_, so the level of the root edge signed at creation is a choice about who can destroy the document, and nothing else.

| Root edge                                                     | Doc is in the admin reach of       | Root edge revocable by                          | Retained subject key                                                                     |
|---------------------------------------------------------------|------------------------------------|-------------------------------------------------|------------------------------------------------------------------------------------------|
| `{issuer: Doc, audience: Owners, subject: Doc, power: Admin}` | every Admin member of Owners, ever | any of them; one revocation bricks the document | cannot escape: old admins' reach covers `Doc → Owners′` too                              |
| `{issuer: Doc, audience: Owners, subject: Doc, power: Edit}`  | nobody                             | nobody                                          | re-roots cleanly: old admins' reach holds Owners, which the new hierarchy never transits |

Edit-rooting costs nothing in capability: humans reach the document at Edit, which is as much as any route can carry, and govern it through Admin over its roles. It is the shape for a document whose owners should be able to leave without taking it with them. Admin-rooting is the shape when the owners _are_ the document (a personal document, a two-party agreement) and being able to end it unilaterally is the point. The power to brick it is not new ([README, Griefing](README.md#griefing)).

A document's rooting level is fixed at creation (the root edge cannot be replaced without the subject key) and is visible to anyone holding the set, so it is a published fact about the document rather than a policy.

## Steward

One permanent key owns many documents, and the people who run them change over time. The steward is that key; the officers are a role the steward appoints and can replace.

```
Doc₁ ─┐  root edges, at Edit
Doc₂ ─┼────────────────────────► Steward          (key retained: cold storage, threshold-split)
Doc₃ ─┘                             │
                                    │  {issuer: Steward, audience: Officers, subject: Steward, power: Edit}
                                    ▼
                                 Officers ──► Alice, Bob   {issuer: Officers, audience: Alice, subject: Officers, power: Admin}
```

- _Each document_ is rooted at Edit in the steward: `{issuer: Doc, audience: Steward, subject: Doc, power: Edit}`. Nobody holds Admin over a document, so nobody can revoke its root edge ([Rooting Level][rooting level]).
- _The officers_ are an Edit member of the steward. Membership composes, so the officers reach every document the steward reaches, at Edit, including documents rooted in the steward later. Being an Edit member puts nothing in anyone's admin reach: neither the steward nor any document is in an officer's reach.
- _The roster_ is Admin over `Officers`, signed by the role key at creation and then by the officers themselves. Officers add and remove each other, and can revoke anything on routes through `Officers`, such as a delegation a removed officer issued.

Officers can delegate onward, at most Edit, and every such delegation routes through `Officers`. What they can never do is put a document into anyone's admin reach, because none of them holds Admin over one.

_Rotation_ is one revocation by the steward. It revokes `Steward → Officers`, which is total because it is the issuer, mints `Officers′`, makes it an Edit member, and re-rosters whoever stays. Everything routed through the old role dies at once. A former officer's admin reach is the old `Officers` node, which no longer routes anything, so their revocations cover nothing that matters and their new delegations convey nothing. The `steward_rotation_leaves_former_officers_nothing` scenario pins this.

The cost is the steward key. It is the one thing that cannot rotate, and whoever holds it can replace the officers or supply anyone into every document. Guard it as a recovery key: offline, threshold-split, exercised rarely. Rooting the documents at Admin instead also works, but then the steward key can brick each document as well.

The pattern is [Constitutional Flatness](#constitutional-flatness) applied at the top: the officers hold a transit-level (Edit) membership in the steward, never Admin, so the steward controls them only wholesale, through the supply line. The tempting alternative, making the officers an Admin member of the steward, puts every document in the reach of everyone who was ever an officer, permanently, and lets any officer delegate Admin over a document to someone outside the role.

## Memberships as the Only Shape

Because delegations name no intermediate node, the schema enforces the shape: humans hold _memberships in roles, at a level_; the only `subject: Doc` edges are supplies. Every delegation to a person is a membership; a delegation to one individual is a membership in a [caretaker][caretakers] role of one.

```
        ┌─────┐
        │ Doc │◄───────────── supply (subject: Doc) ────────┐
        └─────┘                                             │
                    ┌────────┐        supply        ┌───────┴──────┐
                    │ Owners │─────────────────────►│  Moderators  │
                    └────────┘    (subject: Doc)    └──────────────┘
                        ▲                              ▲    ▲    ▲
            membership  │                 membership   │    │    │   membership
        (power: Admin)  │             (power: Admin)   │    │    │   (power: Edit)
                        │                              │    │    │
                       Dan                           Alice Bob Carol
```

What the shape buys:

- _Griefing containment._ Admin reach is built from holding Admin over a node, so Read- and Edit-level members add nothing to anyone's admin reach. Inviting a thousand editors adds zero grief surface.
- _Rotation is exactly the roster._ See [Rotating a Role].
- _One membership, N documents._ A role's portfolio covers many subjects; future supplies propagate by late binding without touching a single membership certificate.
- _Offboarding is one revocation._ Revoking a membership severs the whole portfolio; orphaned per-resource delegations cannot occur, because per-resource delegations to humans do not exist.

The shape has costs. An invitation rides its inviter. Anyone may invite, at or below their own level: Carol, an Edit member, can issue `{issuer: Carol, audience: Eve, subject: Moderators, power: Edit}`, and Eve gets Edit. But Eve's membership is live only while Carol's standing is live, so removing Carol removes Eve in the same cascade. A membership that has to outlive its inviter must come from someone with independent standing. In practice that is an admin of the role, or a singleton [caretaker][caretakers] to re-share from. Only Admin-level memberships add to anyone's admin reach, so an Edit member's invitations add no grief surface.

A role's portfolio is also a blast radius. Membership is all-or-nothing across the portfolio, so portfolio boundaries are access-control decisions, not org-chart decorations.


<!-- Links -->

[keyline]: README.md
[caretakers]: #caretakers
[revocation by the audience]: README.md#revocation-by-the-audience
[roles]: #roles
[rotating a role]: #rotating-a-role
[subject is a scope, not an endpoint]: README.md#subject-is-a-scope-not-an-endpoint
[the ex-admin sharp edge]: README.md#the-ex-admin-sharp-edge
[rooting level]: #rooting-level
