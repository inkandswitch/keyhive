# Keyline Patterns

Companion to the [Keyline design][keyline]. None of the following require mechanism beyond delegations and revocations; they are arrangements of nodes. Where an earlier draft used certificate fields for these jobs, the graph now uses vertices.

> All problems in computer science can be solved by another level of indirection.
>
> — attributed to [David Wheeler](https://en.wikipedia.org/wiki/David_Wheeler_(computer_scientist))


## Roles

A "role" is just a node: mint a key, grant authority *to* it (supplies), and grant authority *over* it to its members (memberships). Because nodes are undifferentiated keys, a role participates in the graph exactly like an individual.

```
              ┌────────┐
     Admin    │ Brooke │    Admin (root)
   ┌──────────┤        ├──────────┐
   ▼          └────────┘          ▼
┌─────────┐   supply {iss: Brooke, aud: Members, sub: Doc, can: Admin}
│ Members │──────────────────────►┌─────┐
└─────────┘                       │ Doc │
 ▲   ▲                            └─────┘
 │   └──────── Bob   {iss: Brooke, aud: Bob,   sub: Members, can: Admin}
 └──────────── Alice {iss: Brooke, aud: Alice, sub: Members, can: Admin}
```

The role's signing key is ephemeral: create the key, sign any ceremony edges, discard it. The role never signs again — authority flows *into* it via supplies (signed by whoever holds the supplied authority) and *through* it via memberships. Members at Admin manage the roster; members at Edit or Read merely transit ([`sub` is a scope][sub is a scope, not an endpoint]). "Invite at a level" is just a membership with a `can` ceiling — attenuation does the rest.

## Pinning: Sub-Scoped Intermediaries

To grant while *submitting the grant to a jurisdiction's oversight* — dies with your standing there, killable by its admins — route it through a node pinned by `sub`:

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
                   │ Dave │
                   └──────┘
```

- *Assignable revocation rights.* Dave — no authority over Members or Doc — has `C` in his record and can cut its edges. The kill switch became a grantable capability.
- *Pre-installed cut points.* Cutting the single edge into `C` severs everything downstream, no enumeration.
- *Revoking the unseen.* `Revoke` names a hash, which requires having seen it. A caretaker at a trust boundary lets you sever a whole unseen subtree by cutting the one edge you *do* hold.

Unlike ocap caretakers, a certificate node is inert — it cannot filter, log, or rate-limit. Only the revocability transfers. In the ocap reading, every Keyline node is a forwarder that may decline to forward: revocation *in its entirety* is forwarders declining — at their own hop (self), across their estate (record), or at a purpose-built proxy (caretaker).

## Rotating a Role

Durable ejection from a role is achieved by abandoning the role node (see [The Ex-Admin Sharp Edge]):

1. Mint `Members′` (ephemeral key; discard).
2. Re-issue the role's supplies to `Members′`; retract the old ones.
3. Re-add the surviving members — *the roster is the entire sweep*.
4. For hygiene, explicitly revoke the ejected member's certificates — permanent, so the removal survives any future re-add of the old key.

Because delegations carry no anchor field, nothing except the roster is attached to the rotated node. Members' grants ride their memberships: the moment a survivor is re-rostered, everything they issued re-grounds through `Members′` automatically. Same certificates, same hashes, zero re-signing. Deny-state migrates the same way. Deep certificates keep their hashes, so explicit revocations keep biting, and surviving admins' revocations extend to `Members′` on their own (records grow with re-rostering). The ejected admin's record froze at a node that no longer routes anything.

$$\text{rotation cost} = O(\text{roster})$$

An earlier draft paid $O(\text{certificates anchored at the node})$ and needed a "spine" pattern to avoid re-anchoring churn; with no anchor field, every grant behaves spine-like natively.[^x509]

[^x509]: Contrast proof-chain systems: an X.509-style certificate hardwires its intermediates, so rotating one intermediate CA re-issues the entire subtree below it. No proofs (CRDT/order-independence), permanence, and rotation-as-hygiene each make the others affordable: disposable jurisdictions are the entire mitigation story for permanence's sharp edges.

### Reconnection and Sealing

Revocation kills certificates, not futures: a cut supply can never return, but a *fresh* grant to the abandoned node is a new hash. And the abandoned node is not empty — its constitution is self-grounded and never died. If anyone with live authority re-supplies the old node, every dormant membership re-energizes at once, and the re-energized jurisdiction is again grief-able by its ever-admins. "Dead" means "dead while everyone remembers not to reconnect" — institutional memory as a security control. Three tiers, cheapest first:

| Tier                            | Mechanism                                                                                                                        | Protects against                                     |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| Boot + move (standard)          | Retract supplies, mint successor, re-roster                                                                                      | All current authority; the ex-admin can never follow |
| Burned-node detection (tooling) | The supply retraction is a permanent signed record that the node was cut; warn loudly on grants *to* such nodes                  | Accidental reconnection — the realistic vector       |
| Sealing (hardening)             | Explicitly revoke every constitutional edge: seniors cut peers, then renounce their own ([renunciation] covers the last one out) | Even deliberate reconnection revives nothing         |

## Constitutional Flatness

Whether ever-admin power *cascades* is a topology choice, made when roles are wired together:

| | Nested (contaminating) | Flat (contained) |
|---|---|---|
| Wiring | `{aud: Mod1, sub: TeamX, can: Admin}` — an upstream role in TeamX's constitution | `{aud: TeamX, sub: Doc}` supply, or a ≤Edit membership |
| TeamX's constitution | Names Mod1 | Names individuals (Dave, Erin) — never an upstream role |
| Consequence | Every Mod1 admin ever holds Admin over TeamX — permanent revocation coverage over everything TeamX-grounded | Upstream admins never hold Admin over TeamX; their control is the supply line: total, coarse, and cleanly severable |

A record contains every node its holder ever reached *as a subject* with Admin. Granting an upstream role Admin over a child role puts the child in every upstream admin's record — permanently, since records never shrink — and rotating the parent does not escape it. The rule:

> Never grant Admin over a child role to an upstream role. Parents govern children by controlling their supplies (total, coarse: cut and re-grant to a successor), not by entering their constitutions. Constitutional membership is permanent contamination; supply control is not.

Transit-level nesting (a child role holding an Edit-level membership in a parent) is safe: only holding Admin over a node enters records, so an Edit membership adds nothing. With flat constitutions, ever-Admin is non-transitive by construction, and an ex-admin's record is exactly the rosters they sat on. No topology mistake can reach the subject itself ([the root edge protects itself][the root edge protects itself]).

## Memberships as the Only Shape

With no anchor field, the schema itself enforces what an earlier draft could only recommend: humans hold *memberships in roles, at a level*; the only `sub: Doc` edges are supplies. Every grant is a membership; individual grants are memberships in [caretaker][caretakers] roles of one.

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

What the shape buys:

- *Griefing containment.* Records are built from holding Admin over a node, so Read- and Edit-level members acquire no ever-power. Inviting a thousand editors adds zero grief surface.
- *Rotation is exactly the roster* — see [Rotating a Role].
- *One membership, N documents.* A role's portfolio covers many subjects; future supplies propagate by late binding without touching a single membership certificate.
- *Offboarding is one revocation.* Cutting a membership severs the whole portfolio; orphaned per-resource grants cannot occur, because per-resource grants on humans do not exist.

Two costs, honestly: invitation is an admin act (a membership is a constitutional edge; an Edit member cannot invite — the escape valve is a singleton caretaker to re-share from), and a role's portfolio is a blast radius: membership is all-or-nothing across it, so portfolio boundaries are access-control decisions, not org-chart decorations.


<!-- Links -->

[keyline]: README.md
[caretakers]: #caretakers
[renunciation]: README.md#renunciation
[roles]: #roles
[rotating a role]: #rotating-a-role
[sub is a scope, not an endpoint]: README.md#sub-is-a-scope-not-an-endpoint
[the ex-admin sharp edge]: README.md#the-ex-admin-sharp-edge
[the root edge protects itself]: README.md#the-root-edge-protects-itself
