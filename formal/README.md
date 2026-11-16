# Formal Models

Tests check the examples someone thought of. A model checks every behaviour of an abstraction, including the ones nobody thought of, but only of the abstraction. Each tool below answers a different kind of question, so Keyhive uses several tools.

> [!NOTE]
> These models abstract the design in `design/`. A result holds for the model. Where the code departs from the design, the model says nothing about the code.

## Which Tool for Which Question

| Question                                                                                                  | Tool    | Model                              |
|-----------------------------------------------------------------------------------------------------------|---------|------------------------------------|
| Who can learn which keys and content, and can anyone make a reader accept what no member wrote?           | Tamarin | [`content.spthy`](./content.spthy) |
| Does Keyline give the intended authority for every small set of certificates?                             | Alloy   | Not started                        |
| Do replicas converge, and do safety properties hold under every order of sync, merge and CGKA operations? | Quint   | Not started                        |
| Does the Rust code do what the design says: codecs, padding arithmetic, no panics?                        | Kani    | Not started                        |
| Machine-checked proofs of the semantics                                                                   | Lean    | Later                              |

### Tamarin: Cryptographic Constructions

Tamarin models an active adversary who controls the network, decrypts with any key it learns, and can be handed secrets (a compromised device, a leaked read capability). It proves properties over an unbounded number of documents, blocks and readers. That fits the questions where the danger is what an adversary can derive: key flow in causal encryption, key commitment, authenticity of what a reader opens.

Its cryptography is symbolic. Hashes never collide, ciphers reveal nothing without the key, and lengths and timing do not exist. So Tamarin says nothing about padding (T8), compression oracles (T10) or side channels; those are argued in `design/threat_model.md`. Proof search may not terminate, and keeping it terminating takes helper lemmas and tactics (see [Modelling Conventions](#modelling-conventions)).

Candidates after content encryption: the seal used for BeeKEM node secrets and wrapped root secrets, and invitation encryption.

### Alloy: Keyline's Authority Function

Keyline's answer is a pure function of a set of signed certificates. That is a relational question with no adversary knowledge and no time, which is what Alloy is built for: it searches every set of certificates up to a size bound for one that breaks a stated property. Most bugs in graph rules show up in small graphs, so a bound of a few principals and certificates finds most of what can go wrong. Examples: revocation only ever removes authority; no derived level is higher than a grounded derivation supports (ADR-008).

### Quint: Replica Dynamics

Convergence and ordering are properties of a system over time: replicas exchange events in any order, merge, go offline and come back. Quint (the TLA family, with types and a programmer's syntax) states these as state machines with invariants and temporal properties. Its simulator finds shallow bugs fast, and its model checkers (Apalache, TLC) search exhaustively up to a bound. Quint over plain TLA+: the same logic, but types catch modelling mistakes early, and the syntax is closer to the Rust it describes.

### Kani, Then Verus: The Rust Code

Kani model-checks the actual Rust code up to a bound, with no rewrite: codec round-trips at every length up to the bound, `padded_len`'s arithmetic, absence of panics and overflow. Verus can prove full functional correctness, but the code must be written in its dialect with proof annotations, which is a much larger commitment. Start with Kani.

### Lean: Proofs of the Semantics

Lean can prove the semantics themselves: that Keyline's evaluation is a least fixed point, that it is a function of the set alone. Such proofs are expensive to keep up while the design changes, so they wait until the semantics settle.

## Tamarin: Content Encryption

[`content.spthy`](./content.spthy) models a block's application key, its subkeys, the synthetic nonce, the AEAD, and the envelope that carries a predecessor's key (`design/ciphersuite.md`, "Content" and "Synthetic Nonce and Key Commitment"). Abstractions: one CGKA epoch, one chunk per block, one predecessor per block, content refs as fresh public names. The AEAD alone is not key-committing (rule `Forge_Ciphertext`), so the model shows that the BLAKE3 nonce check is what commits.

Every result is the intended one. How to read the column depends on the lemma's kind:

- _Sanity_ lemmas ask whether something can happen at all. "Possible" is the goal: it shows the model can do what the properties constrain, so they cannot hold vacuously. Tamarin reports these as "verified", since it found the trace it was asked for.
- _Properties_ and _helpers_ must hold in every trace. "Verified" is the goal.
- The _control_ lemma states something Keyhive does not promise. "Falsified" shows the model finds the attack the threat model expects.

| Lemma                                          | Kind                                                                | Result                 |
|------------------------------------------------|---------------------------------------------------------------------|------------------------|
| `executable_causal_read`                       | Sanity: a member reads a block, then its parent                     | Possible, as intended  |
| `executable_forged_read`                       | Sanity: a forged ciphertext can be accepted                         | Possible, as intended  |
| `executable_child_cap_reveals_parent_key`      | Sanity: the adversary can decrypt                                   | Possible, as intended  |
| `one_ciphertext_one_body`                      | Key commitment                                                      | Verified               |
| `key_origin`                                   | Helper: one step of key flow                                        | Verified               |
| `parent_lineage`                               | Helper: a child's lineage extends its parent's                      | Verified               |
| `keys_flow_only_backwards`                     | A key reaches only its block's and descendants' read caps           | Verified               |
| `payload_secrecy`                              | Content follows its key                                             | Verified               |
| `app_key_origin`                               | Helper: a known key is a leaked group secret's or an honest block's | Verified               |
| `member_reads_are_authentic`                   | A member opens only what a member wrote, unless a key leaked        | Verified               |
| `envelope_step_is_authentic`                   | The same for one step back through an envelope                      | Verified               |
| `member_reads_are_authentic_without_read_caps` | Control: content is not signed, so a read cap can forge             | Falsified, as intended |

Not yet shown: that `one_ciphertext_one_body` fails without the nonce check (`-D=NO_NONCE_CHECK`). The search for that counterexample does not terminate yet.

### Running

> [!WARNING]
> Tamarin can use all available memory and freeze the machine. Cap its memory, and prove one lemma per process.

Tamarin is not in the flake's dev shell:

```sh
nix shell nixpkgs#tamarin-prover nixpkgs#maude
```

Prove one lemma, with Tamarin's heap capped:

```sh
tamarin-prover --prove=keys_flow_only_backwards formal/content.spthy +RTS -M4G -N1 -RTS
```

The `+RTS` flags cap Tamarin's own heap, but Maude runs as a separate process. The runs behind the table above also put a `maude` wrapper first on `PATH` that runs `ulimit -v 4000000` before calling the real `maude`. Do not set `ulimit -v` for Tamarin itself: it then fails at start with `failed to create OS thread: Cannot allocate memory`. Capping the whole process tree with `systemd-run --user --scope -p MemoryMax=6G tamarin-prover …` should also work, but has not been tried.

Useful checks:

- `tamarin-prover formal/content.spthy` loads the theory and reports well-formedness problems.
- `--precompute-only` should report "deconstructions complete". Partial deconstructions are the usual reason a proof search does not end.
- `--bound=N` stops the search at depth `N` and prints the proof tree so far, which shows which goal it keeps unfolding.

### Modelling Conventions

- _Write `KU(t)` for "the adversary knows `t`"._ In a lemma, `K(t)` means the adversary _sent_ `t` to a protocol rule. With `K()`, a secrecy lemma assumes less than intended, and an induction hypothesis never applies to a key the adversary learned without sending it.
- _Spell out what persistent facts hold._ A premise like `!Block(doc, ~pr, ppreds, kdf_app(gs, h(ppreds), ~pr), pl)` tells Tamarin a ref is fresh and a key has a known shape. Without it, Tamarin cannot finish the adversary's deconstructions.
- _Prove one step, then induct._ A transitive property (keys flow back through any number of envelopes) is an induction over a one-step `[reuse]` lemma (`key_origin`). The one-step lemma must say everything the induction step needs, including the order of events.
- _Use tactics for public data._ Refs, document ids, hashes and nonces are on the wire, and the adversary learns them from many rules. The `wire_last` tactic solves those goals last.
- _Pair every property with a sanity lemma._ An exists-trace lemma shows the behaviour the property constrains can happen at all. Without one, a property can hold only because the model cannot do anything.
