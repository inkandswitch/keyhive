# Formal Models

Tests check the examples someone thought of. A model checks every behaviour of an abstraction, including the ones nobody thought of, but only of the abstraction. Each tool below answers a different kind of question, so Keyhive uses several tools.

> [!NOTE]
> Most of these models abstract the design in `design/`. A result holds for the model. Where the code departs from the design, the model says nothing about the code. The exception is [`hax/`](#hax-and-proverif-chunk-encryption), whose model is extracted from the Rust.

## Which Tool for Which Question

| Question                                                                                                  | Tool           | Model                              |
|-----------------------------------------------------------------------------------------------------------|----------------|------------------------------------|
| Who can learn which keys and content, and can anyone make a reader accept what no member wrote?           | Tamarin        | [`content.spthy`](./content.spthy) |
| Does the shipped code that seals and opens a chunk commit it to one key?                                  | hax + ProVerif | [`hax/`](./hax/)                   |
| Does Keyline give the intended authority for every small set of certificates?                             | Alloy          | Not started                        |
| Do replicas converge, and do safety properties hold under every order of sync, merge and CGKA operations? | Quint          | Not started                        |
| Does the Rust code do what the design says: codecs, padding arithmetic, no panics?                        | Kani           | Not started                        |
| Machine-checked proofs of the semantics                                                                   | Lean           | Later                              |

### Tamarin: Cryptographic Constructions

Tamarin models an active adversary who controls the network, decrypts with any key it learns, and can be handed secrets (a compromised device, a leaked read capability). It proves properties over an unbounded number of documents, blocks and readers. That fits the questions where the danger is what an adversary can derive: key flow in causal encryption, key commitment, authenticity of what a reader opens.

Its cryptography is symbolic. Hashes never collide, ciphers reveal nothing without the key, and lengths and timing do not exist. So Tamarin says nothing about padding (T8), compression oracles (T10) or side channels; those are argued in `design/threat_model.md`. Proof search may not terminate, and keeping it terminating takes helper lemmas and tactics (see [Modelling Conventions](#modelling-conventions)).

Candidates after content encryption: the seal used for BeeKEM node secrets and wrapped root secrets, and invitation encryption.

### hax and ProVerif: Models Extracted From the Code

[hax](https://github.com/cryspen/hax) translates Rust into ProVerif, a symbolic prover like Tamarin. Cryptographic primitives are replaced by symbols the model defines; the code that calls them is extracted as it is. A property proven this way holds for the code that ships, and a change to that code changes the model. The price is code shape: hax extracts only pure functions (no in-place buffers, loops, closures or `tracing` spans), so it covers small functions, not whole protocols. Tamarin keeps the questions about how blocks compose.

### Alloy: Keyline's Authority Function

Keyline's answer is a pure function of a set of signed certificates. That is a relational question with no adversary knowledge and no time, which is what Alloy is built for: it searches every set of certificates up to a size bound for one that breaks a stated property. Most bugs in graph rules show up in small graphs, so a bound of a few principals and certificates finds most of what can go wrong. Examples: revocation only ever removes authority; no derived level is higher than a grounded derivation supports (ADR-008).

### Quint: Replica Dynamics

Convergence and ordering are properties of a system over time: replicas exchange events in any order, merge, go offline and come back. Quint (the TLA family, with types and a programmer's syntax) states these as state machines with invariants and temporal properties. Its simulator finds shallow bugs fast, and its model checkers (Apalache, TLC) search exhaustively up to a bound. Quint over plain TLA+: the same logic, but types catch modelling mistakes early, and the syntax is closer to the Rust it describes.

### Kani, Then Verus: The Rust Code

Kani model-checks the actual Rust code up to a bound, with no rewrite: codec round-trips at every length up to the bound, `padded_len`'s arithmetic, absence of panics and overflow. Verus can prove full functional correctness, but the code must be written in its dialect with proof annotations, which is a much larger commitment. Start with Kani.

### Lean: Proofs of the Semantics

Lean can prove the semantics themselves: that Keyline's evaluation is a least fixed point, that it is a function of the set alone. Such proofs are expensive to keep up while the design changes, so they wait until the semantics settle.

## Tamarin: Content Encryption

[`content.spthy`](./content.spthy) models a block's application key, its subkeys, the synthetic nonce, the AEAD, and the envelope that carries a predecessor's key (`design/ciphersuite.md`, "Content" and "Synthetic Nonce and Key Commitment"). Abstractions: one CGKA epoch, one chunk per block, one predecessor per block, content refs as fresh public names, and the header's predecessors sent as they are rather than as their digest (the same for these properties; see the theory's header comment). The AEAD alone is not key-committing (rule `Forge_Ciphertext`, restricted to two distinct keys), so the model shows that the BLAKE3 nonce check is enough to commit. That the check is needed is shown on the code (see [hax and ProVerif](#hax-and-proverif-chunk-encryption)).

Every leak a lemma allows must happen before what it explains: a reveal before the adversary knows the key, a write before the read.

Every result is the intended one (Tamarin 1.12.0, Maude 3.5.1, `nix develop .#formal`; 6 minutes in all, one lemma per process). How to read the column depends on the lemma's kind:

- _Sanity_ lemmas ask whether something can happen at all. "Possible" is the goal: it shows the model can do what the properties constrain, so they cannot hold vacuously. Tamarin reports these as "verified", since it found the trace it was asked for.
- _Properties_ and _helpers_ must hold in every trace. "Verified" is the goal.
- The _control_ lemma states something Keyhive does not promise. "Falsified" shows the model finds the attack the threat model expects.

| Lemma                                          | Kind                                                                      | Result                 |
|------------------------------------------------|---------------------------------------------------------------------------|------------------------|
| `executable_causal_read`                       | Sanity: a member reads a block, then its parent                           | Possible, as intended  |
| `executable_forged_read`                       | Sanity: a forged ciphertext can be accepted                               | Possible, as intended  |
| `executable_child_cap_reveals_parent_key`      | Sanity: the adversary can decrypt                                         | Possible, as intended  |
| `key_commitment`                               | A nonce and ciphertext open under one key, AAD and body                   | Verified               |
| `key_origin`                                   | Helper: one step of key flow                                              | Verified               |
| `parent_lineage`                               | Helper: a child's lineage extends its parent's                            | Verified               |
| `keys_flow_only_backwards`                     | A key reaches only its block's and descendants' read caps                 | Verified               |
| `payload_secrecy`                              | Content follows its key                                                   | Verified               |
| `app_key_origin`                               | Helper: a known key is a leaked group secret's or an honest block's       | Verified               |
| `member_reads_are_authentic`                   | A member opens what a member wrote, where it was written, or a key leaked | Verified               |
| `envelope_step_is_authentic`                   | The same for one step back through an envelope                            | Verified               |
| `member_reads_are_authentic_without_read_caps` | Control: content is not signed, so a read cap can forge                   | Falsified, as intended |

`key_commitment` also verifies with `-D=FORGE_SAME_KEY`, which lets `Forge_Ciphertext` use one key twice. The control takes the longest, about 2 minutes. CI runs every lemma and checks each result (`nix run .#ci-tamarin`).

### Running

> [!WARNING]
> Tamarin can use all available memory and freeze the machine. Cap its memory, and prove one lemma per process.

Tamarin and Maude are in their own dev shell, kept out of the default one because they add about 460 MiB (`nix/formal.nix`):

```sh
nix develop .#formal
```

Prove one lemma with `prove`, which caps both processes and stops after a timeout:

```sh
prove keys_flow_only_backwards
prove key_commitment -D=FORGE_SAME_KEY
```

Extra arguments go to `tamarin-prover`. The limits are environment variables: `PROVE_TIMEOUT` (seconds, default 300), `TAMARIN_HEAP` (default `4G`) and `MAUDE_VMEM_KB` (default `4000000`). `THEORY` selects the model (default `formal/content.spthy`).

Why a wrapper: `+RTS -M4G -N1 -RTS` caps Tamarin's own heap, but Maude runs as a separate process. `prove` hands Tamarin a `maude` that runs `ulimit -v` first, through `--with-maude`. Shadowing `maude` on `PATH` does not work, because nixpkgs' `tamarin-prover` puts its own Maude first on `PATH`. Do not set `ulimit -v` for Tamarin itself: it then fails at start with `failed to create OS thread: Cannot allocate memory`. Running `tamarin-prover` directly in the shell works, but with no cap on Maude.

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

## hax and ProVerif: Chunk Encryption

`keyhive_content/src/encrypted.rs` seals and opens each chunk with `seal_chunk` and `open_chunk`. `cargo hax` extracts both into [`hax/extraction/lib.pvl`](./hax/extraction/lib.pvl), committed so a change shows in review. The primitives they call are methods of `ChunkCipher`, whose bodies hax replaces with the symbols of [`hax/keyhive.pvl`](./hax/keyhive.pvl): the subkey derivations, the synthetic nonce, and the AEAD. As in the Tamarin model, the AEAD is not key-committing (`ks_forge`). [`hax/analysis.pv`](./hax/analysis.pv) states the queries; the adversary chooses every key, AAD, nonce and ciphertext.

| Query                              | Kind                                                                   | Result                   |
|------------------------------------|------------------------------------------------------------------------|--------------------------|
| `event(Disagree)`                  | Key commitment: two readers open one nonce and ciphertext differently  | Not reachable            |
| `event(RoundTrip)`                 | Sanity: `open_chunk` opens what `seal_chunk` wrote                     | Reachable, as intended   |
| `event(DisagreeWithoutNonceCheck)` | Control: the same readers without the nonce check                      | Reachable, as intended   |

The control is the result Tamarin's `-D=NO_NONCE_CHECK` search does not reach: without the check, the AEAD alone does not commit. Deleting the check from `open_chunk` makes `Disagree` reachable.

What the extraction does not cover: the six `replace_body` strings in `encrypted.rs` are unchecked ProVerif, reviewed like any model; the chunk loop, the header and AAD encoding, and the causal walk are not extracted. Symbolic cryptography, as in Tamarin, so the nonce's truncation to 24 bytes is not modelled.

### Running

```sh
nix develop .#formal
prove-hax
```

`prove-hax` re-extracts into `hax/extraction/`, runs ProVerif with hax's libraries, and fails unless every verdict is the expected one. ProVerif runs under `ulimit -v` (`PROVERIF_VMEM_KB`, default `4000000`) and `PROVE_TIMEOUT`. Check `git diff formal/hax/extraction` afterwards: a diff means the code changed, and the model with it. CI runs `prove-hax` and fails on such a diff (`nix run .#ci-hax`): commit the new extraction with the code change.

To annotate more code: `#[cfg_attr(feature = "hax", hax_lib::proverif::replace_body("…"))]` on a primitive, with the symbol it names declared in `keyhive.pvl`. The `hax` feature is only for extraction.

