# Cipher Suite

| Feature            | Algorithm                                                  | Where                                              |
|--------------------|------------------------------------------------------------|----------------------------------------------------|
| Hash / KDF         | [BLAKE3] (plain hash, XOF, and `derive_key` modes)         | `keyhive_crypto::digest`, `siv`, `separable`, `beekem::pcs_key` |
| Signatures         | [Ed25519] (RFC 8032, via `ed25519-dalek`)                  | `keyhive_crypto::signed`, `verified`, `id`         |
| Key exchange       | [X25519] (RFC 7748, via `x25519-dalek`)                    | `keyhive_crypto::share_key`, BeeKEM path secrets   |
| Symmetric AEAD     | [XChaCha20-Poly1305] with a BLAKE3-derived synthetic nonce | `keyhive_crypto::symmetric_key`, `siv`; `beekem::encrypted` (content) |
| Content addressing | BLAKE3, 32-byte output, typed as `Digest<T>`               | `keyhive_crypto::digest`                           |

All identifiers in Keyhive (individuals, groups, documents) are Ed25519 verifying keys. Read access comes from X25519 "share keys" (prekeys and BeeKEM leaf/inner-node keys). Content, BeeKEM node secrets, and the earlier root secrets an update wraps are encrypted with XChaCha20-Poly1305. The key is derived from an X25519 exchange (BeeKEM node secrets), from a BeeKEM root secret (wrapped root secrets), or from a BeeKEM application secret (document content).

Keys read from the canonical codec are validated on decode. An `Identifier` (Ed25519) must be the canonical encoding of a point outside the small-order subgroup. A `ShareKey` (X25519) must be a canonical u-coordinate (below p, top bit clear) of large order, since a Diffie-Hellman exchange with a small-order point gives a shared secret anyone can compute. So one key has one encoding, and neither kind of key can be degenerate. Keys still read through serde are not checked this way.

## Domain Separation

The byte string `/keyhive/` (`keyhive_crypto::domain_separator::SEPARATOR`) is used as:

- the first input to `Siv::new`, the synthetic-nonce hash for BeeKEM node secrets and wrapped root secrets (below);
- the `derive_key` context in `Separable::derive_from_bytes`, which turns raw key material into a `SymmetricKey` or `ShareSecretKey`. Every BeeKEM node key (`ShareSecretKey::derive_symmetric_key`) passes through it.

BLAKE3 `derive_key` contexts take the form `/keyhive/<area>/<purpose>/v<N>/<YYYY-MM-DD>`. The version belongs to the context, and the date is the day that version was introduced, so no redesign or other application reuses one by accident (BLAKE3 asks for contexts that are "hardcoded, globally unique, and application-specific"). Content derives its application key, its encryption and nonce subkeys, and its header digest under `/keyhive/content/<purpose>/v1/2026-10-26` ([Content](#content)), and prekey selection draws from `/keyhive/prekey/selection/v1/2026-10-26`. The key an update wraps earlier root secrets under still uses `/keyhive/beekem/predecessor_secrets/` (see below).

Content-addressing digests (`Digest::hash`) and signing digests (`signed::Signed`) are plain `blake3::hash` over the `bincode` encoding, without a separator; `Digest<T>` separates them at the type level. Types migrated to the canonical codec (Keyline certificates and prekey operations so far) instead travel as a frame `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len ‖ payload ‖ signature` and sign and hash the frame without its signature (`keyhive_crypto::signable`); see [Keyline's implementation notes](./keyline/implementation.md#domain-separation).

## Synthetic Nonce and Key Commitment

> [!CAUTION]
> This construction is built from standard primitives but is not itself a standard AEAD mode. It has not been independently reviewed, and this section describes the intended construction. See [SECURITY.md](../SECURITY.md).

XChaCha20-Poly1305 has a 192-bit nonce, large enough that random nonces do not collide. Two problems remain:

1. Poly1305 is not key-committing: one ciphertext can decrypt to different valid plaintexts under different keys ([Invisible Salamanders][encryptment]).
2. The same key encrypts many payloads on many replicas, so nonce generation must not depend on a sound CSPRNG at every replica.

The nonce is therefore derived deterministically, and the recipient recomputes it after decryption. Content uses a keyed construction per chunk ([Content](#content)). BeeKEM node secrets and wrapped root secrets are sealed with `SymmetricKey::try_seal`, which authenticates its associated data `aad` and takes its nonce from `Siv::new(key, plaintext, aad)`:

```
nonce = BLAKE3( "/keyhive/" ‖ aad ‖ key ‖ plaintext )[0..24]
```

using BLAKE3 in XOF mode and truncating the 32-byte default output to the 24 bytes XChaCha requires.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          BLAKE3 (XOF, 24 bytes)                      │
│ ┌──────────────────┬──────────────────┬──────────────┬─────────────┐ │
│ │ Domain Separator │ Associated Data  │  ChaCha Key  │  Plaintext  │ │
│ │   "/keyhive/"    │ (starts with the │  (32 bytes)  │  (streamed) │ │
│ │                  │  BeeKEM tree ID) │              │             │ │
│ └──────────────────┴──────────────────┴──────────────┴─────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

Properties:

- _Nonce uniqueness._ A nonce repeats only for an identical (key, plaintext, associated data) triple, in which case the ciphertext is identical too and only equality is revealed. The tree ID in the associated data prevents reuse across documents; the separator prevents reuse across protocols.
- _Key and message commitment._ The nonce is a hash over key and plaintext. The recipient recomputes it after decryption and rejects a mismatch (`SymmetricKey::try_open`, and per chunk for content), so a ciphertext is committed to one key.

Trade-offs:

- Commitment is checked after decryption, so a malicious ciphertext costs one decryption before rejection.
- `Siv::new` feeds the key to the unkeyed BLAKE3 hasher as input rather than through keyed mode (`Hasher::new_keyed`). This relies on BLAKE3 acting as a PRF over a secret prefix. Content uses keyed mode.

## Content

Content is encrypted in chunks of 64 KiB, so a block of any size streams through bounded memory, and any byte range decrypts by reading only the chunks that cover it. Each block's application key derives two subkeys:

```
enc_key   = derive_key("/keyhive/content/encryption-key/v1/2026-10-26", app_key)
nonce_key = derive_key("/keyhive/content/nonce-key/v1/2026-10-26",      app_key)

aad_i   = BLAKE3_derive("/keyhive/content/header/v1/2026-10-26", doc_id ‖ header) ‖ i:u64 ‖ last:u8
nonce_i = BLAKE3_keyed(nonce_key, aad_i ‖ chunk_i)[0..24]
ct_i    = XChaCha20-Poly1305(enc_key, nonce_i, aad_i, chunk_i)
```

The block travels as `"KHE" ‖ version ‖ content_ref ‖ pred_refs ‖ pcs_key_hash ‖ pcs_update_op ‖ ( nonce_i ‖ ct_i )+`. Every chunk but the last is full; the last is empty only when the whole plaintext is, so each plaintext has one chunking.

- _Commitment per chunk._ The reader recomputes each `nonce_i` from what the chunk decrypts to and rejects a mismatch. Causal encryption hands ancestors' keys out in envelopes that any writer composes, so without the check one ciphertext could decrypt under its real key and under a key an envelope names, to two histories.
- _Bound to its header and document._ The header digest and `doc_id` are in every chunk's associated data, so editing a header field or reading a block as part of another document fails authentication.
- _Order and length._ The index and final flag are in each chunk's associated data, so reordering chunks, truncating at a chunk boundary, or appending a chunk fails authentication.
- _Overhead._ 132 bytes of header and 40 bytes per chunk (nonce and tag): 0.06% at 64 KiB.

## Key Derivation in BeeKEM

Inner-node secrets are X25519 secret keys sampled independently from the CSPRNG (no ratcheting; see [`beekem/README.md`](../beekem/README.md)). Each secret is sealed for a sibling under a symmetric key derived from the X25519 shared secret (`ShareSecretKey::derive_symmetric_key`):

```
sealed = try_seal(key, secret, aad = tree_id ‖ encrypter_pk ‖ paired_pk)
```

The tree ID binds the secret to its tree: share keys can appear in several trees, since prekeys are shared across documents, and without it a secret sealed in one would open in another. The two public keys bind it to the exchange it was sealed under, as HPKE binds its shared secret to them. Opening checks the synthetic nonce, so a node secret is committed to one key. `EncryptedSecret` travels as `sealed_len ‖ sealed ‖ paired_pk`, and a sealed blob shorter than its nonce and tag does not decode.

A block's application key is derived from the root secret (the `PcsKey`), its predecessors and its content ref:

```
app_key = derive_key("/keyhive/content/application-key/v1/2026-10-26",
                     root_secret ‖ Digest<PredecessorRefs> ‖ content_ref)
```

`Digest<PredecessorRefs>` is a kinded hash, BLAKE3 over `"KH" ‖ 'H' ‖ 0x00 ‖ count ‖ refs`, and the content ref is its canonical, self-delimiting encoding. Each block therefore gets a distinct key bound to the CGKA epoch and to its causal position; see [`causal_encryption.md`](./causal_encryption.md). The application key is what a causal envelope hands to a successor's readers.

Each update also encrypts the root secrets of earlier updates under a key derived from its own root secret. The BeeKEM tree ID is the associated data (authenticated, and an input to the nonce), and opening checks the synthetic nonce:

```
key = derive_key("/keyhive/", derive_key("/keyhive/beekem/predecessor_secrets/", root_secret))
```

## Sub-Protocols

| Feature                  | Mechanism                                                                             |
|--------------------------|---------------------------------------------------------------------------------------|
| Group definition         | Capability graph ([Convergent Capabilities](./convergent_capabilities.md))            |
| Read-group key agreement | BeeKEM (Continuous Group Key Agreement)                                               |
| Read-access revocation   | BeeKEM's built-in post-compromise security                                            |
| Transitive read access   | BeeKEM + capability graph (weakest link on the best path; `Relay` never joins the tree) |
| Granular edit access     | Partition-tolerant object capabilities                                                |
| Edit revocation          | Causal locking, back-dating detection, default to "whiteout" (skip materialisation)   |

## Agility

Nothing in the design is specific to these primitives. Ed25519 can be replaced by another signature scheme and X25519 by any key exchange or KEM, including post-quantum ones. BeeKEM requires only a key-exchange or KEM primitive.

<!-- External Links -->
[BLAKE3]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
[Ed25519]: https://www.rfc-editor.org/rfc/rfc8032
[X25519]: https://www.rfc-editor.org/rfc/rfc7748
[XChaCha20-Poly1305]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
[encryptment]: https://eprint.iacr.org/2019/016.pdf
