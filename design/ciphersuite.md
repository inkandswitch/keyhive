# Cipher Suite

| Feature            | Algorithm                                                  | Where                                              |
|--------------------|------------------------------------------------------------|----------------------------------------------------|
| Hash / KDF         | [BLAKE3] (plain hash, XOF, and `derive_key` modes)         | `keyhive_crypto::digest`, `siv`, `separable`, `beekem::pcs_key` |
| Signatures         | [Ed25519] (RFC 8032, via `ed25519-dalek`)                  | `keyhive_crypto::signed`                           |
| Key exchange       | [X25519] (RFC 7748, via `x25519-dalek`)                    | `keyhive_crypto::share_key`, BeeKEM path secrets   |
| Symmetric AEAD     | [XChaCha20-Poly1305] with a BLAKE3-derived synthetic nonce | `keyhive_crypto::symmetric_key`, `siv`             |
| Content addressing | BLAKE3, 32-byte output, typed as `Digest<T>`               | `keyhive_crypto::digest`                           |

All identifiers in Keyhive (individuals, groups, documents) are Ed25519 verifying keys. Read access is carried by X25519 "share keys" (prekeys and BeeKEM leaf/inner-node keys). Content and BeeKEM node secrets are encrypted with XChaCha20-Poly1305 under keys that are either derived from an X25519 exchange (BeeKEM) or from a BeeKEM application secret (document content).

## Domain Separation

The byte string `/keyhive/` (`keyhive_crypto::domain_separator::SEPARATOR`) is used as:

- the first input to the synthetic-nonce hash (below);
- the AEAD associated data on every encryption;
- the `derive_key` context in `Separable::derive_from_bytes`, which turns raw key material into a `SymmetricKey` or `ShareSecretKey`. Every BeeKEM node key (`ShareSecretKey::derive_symmetric_key`) and every application secret passes through it.

Application secrets additionally use the context `/keyhive/beekem/app_secret/` for their first derivation stage (see below).

Content-addressing digests (`Digest::hash`) and signing digests (`Signed`) are plain `blake3::hash` over the `bincode` encoding, without a separator; `Digest<T>` separates them at the type level.

## Synthetic Nonce and Key Commitment

> [!CAUTION]
> This construction is built from standard primitives but is not itself a standard AEAD mode. It has not been independently reviewed, and this section describes the intended construction. See [SECURITY.md](../SECURITY.md).

XChaCha20-Poly1305 has a 192-bit nonce, large enough that random nonces do not collide. Two problems remain:

1. Poly1305 is not key-committing: one ciphertext can decrypt to different valid plaintexts under different keys ([Invisible Salamanders][encryptment]).
2. The same key encrypts many payloads on many replicas, so nonce generation must not depend on a sound CSPRNG at every replica.

The nonce is therefore derived deterministically. `Siv::new(key, plaintext, doc_id)` computes

```
nonce = BLAKE3( "/keyhive/" ‖ doc_id ‖ key ‖ plaintext )[0..24]
```

using BLAKE3 in XOF mode and truncating the 32-byte default output to the 24 bytes XChaCha requires.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          BLAKE3 (XOF, 24 bytes)                      │
│ ┌──────────────────┬──────────────────┬──────────────┬─────────────┐ │
│ │ Domain Separator │   Document ID    │  ChaCha Key  │  Plaintext  │ │
│ │   "/keyhive/"    │ (Ed25519 pubkey) │  (32 bytes)  │  (streamed) │ │
│ └──────────────────┴──────────────────┴──────────────┴─────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

Properties:

- _Nonce uniqueness._ A nonce repeats only for an identical (key, plaintext, document) triple, in which case the ciphertext is identical too and only equality is revealed. `doc_id` prevents reuse across documents; the separator prevents reuse across protocols.
- _Key and message commitment._ The nonce is a hash over key and plaintext. The recipient recomputes it after decryption and rejects a mismatch, so a ciphertext is committed to one key.
- _Streaming._ BLAKE3 consumes the plaintext incrementally; the preimage is never materialised.

Trade-offs:

- Commitment is checked after decryption, so a malicious ciphertext costs one decryption before rejection.
- The key is fed to the unkeyed BLAKE3 hasher as input rather than through keyed mode (`Hasher::new_keyed`). This relies on BLAKE3 acting as a PRF over a secret prefix. Moving to keyed mode would change the wire format.

## Key Derivation in BeeKEM

Inner-node secrets are X25519 secret keys sampled independently from the CSPRNG (no ratcheting; see [`beekem/README.md`](../beekem/README.md)). Each secret is encrypted for a sibling by deriving a symmetric key from the X25519 shared secret (`ShareSecretKey::derive_symmetric_key`) and applying the AEAD above, with the BeeKEM tree ID as `doc_id`.

Application secrets for document content are derived from the root secret (the `PcsKey`) in two stages:

```
material = derive_key("/keyhive/beekem/app_secret/",
                      root_secret ‖ "epoch:<hash(root)>/pred:<hash(predecessor refs)>/content:<hash(content ref)>")
key      = derive_key("/keyhive/", material)
```

Each content chunk therefore gets a distinct key bound to the CGKA epoch and to its causal position; see [`causal_encryption.md`](./causal_encryption.md).

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
