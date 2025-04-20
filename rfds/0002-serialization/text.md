# Serialization

## Motivation

Serialization is important for signed data since the payload 
must be exact (down to the bit) in order to 
[verify a signature or hash][How (not) to sign a JSON object].
There are many serialization format for a reason: one true format
does not exist. For Keyhive, the primary concern is security,
followed by adoptability.

Security is always subtle; there are a [plethora of attacks][Taxonomy of Attacks]
that can be an unintended consequence of representation.



# Desired Properties

The selection criteria for an appropriate codec are broadly about ease
of implementation and security concerns.

## Security

* Maturity of format and ecosystem
* Strict with, and resistant to, malicious input
* Able to mitigate especially [canonicalization attacks]

## Engineering

* Availability in popular ecosystems
* Minimal encoded size overhead
* Good average performance (both cycles and memory)
* Extensibility (e.g. for future fields)
* Permissively licensed

# Choice: Protocol Buffers v3

We believe that [Protocol Buffers] version 3 ("Protobuf" or "proto3")
is a good fit for the Keyhive use case.

Protobuf is attractive from a pure engineering perspective:
* Packages are available in all major languages
* It is extensively battle tested in critical applications at scale
* Protobuf is fast to both encode and decode
* Has among the lowest space overhead of all formats considered

Protobuf schema definitions may be given in a special [Protobuf IDL]. 
This is a double-edged sword. On one hand it requires implementers of Keyhive
be able to read this IDL. On the other, most libraries provide codegen capabilities.
Further, this decides the format in which to formally define Keyhive schemata.
A challenge of the Protobuf IDL for us is that it's limited to Protobuf types,
and cannot check arbitrary properties like inequalities. We will likely need
to specify more about the types than the raw serialization, especially to help
implementers [maintain invariants up front][Parse Don't Validate].

Despite not being perfect (see [contraindications]), Protobuf also fares reasonably
well from a security perspective. We believe that the most serious security challenges
can be managed at the schema layer.

## Contraindications

### Duplicate Map Keys

One problem with the specification is that it allows for multiple behaviors in the
case of duplicate map keys.

> When parsing from the wire or when merging, if there are duplicate map keys 
> the last key seen is used. When parsing a map from text format,
> parsing may fail if there are duplicate keys.
>
> [...]
>
> clients using the `repeated` field definition will produce a 
> semantically identical result; however, clients using the map field definition 
> may reorder entries and drop entries with duplicate keys.
>
> — [Proto3 Spec][proto3 map features]

At time of writing, we do not have a need for user-defined maps or repeated fields.
Going forward, we must remember to never use this feature.

### Lack of Deterministic Serialization

Very few serialization formats are deterministic, and Protobuf also lacks determinism.
This means that the serialized payload MUST be stored verbatim in order 
to check hashes or signatures.

Given that Keyhive uses end-to-end encryption, and any node in local-first 
may act as a provider, we expect that most implementations will store 
the ciphertexts directly, thus we assume that the exact bytes are assumed
to be stored.

# Alternatives Considered

Many other formats were considered. Some of the front runners are listed below.
A general observation is that Protobuf and Arrow were _by far_ the most popular
across all languages surveyed (by the rough metric of "recent downloads").

## Bespoke Keyhive Serialization Format



## Bincode v2

Development was originally done with [Bincode]. This is a popular choice in Rust
for it's flexibility, speed, low size overhead, and fails loudly on malicious input.
A [specification][Bincode Spec] exists, though the primacy of Rust is clear:

> This specification is primarily defined in the context of Rust,
> but aims to be implementable across different programming languages.
>
> —  [Bincode Spec]

Bincode is not widely used in other ecosystems. Many languages lack a Bincode
implementation, which increases the bar for future implementations.
It is little known outside of Rust (which does have significant Bincode adoption).

## ASN.1 DER

[ASN.1] is a well known IDL that has been used extensively in 
cryptographic applications such as PCKS and X.509.
It is the oldest format considered by decades[^older].

We consider its maturity a virtue, but it lacks many of the niceties 
and packaging that have come in the years since. ASN.1 is often cited
as having a steep learning curve, having limited tooling, and being resistant 
to schemas that upgrade easily. It is also not the most efficient format on this list.

[^older]: It is even older than the author of this document(!)

## Parquet

## Arrow

## Avro

## Flatbuf

## Capt'n Proto

## CBOR

[CBOR] is an IETF-standardized format in wide use.
It is a non-human-readable binary format which aims
at being a reasonably compact, schemaless,
extensible for applications that would otherwise
reach for JSON.

There are CBOR implementations in all languages surveyed.
An IDL exists outside of the core CBOR spec ([CDDL]).
It is easy to read and write, but lacks the expressive
power and adoption of many other IDLs on this list.

CBOR is significantly more compact than JSON, but is
among the higher overhead formats on this list.
It is also possible to express ambiguous data,
and map key order is not specified unless
Canonical CBOR is opted into (which is not available 
in all libraries).

## DAG-CBOR

[DAG-CBOR] is an [IPLD] codec that further constrains CBOR.
It has canonicalized encoding, an in-built hash link type,
and has existing tooling to deterministically convert to
and from a more developer-friendly JSON representation.
The best known application that uses DAG-CBOR is [Bluesky],
which has tens-of-millions of users at time of writing.

Unfortunately, DAG-CBOR comes with some drawbacks.
Chief among them is that it is a young format with
few implementations. Malformed input (e.g. duplicate keys) 
are not strictly enforced in all implementations, and it
inherits many of the drawbacks of regular CBOR:
it is more compact than JSON but less compact than Protobuf,
as is self-describing (usually a feature but we need
compaction more than flexibility).

<!-- Internal links -->

[contraindictions]: #contraindications

<!-- Extenral Links -->

[ASN.1]: https://www.itu.int/rec/T-REC-X.680/
[Bincode Spec]: https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md
[Bincode]: https://github.com/bincode-org/bincode
[Bluesky]:  https://bsky.app/
[CBOR]: https://cbor.io/spec.html
[CDDL]: https://www.rfc-editor.org/rfc/rfc8610.html
[DAG-CBOR]: https://ipld.io/specs/codecs/dag-cbor/spec/
[How (not) to sign a JSON object]: https://latacora.micro.blog/2019/07/24/how-not-to.html
[IPLD]: https://ipld.io/
[Parse Don't Validate]: https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/
[Protobuf IDL]: https://protobuf.com/docs/language-spec
[Protobuf]: https://protobuf.dev/
[Taxonomy of Attacks]: https://www.blackhat.com/presentations/bh-usa-07/Hill/Whitepaper/bh-usa-07-hill-WP.pdf
[canonicalization attacks]: https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/
[proto3 map features]: https://protobuf.dev/programming-guides/proto3#maps-features
