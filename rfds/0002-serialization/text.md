# Serialization

## Motivation

Serialization is important for signed data since the payload 
must be exact in order to verify the signature.




...
...
.....
...
..

# Desired Properties

The selection criteria for an appropriate codec are as follows:

## Security Considerations

* Maturity of format and ecosystem
* Strict with, and resistent to, malicious input
* Able to mitigate [canonicalization attacks]

## Engineering Considerations

* Availability in popular languages
* Minimal encoded size overhead
* Good average performance (both cycles and memory)
* Extensibility (e.g. for future fields)
* Permissively licensed

# Protocol Buffers

We believe that [Protocol Buffers] ("Protobuf") is a good fit for our use case.

Protobuf is attractive from a pure engineering perspective:
* Packages are available in all major languages
* It is extensively battle tested in critical applications at scale
* Protobuf is fast to both encode and decode
* Has among the lowest space overhead of all formats considered

Protobuf definitions include definitions in a special [Protobuf IDL]. 
This is a double-edged sword. On one hand it requires implementers of Keyhive
be able to read this IDL. On the other, most libraries provide codegen capabilities.
Further, this decides the format in which to formally define Keyhive schemata.

Protobuf also fares well from a security perspective. If a schema allows for
duplicate fields, the last field of that label MUST be used.

# Alternatives Considered

## Bespoke Keyhive Serializer



## Bincode 2

Development was originally done with [Bincode]. This is a popular choice in Rust
for it's flexibility, speed, low size overhead, and fails loudly on malicious input.
A [specification][Bincode Spec] exists, though the primacy of Rust is clear:

> ![QUOTE]
> This specification is primarily defined in the context of Rust,
> but aims to be implementable across different programming languages.
> 
> —  [Bincode Spec]

Bincode is not widely used in other ecosystems. Many languages lack a Bincode
implementation, which increases the bar for future implementations. 

## Parquet

## Arrow

## Avro

## Flatbuf

## Capt'n Proto

## CBOR

## DAG-CBOR


<!-- Extenral Links -->

[Bincode]: https://github.com/bincode-org/bincode
[Bincode Spec]: https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md
[Protobuf IDL]: https://protobuf.com/docs/language-spec
[Protobuf]: https://protobuf.dev/
