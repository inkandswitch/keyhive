# Stable Chunking

Take the following causal graph on two replicas.

```mermaid
flowchart TD
    subgraph Replica A
        j(f34bk0)
        h(z3fgb8)
        g(a5j200)
    end

    subgraph Common
        d(u0n7c2)
        e(644dn9)
    end

    subgraph Replica B
        i(8ui0n7)
        a(8vxt00)
        b(roib8a)
        c(f36c09)
        f(ig0000)
    end

    a --> b
    b --> c
    b --> d
    c --> e
    d --> e
    g --> d
    h --> g
    i --> a
    i --> f
    j --> h

    f --> c
    
    style b fill:red;
    style c fill:red;
    style d fill:red;
    style e fill:red;
```

Replica A and B each start from their heads, and walk until they encounter their hardness metric:

```mermaid
flowchart TD
    subgraph Replica A
        subgraph headsA["00 Head(s)"]
            direction TB
            j(f34bk0)
            h(z3fgb8)
        end

        subgraph chunkA["00 Chunk"]
            g(a5j200)
            dA(u0n7c2)
            eA(644dn9)
        end
    end

    subgraph Replica B
        subgraph headsB["00 Head(s)"]
            i(8ui0n7)
        end

        subgraph chunkB1["00 Chunk"]
            f(ig0000)
            c2(f36c09)
            eB2(644dn9)
        end

        subgraph chunkB2["00 Chunk"]
            a(8vxt00)
            b(roib8a)
            c(f36c09)
            dB(u0n7c2)
            eB(644dn9)
        end
    end

    a --> b
    b --> c
    b --> dB
    c --> eB
    dA --> eA
    dB --> eB
    g --> dA
    h --> g
    i --> a
    i --> f
    j --> h
    f --> c2 --> eB2
    
    style c fill:red;
    style c2 fill:red;
    style dB fill:red;
    style eB fill:red;
    style eB2 fill:red;
    style dA fill:red;
    style eA fill:red;
```

> [!NOTE]
> Typically this hardness metric would produce larger chunks, but for explanatory purposes they've been kept small

Note that we have the same ops in multiple chunks! This is both across replicas (`u0n7c2` and `644dn9`), and inside chunks on replica B (`f36c09` and `644dn9`). This duplication will only persist until the next common chunk (which we're guaranteed by hash chaining).

This bounded, limited duplication is in service of a very important property: being coordination-free. If another Replica C has ops from the `8vxt00` chunk but not the `ig000` or `a5j200` (plus others not seen above), it will _also_ produce the same `8vxt00` chunk.

```mermaid
flowchart TD
    subgraph Replica C
        subgraph headC["00 Head(s)"]
            rc1(5rg0b8) --> rc2(t6voia)
            rc3(xcwq4n)
        end

        subgraph chunkC["00 Chunk"]
            direction TB

            rc2 --> gC(a5j200) --> dC(u0n7c2) --> eC(644dn9)
            rc3 --> gC
        end
    end

    subgraph Replica A
        subgraph headsA["00 Head(s)"]
            direction TB
            j(f34bk0)
            h(z3fgb8)
        end

        subgraph chunkA["00 Chunk"]
            g(a5j200)
            dA(u0n7c2)
            eA(644dn9)
        end
    end

    subgraph Replica B
        subgraph headsB["00 Head(s)"]
            i(8ui0n7)
        end

        subgraph chunkB1["00 Chunk"]
            f(ig0000)
            c2(f36c09)
            eB2(644dn9)
        end

        subgraph chunkB2["00 Chunk"]
            a(8vxt00)
            b(roib8a)
            c(f36c09)
            dB(u0n7c2)
            eB(644dn9)
        end
    end

    a --> b
    b --> c
    b --> dB
    c --> eB
    dA --> eA
    dB --> eB
    g --> dA
    h --> g
    i --> a
    i --> f
    j --> h
    f --> c2 --> eB2

    style chunkA fill:blue;
    style chunkC fill:blue;
```

# Granularity

If we make the hash function _too_ hard, we cease to retain common sections between replicas. Below we have a hash hardness of six zeroes (`000000`). 

```mermaid
flowchart TD
    subgraph Replica A
        subgraph headsA["000000 Head(s)"]
            direction TB
            j(f34bk0)
            h(z3fgb8)
            g(a5j200)
            dA(u0n7c2)
            eA(644dn9)
        end
    end

    subgraph Replica B
        subgraph headsB["000000 Head(s)"]
            direction TB
            i(8ui0n7)

            f(ig0000)

            a(8vxt00)
            b(roib8a)
            c(f36c09)
            dB(u0n7c2)
            eB(644dn9)
        end
    end

    a --> b
    b --> c
    b --> dB
    dA --> eA
    dB --> eB
    g --> dA
    h --> g
    i --> a
    i --> f
    j --> h
    f --> c --> eB
    
    style b fill:red;
    style c fill:red;
    style dB fill:red;
    style eB fill:red;
    style dA fill:red;
    style eA fill:red;
```

# Merging

Later, we decide that we want to merge chunks. We choose a harder hash metric (six `0`s). We know that everything inside each `00` chunk will get grouped together, so we don't have to recompute that traversal (though we _do_ want to deduplicate). We only need to look at the heads of each graph to know if we should stop.

In this example, let's assume that the replicas from earlier have synced, so we'll treat it as a single graph:

```mermaid
flowchart TD
    subgraph one["000000 Head(s)"]
      a
      b
      c
      e
      i
      d1(u0n7c2)
    end

    subgraph Chunk[00000 Chunk]
        f
        c3(f36c09)
        e3(644dn9)
    end

    subgraph Head1["000000 Head(s)"]
        d
        g
        h
        j
        e2(644dn9)
    end

    j(f34bk0)
    h(z3fgb8)
    g(a5j200)

    d(u0n7c2)
    e(644dn9)

    i(8ui0n7)
    a(8vxt00)
    b(roib8a)
    c(f36c09)
    f(ig0000)

    a --> b
    b --> c
    c --> e
    d --> e2
    g --> d
    h --> g
    i --> a
    i --> f
    j --> h

    b --> d1 --> e

    f --> c3
    c3 --> e3
    
    b ~~~ d

    style c3 fill:red;
    style e3 fill:red;

    style d1 fill:red;
    style e2 fill:red;

    style c fill:red;
    style d fill:red;
    style e fill:red;
```

## Archival Strategy

To reduce the duplication across chunks, we can merge chunks into larger runs. _Extremely_ generally, ops much earlier in the causal history are less likely to have siblings. Under this assumption, we can use a metric like hash hardness to determine ranges with a backoff.

One such metric is to decrease the hash hardness as chunks are generated. In essence, this is a search problem on the causal graph, splitting it into probabilistically smaller regions the nearer it gets to the latest head. This strategy is stable across all replicas with shared history, and produces stable subsumptions.

(Forgive me, I added more ops under `ig0000` to make the chunk more illustrative)

```mermaid
flowchart TD
    d(u0n7c2)
    c(f36c09)
    e(644dn9)
    j(f34bk0)
    h(z3fgb8)
    g(a5j200)
    i(8ui0n7)
    a(8vxt00)
    b(roib8a)
    f(ig0000)

    subgraph four["0000"]
        f
        c
        e

        f --> x(g6t000) --> y(634v03) --> z(xde4g2) --> o(83bd7xa)
        e --> w(8ubx00) --> z
    end

    subgraph two["00"]
        subgraph B[" "]
            a
            b
            d
            cB(f36c09)
            eB(644dn9)

            b --> cB --> eB
            d --> eB
        end

        subgraph C [" "]
            g --> dA(u0n7c2) --> eA(644dn9)
        end
    end

    subgraph Heads["None (i.e. heads)"]
        subgraph D[" "]
            h
            j
        end

        subgraph E[" "]
            i
        end
    end

    a --> b
    c --> e
    h --> g
    i ---> a
    i --> f
    j --> h
    b --> d
    f --> c
    B ~~~~~~ four

    eB --> w
    eA --> w

    style c fill:red;
    style cB fill:red;

    style d fill:red;
    style dA fill:red;

    style e fill:red;
    style eA fill:red;
    style eB fill:red;
```

## Merging & Encryption

Under encryption, the contents cannot be inspected, and the same ops may be encrypted with a different key (yielding a different ciphertext). An [Agent] with [Pull] access may want to know which granular chunks can be be retired after a period of time. This is achieved by nothing the head hashed and metric used:

```rust
struct EncryptedChunk {
    head: Vec<Hash>,
    hardness: u8,
    contains: Vec<(Hash, MaxHardness)>,
}
```

We do need to note the hardness in addition to the hash, since the two together uniquely determine the resulting subgraph. We only need to note the maximum hardness used, since hardness is a monotone function. We cannot only rely on the zeros in the hash because we may have used a weaker metric to calculate the region.

> [!NOTE]
> This is — in a sense — a known plaintext attack _against ourselves_ in the common case where we produce the exact same chunk prior to encryption. This means that any encryption method used MUST be secure against known plaintext.

# Adversarial Garbage Collection

# Future Directions

This chunking strategy can also be used to generate stable flattened histories (AKA "squash compression").
