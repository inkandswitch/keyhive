# Group Membership

Group membership in Beehive has two main concepts: a membership op-based CRDT, and a variant of object capabilities adapted to an eventually consistent setting. We propose naming this class of capabilities "Convergent Capabilities", or "concap" for short.

To keep the nuber of pieces small in the example, we will use a short hierarchy: admins (arbitrary access) and read-only. 

## Example

### Objects & Causal State

```mermaid
flowchart
    subgraph Legend
        direction RL
        successor["Successor Op Author\n--------------------------\nSuccessor Op Payload"] -->|after| predecessor["Predessor Op Author\n-----------------------------\nPredecessor Op Payload"]
    end
```

```mermaid
flowchart RL
    subgraph docA[Document A]
        subgraph DocAState[Doc State]
            opA4 --> opA2 --> opA1
            opA4 --> opA3 --> opA1
        end

        subgraph DocAAuth[Doc Auth]
            addAdminsGroup["Doc A Root\n----------------------\nAdd Team Group"] --> initDocAAuth["Doc A Root\n---------------------\nSelf Certified Init"]
        end
    end

    subgraph docB[Document B]
        subgraph DocBState[Doc State]
            opB4 --> opB2 --> opB1
            opB4 --> opB3 --> opB1
        end

        subgraph DocBAuth[Doc Auth]
            direction TB
        
            addAdminsGroupB --> initDocBAuth
            addFrancine["Doc B Root\n----------------\nAdd Francine"] --> initDocBAuth["Doc B Root\n---------------------\nSelf-Certified Init"]
        end
    end

    subgraph admins[Team Group]
        rootAdminAddsBob["Team Root\n---------------\nAdd Bob"] --> initAdmins["Team Root\n---------------------\nSelf-Certified Init"]
        rootAdminAddsAlice["Team Root\n---------------\nAdd Alice"] --> initAdmins
        aliceAddsCarol["Alice\n------------\nAdd Carol"] ----> rootAdminAddsAlice
        bobRemovesCarol["Bob\n-----------------\nRemove Carol"] --> rootAdminAddsBob

        aliceAddsReaders["Alice\n-----------------------\nAdd Readers Group"] --> rootAdminAddsAlice
    end

    subgraph readers[Readers Group]
        bobAddsErin["Bob\n----------\nAdd Erin"] --> initReaders["Readers Root\n---------------------\nSelf-Certified Init"]
        aliceAddsDan["Alice\n----------\nAdd Dan"] --> initReaders
    end

    bobRemovesCarol -.-> opA3
    bobRemovesCarol -...-> opB4

    aliceAddsReaders -.-> bobAddsErin
    aliceAddsReaders -.-> aliceAddsDan

    addAdminsGroup -.-> rootAdminAddsBob
    addAdminsGroupB -.-> aliceAddsReaders

    addAdminsGroup -----> opA1
```

### Materialized View

The above example materialized to the following:

```mermaid
flowchart TB
    subgraph read_only
        direction TB

        subgraph readers
            direction TB

            Erin
            Dan

            reader_root
        end

        Francine

        subgraph also_write
            subgraph also_change_membership
                subgraph admins
                    direction TB

                    Alice
                    Bob
                    Carol

                    admin_root_pk
                end

                subgraph docA
                    direction TB

                    docA_root_pk
                end

                subgraph docB
                    direction TB

                    docB_root_pk
                end
            end
        end
    end

    admins --> docA
    admins --> docB

    Francine ~~~ readers
    readers --> admins
```

# State Transition

The state of a 

FIXME: batch signatures (since signatures don't compress)
IXME alternate version from teh paper:

FIXME on add, do we need agent heads, or just the removals? If only removals for efficiency, keep them in a Merkle Set, and reference the root? Given that this is concurrent taht may not work...
FIXME need to include agent heads in revocations?
FIXME discuss deny listing
FIXME do we need to include the proofhead since we can materialize the view. It may make it fster to provide a Merkle proof & compare to the tombstone set
        ...that imples that we define a way to reference auth state heads in a merkle tree, but we may not actually be able to do that thanks to EC
        ... nope, we've opted to allow re-adds, so no tombstone set

TODO: fix formatting; I just find this easier to read as a personal quirk 

```rust
enum AuthAction {
  // Arguably this could be expressed as AddGroup with group_heads: vec![singleton.id].
  // It's a noop if you give a stateless agent a different head,
  // since you will never be able to apply the op.
  AddSingleton { id: PublicKey },
  
  // Add Group includes docs, since Doc :< Group
  // Since Group :< Singleton, you *could* add a group that way,
  // but it would add at the start of its history 
  // (which may or may not be desirable, depending on the domain)
  AddGroup { 
    id: PublicKey, 
    group_heads: Vec<Hash> 
  },
  
  RemoveAgent { id: PublicKey },
}

struct AuthOp {
  action: AuthAction, // ⬆️
  
  auth_pred: Vec<Hash>, 
  doc_heads: Vec<(DocId, Hash)>,
  
  author: PublicKey,
  signature: Signature
}
```

## Materialization

Materialization if access at a certain level proceeds recursively. Given read access to the caveats of each group, a complete list of users and their capabilities $\langle \textsf{agentId}, \textsf{agentOrDocId}, \textsf{[restrictions]} \rangle$. The lowest level of rights in the preset is `pull`, which only requires knowing the current public key of leaf agents.

In this case, we have the following authority for Doc A:

| Agent       | Pull Doc A | E2EE Read Doc A | Write to Doc A | Change Membership on Doc A |
|-------------|------------|-----------------|----------------|----------------------------|
| Alice       | ✅         | ✅              | ✅             | ✅                         |
| Bob         | ✅         | ✅              | ✅             | ✅                         |
| Carol       | ✅         | ✅              | ✅             | ✅                         |
| Dan         | ✅         | ✅              | ❌             | ❌                         |
| Erin        | ✅         | ✅              | ❌             | ❌                         |
| Francine    | ❌         | ❌              | ❌             | ❌                         |
| Reader Root | ✅         | ✅              | ❌             | ❌                         |
| Admin Root  | ✅         | ✅              | ✅             | ✅                         |
| Doc A Root  | ✅         | ✅              | ✅             | ✅                         |
| Doc B Root  | ❌         | ❌              | ❌             | ❌                         |

And for Doc B:

| Agent       | Pull Doc B | E2EE Read Doc B | Write to Doc B | Change Membership on Doc B |
|-------------|------------|-----------------|----------------|----------------------------|
| Alice       | ✅         | ✅              | ✅             | ✅                         |
| Bob         | ✅         | ✅              | ✅             | ✅                         |
| Carol       | ✅         | ✅              | ✅             | ✅                         |
| Dan         | ✅         | ✅              | ❌             | ❌                         |
| Erin        | ✅         | ✅              | ❌             | ❌                         |
| Francine    | ✅         | ✅              | ❌             | ❌                         |
| Reader Root | ✅         | ✅              | ❌             | ❌                         |
| Admin Root  | ✅         | ✅              | ✅             | ✅                         |
| Doc A Root  | ❌         | ❌              | ❌             | ❌                         |
| Doc B Root  | ✅         | ✅              | ✅             | ✅                         |

### Auth Roots

Auth roots are

## Re-Adds


# Anatomy

All groups MUST be represented by a "root" keypair. A 

## Stateless Singletons

```mermaid
flowchart TB
    subgraph Singleton
        _singletonPK["Singleton Public Key"]
    end
```

## Stateful Groups

```mermaid
flowchart TB
    subgraph Group
        direction TB

        _groupPK["Group Root (Public Key)"]

        subgraph membership[Group Membership]
            rootAddsAlice[Group Root\n-------------\nAdd Alice] --> groupRoot[Group Root\n----------------------\nSelf Certifying Init]
            rootAddsBob[Group Root\n-------------\nAdd Bob] --> groupRoot
            aliceAddsCarol[Alice\n------------\nAdd Carol] --> rootAddsAlice

            removeCarol[Bob\n----------------\nRemove Carol] --> rootAddsBob
            removeCarol --> aliceAddsCarol
            bobAddsIas[Bob\n-----------------------------\nAdd Ink & Switch Group] ---> rootAddsBob
        end
    end

    groupRoot -.->|implied by| _groupPK
```

## Documents

```mermaid
flowchart TB
    subgraph Document
        direction TB

        _docPK["Document Root (Public Key)"]

        subgraph docGroup[Document Membership]
            docRootAddsSingleton["Doc Root\n--------------------\nAdd Singleton PK"] --> docRoot[Document Root\n----------------------\nSelf Certifying Init]
            docRootAddsAnotherGroup["Doc Root\n------------------------------\nAdd Ink & Switch Group"] --> docRoot
            singetonRemovesAnotherGroup[Singleton\n----------------------------------\nRemove Ink & Switch Group] --> docRootAddsSingleton
            singetonRemovesAnotherGroup --> docRootAddsAnotherGroup
        end

        subgraph ops[Document Operations]
            addKeyFoo["Ink & Switch\n---------------\nfoo := 1"] --> InitMap[Document Root\n------------------\nInitialize Map]
            removeKeyFoo["Singleton\n---------------------\nRemove Key ''foo''"] --> addKeyFoo
            addKeyBar["Singleton\n-----------\nbar := 2"] --> addKeyFoo
        end
    end

    singetonRemovesAnotherGroup -.->|lock state after| addKeyFoo
    InitMap -.->|self-certified by| docRoot -.->|self-certified by| _docPK
```

## Encrypted Op State

Note that the above may not all be available as cleartext. For example, a Puller will see the [Document] example above as something along the following lines:

```mermaid
flowchart TB
    subgraph Document
        direction TB

        _docPK["Document Root (Public Key)"]

        subgraph docGroup[Document Membership]
            docRootAddsSingleton["Doc Root\n--------------------\nAdd Singleton PK"] --> docRoot[Document Root\n----------------------\nSelf Certifying Init]
            docRootAddsAnotherGroup["Doc Root\n------------------------------\nAdd Ink & Switch Group"] --> docRoot
            singetonRemovesAnotherGroup[Singleton\n----------------------------------\nRemove Ink & Switch Group] --> docRootAddsSingleton
            singetonRemovesAnotherGroup --> docRootAddsAnotherGroup
        end

        subgraph ops[Document Operations]
            someStuff[Encrypted Bytes]
        end

        addKeyFoo -.->|somewhere inside| ops
    end

    singetonRemovesAnotherGroup -.->|lock state after| addKeyFoo["Document PK @ Op Hash"]
    docRoot -.->|self-certified by| _docPK
```

This enough information for them to know may request document bytes, but not enough to actually decrypt the document state.

# Delegation

## Attenuated Authority

## Transitive Access

# Device Management

This strategy does not distinguish between users, groups, and public keys. In a sense, public keys are stateless singleton groups.

```mermaid
flowchart TB

    doc1["Meeting Notes\n(Patchwork)"] -->|read only| ias
    doc2["LaTeX Paper\n(Jacquard)"] -->|read & write| ias
    doc3["Kid's Homework\n(Patchwork)"] -->|read| alice

    ias["Ink & Switch\n(Beehive Group)"] -->|all| alice

    subgraph alicedomain[" "]
        alice["''Alice''\n(Beehive Group)"]

        aliceLaptop[Alice's Laptop]
        aliceTablet[Alice's Tablet]
        alicePhone[Alice's Phone]
        
        aliceFirefox[Firefox WebCrypto Context]
        aliceWebWorker1[Web Worker 1]
        aliceWebWorker2[Web Worker 2]
        aliceWebWorker3[Web Worker 3]

        alice -->|all| aliceLaptop -->|all| aliceFirefox
        aliceFirefox -->|only Patchwork| aliceWebWorker1
        aliceFirefox -->|only Jacquard| aliceWebWorker2
        aliceFirefox -->|all| aliceWebWorker3
        
        alice -->|all| aliceTablet
        alice -->|only Jacquard read| alicePhone
    end
```

## Applications to [Collection Sync]

# FAQ

## Differences from Access Control Lists (ACLs)

## Differences from Object Capabilities (ocap)

## Differences from Certificate Capabilities / SPKI

<!-- External Links -->

[Collection Sync]: ./collection_sync.md
