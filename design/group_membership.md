# Group Membership

# Abstract

Keyhive maintains groups with mutable membership (additions and removals). This has two main concepts: a membership op-based CRDT, and a variant of object capabilities adapted to an eventually consistent setting. Some groups are associated with Automerge documents. Membership changes and document content MAY causally depend on each other. This document describes how to maintain this group membership.

# Conventions

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

## Diagrams

There are several diagrams below. We use the following graphical conventions:

```mermaid
flowchart
    subgraph Legend
        direction RL
        successor["Successor Op Author<br>--------------------------<br>Successor Op Payload"] -->|after| predecessor["Predessor Op Author<br>-----------------------------<br>Predecessor Op Payload"]
    end
```

# Agents

"Agents" in Keyhive represent some principal that is capable of receiving, delegating, and exercising authority. They are distinguished by other entities in the system by being able to cryptographically sign operations. As such, Agents MUST be represented by a "root" key pair which acts as their ID.

Agents form a subtyping hierarchy: `Document :< Stateful :< Stateless`.

``` rust
// Pseudocode
enum Agent {
    Stateless { id: PublicKey },
    Stateful { 
        id: PublicKey,
        auth_state: Vec<AuthOp>
    },
    Document {
        id: PublicKey,
        auth_ops: Vec<AuthOp>,
        content_ops: Vec<AutomergeOp>
    }
}
```

## Stateless (AKA "Singleton")

The simplest Agent variant is a public key with no associated state. Almost (but not all) ops in Keyhive are signed by Stateless Agents. These are typically the leaf keys in a [group hierarchy].

Some examples of Stateless Agents include Passkeys, non-extractable WebCrypto keys, hardware keys, or other keys limited by application context.

There is no mechanism to rotate a stateless key itself. However, managing key rotation and/or multiple keys (e.g. [for all of a user's devices]) is possible via [Stateful Agents].

```mermaid
flowchart TB
    subgraph StatelessAgent[Stateless Agent]
        _singletonPK["Singleton Public Key"]
    end
```

## Stateful (AKA "Group")

Stateful Agents add authorization state. The operations that make up the state's history MUST be rooted in (begin at) the Stateful Agent's public key.

Once another Agent is grated control of it, the Stateful Agent MAY delete its secret key.

A very common pattern is for the creator of an Agent to include instructions to add itself to the child's membership upon initialization. This is known as [Membership by Parenthood].

```mermaid
flowchart TB
    subgraph StatefulAgent[Stateful Agent]
        direction TB

        _groupPK["Group Root<br>(Public Key)"]

        subgraph membership[Group Membership]
            rootAddsAlice[Group Root<br>-------------<br>Add Alice] --> groupRoot[Group Root<br>----------------------<br>Self Certifying Init]
            rootAddsBob[Group Root<br>-------------<br>Add Bob] --> groupRoot
            aliceAddsCarol[Alice<br>------------<br>Add Carol] --> rootAddsAlice

            removeCarol[Bob<br>----------------<br>Remove Carol] --> rootAddsBob
            removeCarol --> aliceAddsCarol
            bobAddsIas[Bob<br>-----------------------------<br>Add Ink & Switch Group] ---> rootAddsBob
        end
    end

    groupRoot -.->|implied by| _groupPK
```

## Document

Documents are a subtype of Stateful Agents. They add stateful document content in addition to stateful auth. This is important so that the document content can self-certify the associated auth history.

```mermaid
flowchart TB
    subgraph DocumentAgent[Document Agent]
        direction TB

        _docPK["Document Root<br>(Public Key)"]

        subgraph docGroup[Document Membership]
            docRootAddsSingleton["Doc Root<br>--------------------<br>Add Singleton PK"] --> docRoot[Document Root<br>----------------------<br>Self Certifying Init]
            docRootAddsAnotherGroup["Doc Root<br>------------------------------<br>Add Ink & Switch Group"] --> docRoot
            singetonRemovesAnotherGroup[Singleton<br>----------------------------------<br>Remove Ink & Switch Group] --> docRootAddsSingleton
            singetonRemovesAnotherGroup --> docRootAddsAnotherGroup
        end

        subgraph ops[Document Operations]
            addKeyFoo["Ink & Switch<br>---------------<br>foo := 1"] --> InitMap[Document Root<br>------------------<br>Initialize Map]
            removeKeyFoo["Singleton<br>---------------------<br>Remove Key ''foo''"] --> addKeyFoo
            addKeyBar["Singleton<br>-----------<br>bar := 2"] --> addKeyFoo
        end
    end

    singetonRemovesAnotherGroup -.->|lock state after| addKeyFoo
    InitMap -.->|self-certified by| docRoot -.->|self-certified by| _docPK
```

### Encrypted Content

Note that the above may not all be available as cleartext to all participants. For example, a sync server (which only has [Pull] rights) will see the [Document] example above as something along the following lines:

```mermaid
flowchart TB
    subgraph DocumentAgent[Document Agent]
        direction TB

        _docPK["Document Root<br>(Public Key)"]

        subgraph docGroup[Document Membership]
            docRootAddsSingleton["Doc Root<br>--------------------<br>Add Singleton PK"] --> docRoot[Document Root<br>----------------------<br>Self Certifying Init]
            docRootAddsAnotherGroup["Doc Root<br>------------------------------<br>Add Ink & Switch Group"] --> docRoot
            singetonRemovesAnotherGroup[Singleton<br>----------------------------------<br>Remove Ink & Switch Group] --> docRootAddsSingleton
            singetonRemovesAnotherGroup --> docRootAddsAnotherGroup
        end

        subgraph ops[Document Operations]
            someStuff[Encrypted Bytes]
        end

        addKeyFoo -.->|somewhere inside| ops
    end

    singetonRemovesAnotherGroup -.->|lock state after| addKeyFoo(["Document PK @ Op Hash"])
    docRoot -.->|self-certified by| _docPK
```

This enough information for the sync server to know may request document bytes, but not enough to actually decrypt the document state.

### Cross-Group Dependencies

In addition to content and authority operations depending on each other inside a Group, they MAY include causal dependencies into others.

``` mermaid
flowchart
    subgraph DocumentAgent[Document A Agent]
        _docPK["Document A Root<br>(Public Key)"]

        subgraph docAGroup[Document A Membership]
            docRoot
            docRootAddsAnotherGroup
            docRootAddsSingleton
            docRootAddsSingleton
            singetonRemovesAnotherGroup
        end

        subgraph opsA[Document A Content]
            InitMap
            addKeyFoo
            
            addKeyBar
            removeKeyFoo
        end
    end

    removeKeyFoo["Carol<br>---------------------<br>Remove Key ''foo''"] --> addKeyFoo
    addKeyFoo["Dan<br>---------------<br>foo := 1"] --> InitMap[Document Root<br>------------------<br>Initialize Map]

    addKeyBar["Carol<br>-----------------------<br>bar := Document B"] ----> addKeyFoo
    
    docRootAddsSingleton["Doc A Root<br>--------------------<br>Add Carol PK"] --> docRoot[Document Root<br>----------------------<br>Self Certifying Init]
    docRootAddsAnotherGroup["Doc Root<br>-----------<br>Add Dan"] --> docRoot
    singetonRemovesAnotherGroup[Carol<br>---------------<br>Remove Dan] --> docRootAddsSingleton
    singetonRemovesAnotherGroup --> docRootAddsAnotherGroup

    singetonRemovesAnotherGroup -.->|lock state after| addKeyFoo
    singetonRemovesAnotherGroup -.-> docBRootAddsAnotherGroup
    InitMap -.->|self-certified by| docRoot -.->|self-certified by| _docPK

    subgraph DocumentAgent2[Document B Agent]
        _docBPK["Document B Root<br>(Public Key)"]

        subgraph docBGroup[Document B Membership]
        
            docBRoot
            docBRootAddsSingleton
            docBRootAddsAnotherGroup
            bobAddsDocA
            docBRootAddsAnotherGroup
        end

        subgraph opsB[Document B Content]
            addCharH["Alice<br>----------<br>push('H')"] --> InitStringB[Document Root<br>------------------<br>Initialize String]
            addCharI["Alice<br>---------<br>push('i')"] --> addCharH
            addCharExp["Bob<br>----------<br>push('!')"] --> addCharI
        end
    end

    InitStringB-.->|self-certified by| docBRoot -.->|self-certified by| _docBPK
    addCharH -.-> docBRootAddsAnotherGroup
    docBRootAddsSingleton -.-> addCharI
    addCharExp -.-> docBRootAddsSingleton

    addKeyBar -.-> addCharExp

    docBRootAddsSingleton["Doc Root<br>--------------<br>Add Bob PK"] --> docBRoot[Document Root<br>----------------------<br>Self Certifying Init]
    docBRootAddsAnotherGroup["Doc Root<br>-----------<br>Add Alice"] --> docBRoot

    bobAddsDocA["Bob<br>-----------<br>Add Document A"] -..-> docRoot
    bobAddsDocA --> docBRootAddsAnotherGroup

    style docBGroup fill:green;
    style docAGroup fill:green;

    style opsA fill:blue;
    style opsB fill:blue;
```

# Authority Graphs

A change to group membership MAY be causally dependent on the state of another group or document content (and vice versa).

## Example

```mermaid
flowchart RL
    subgraph docA[Document A]
        subgraph DocAState[Doc Content]
            opA4 --> opA2 --> opA1
            opA4 --> opA3 --> opA1
        end

        subgraph DocAAuth[Doc Auth]
            addAdminsGroup["Doc A Root<br>----------------------<br>Add Team Group"] --> initDocAAuth["Doc A Root<br>---------------------<br>Self Certified Init"]
        end
    end

    subgraph docB[Document B]
        subgraph DocBState[Doc Content]
            opB4 --> opB2 --> opB1
            opB4 --> opB3 --> opB1
        end

        subgraph DocBAuth[Doc Auth]
            direction TB
        
            addAdminsGroupB --> initDocBAuth
            addFrancine["Doc B Root<br>----------------<br>Add Francine"] --> initDocBAuth["Doc B Root<br>---------------------<br>Self-Certified Init"]
        end
    end

    subgraph admins[Team Group]
        rootAdminAddsBob["Team Root<br>---------------<br>Add Bob"] --> initAdmins["Team Root<br>---------------------<br>Self-Certified Init"]
        rootAdminAddsAlice["Team Root<br>---------------<br>Add Alice"] --> initAdmins
        aliceAddsCarol["Alice<br>------------<br>Add Carol"] ----> rootAdminAddsAlice
        bobRemovesCarol["Bob<br>-----------------<br>Remove Carol"] --> rootAdminAddsBob

        aliceAddsReaders["Alice<br>-----------------------<br>Add Readers Group"] --> rootAdminAddsAlice
    end

    subgraph readers[Readers Group]
        bobAddsErin["Bob<br>----------<br>Add Erin"] --> initReaders["Readers Root<br>---------------------<br>Self-Certified Init"]
        aliceAddsDan["Alice<br>----------<br>Add Dan"] --> initReaders
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

The above example materializes to the following:

```mermaid
%%{ init: { 'themeVariables': { 'lineColor': '#FFF' } } }%%
flowchart BT
    subgraph pullers[Pull]
        Francine

        subgraph read_only[Read]
            subgraph readers[Readers Group]
                direction TB

                Erin
                Dan

                reader_root
            end

            subgraph also_write[Write]
                subgraph also_change_membership[Unrestricted]
                    subgraph admins[Team Group]
                        direction TB

                        Alice
                        Bob
                        Carol

                        admin_root_pk
                    end

                    subgraph docA[Document A]
                        docA_root_pk[Doc A Root]
                    end

                    subgraph docB[Document B]
                        docB_root_pk[Doc B Root]
                    end
                end
            end
        end
    end

    docA --> admins
    docB --> admins

    docB --> Francine
    admins --> readers

    style pullers color:white,fill:darkblue,stroke:#FFF,stroke-width:1px,stroke-dasharray: 5 3;
    style read_only color:white,fill:blue,stroke:#FFF,stroke-width:1px,stroke-dasharray: 5 3;
    style also_write color:white,fill:purple,stroke:#FFF,stroke-width:1px,stroke-dasharray: 5 3;
    style also_change_membership color:white,fill:darkred,stroke:#FFF,stroke-width:1px,stroke-dasharray: 5 3;
```

Validating [capabilities] proceeds recursively. Given read access to the caveats of each group, a complete list of users and their capabilities. The lowest level of rights MUST be `pull`, which only requires knowing the current public key of leaf agents.

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
| Francine    | ✅         | ❌              | ❌             | ❌                         |
| Reader Root | ✅         | ✅              | ❌             | ❌                         |
| Admin Root  | ✅         | ✅              | ✅             | ✅                         |
| Doc A Root  | ❌         | ❌              | ❌             | ❌                         |
| Doc B Root  | ✅         | ✅              | ✅             | ✅                         |


# Auth State Transition

```rust
pub struct Attenuation {
    group_id: Option<GroupId>,
    ceveats: CeveatDsl
}

enum AuthAction {
  // Arguably this could be expressed as AddGroup with group_heads: vec![singleton.id] or possibly vec![]
  // It's a noop if you give a stateless agent a different head,
  // since you will never be able to apply the op.
  AddSingleton { 
    id: PublicKey,
    attenuation: Attenuation
  },
  
  // Add Group includes docs, since Doc :< Group
  // Since Group :< Singleton, you *could* add a group that way,
  // but it would add at the start of its history 
  // (which may or may not be desirable, depending on the domain)
  AddGroup { 
    id: PublicKey, 
    attenuation: Attenuation,
    group_heads: Vec<Hash>, // REMINDER: this is the group being added's heads (aud), NOT the group being added to (iss)
  },
  
  RemoveAgent { id: PublicKey },
}

struct AuthOp {
  action: AuthAction, // ⬆️
  
  /// The 
  auth_pred: Vec<Hash>, 
  
  /// All heads for all known updated documents.
  /// In effect, this locks the auth change to occur *after* content updates.
  doc_heads: BTreeMap<DocId, Vec<Hash>>,
  
  author: PublicKey,
  signature: Signature
}
```

### Roots

Auth roots are the key pair associated to a group. Since their public key is the document ID, these are REQUIRED to make delegation chains "self-certifying".

## Re-Adds

An Agent MAY be re-added to a group. In this case, the re-add operation MUST (transitively) causally succeed that Agent's revocation.

Note that for purposes of [seniority], the re-added Agent's seniority MUST be calculated from their earliest add (prior to the revocation).

# Delegation

Any [Agent] MAY delegate its authority over _it's own capabilities_ to others.

Restricting _sub-delegation_ of an Agent's capabilities MUST NOT be permitted. It is well known that attempting to do so leads to worse outcomes (e.g. users sharing secret keys), and prevents desirable behavior such as sub-delegating very narrow authority ([PoLA]) to ephemeral workers.

## Transitive Authority

Recall that [capabilities come in the following categories][capabilities]: pull, read, mutate, and manager. All of these MAY be attenuated. For example, an Agent MAY be granted the ability to alter the membership of an external group or document.

```mermaid
sequenceDiagram
    autonumber

    participant Doc
    participant Ink & Switch
    actor PvH
    actor Mallory

    Note over Doc,Ink & Switch: Setup Groups
    Ink & Switch ->> Ink & Switch: 🐣 Init
    Doc ->> Doc: 🐣 Init
    Doc ->> Ink & Switch: 🎟️ Delegate(Doc, Write)

    Note over Ink & Switch,Mallory: Add users to Ink & Switch

    Ink & Switch ->> PvH: 🎟️ Delegate all (including manage membership)
    Ink & Switch ->> Mallory: 🎟️ Delegate [Doc: Write]

    Note over Doc,Mallory: Users write ops to Doc
    PvH -->> Doc: ✍️ Write Op1 (authorized by ➋→➌→➍←➊)
    Mallory -->> Doc: ✍️ Write Op2 (authorized by ➋→➌→➎←➊)

    Note over Doc,Mallory: Mallory Revoked
    PvH -->> Ink & Switch: 💔 Revoke Mallory (authorized by ➊→➍)
    Mallory --x Doc: 🚫 Write Op3 (REJECTED becuase ➑)
```

### Cycles

Group delegations MUST form a directed graph, which MAY contain cycles. For example:

``` mermaid
flowchart LR
    subgraph Docs
        j["LaTeX Document<br>(Jacquard)"]
        p["Meeting Notes<br>(Patchwork)"]
    end

    subgraph Groups
        ias[Ink & Switch]
        bigco[BigCo]
    end

    subgraph Users
        pvh[Peter]
        ajg[Alex]
        bez[Brooke]
    end

    j --> ias
    p --> bigco

    ias ---> bigco
    bigco --> ias

    bigco --> bez
    bigco --> ajg

    ias --> ajg
    ias --> pvh

    linkStyle 2,3 stroke:green;
```

For simplicity, in this scenario BigCo and Ink & Switch have delegated to each other full control (shown in green). While they have different members, they can be considered a single group because they've co-delegated.

# Device Management

This strategy does not distinguish between users, groups, and public keys. In a sense, public keys are stateless singleton groups.

```mermaid
flowchart TB
    doc1["Meeting Notes<br>(Patchwork)"] -->|read only| ias
    doc2["LaTeX Paper<br>(Jacquard)"] -->|read & write| ias
    doc3["Kid's Homework<br>(Patchwork)"] -->|read| alice

    ias["Ink & Switch<br>(Keyhive Group)"] -->|all| alice

    subgraph alicedomain[" "]
        alice["''Alice''<br>(Keyhive Group)"]

        aliceLaptop[Alice's Laptop]
        aliceTablet[Alice's Tablet]
        alicePhone[Alice's Phone]
        
        alicePW[Homework App WebCrypto Context]
        aliceJQ[LaTeX Editor WebCrypto Context]

        aliceLaptop -->|only Homework Doc| alicePW
        aliceLaptop -->|only LaTeX Doc| aliceJQ
        
        alice -->|all| aliceTablet
        alice -->|all| aliceLaptop
        alice -->|all| alicePhone -->|only LaTeX Doc read| NotificationsApp[Notifications App]
    end
```

# Applications to [Collection Sync]

Chunk providers (sync servers and peers) need to know which documents that Agents are permitted to pull. Ideally this is done in as few round trips as possible. The requester may not know of all the documents that are allowed to pull. To find the relevant documents, the provider walks the auth graph, starting from the requester. Every reachable document is included in the collection, and sent to the user in one response. If the requester knows of more documents that were not included, it either means that the provider is missing auth operations, and can prove access by pushing the relevant auth histories to the provider at the start of a second round.

<!-- External Links -->

[BCP 14]: https://datatracker.ietf.org/doc/bcp14/
[Collection Sync]: ./collection_sync.md
 [capabilities]: ./convergent_capabilities.md
