# Group Membership

Group membership in Beehive has two main concepts: a membership CRDT, and a variant of object capabilities adapted to an eventually consistent setting. We propose naming this class of capabilities "Convergent Capabilities", or "concap" for short.

## Example

```mermaid
flowchart
    subgraph Legend
        direction TB
        successor --> predecessor
    end
```

```mermaid
flowchart
    subgraph docA
        direction TB
        
        subgraph DocAState
            direction RL
            
            opA4 --> opA2 --> opA1
            opA4 --> opA3 --> opA1
        end

        subgraph DocAAuth
            direction TB
        
            addAdminsGroup --> initDocAAuth
        end
    end

    subgraph docB
        direction TB
        
        subgraph DocBState
            opB4 --> opB2 --> opB1
            opB4 --> opB3 --> opB1
        end

        subgraph DocBAuth
            direction TB
        
            addAdminsGroupB --> initDocBAuth
        end
    end

    subgraph admins
        direction TB
        
        rootAdminAddsBob --> initAdmins
        rootAdminAddsAlice --> initAdmins
        aliceAddsCarol --> rootAdminAddsAlice
        bobRemovesCarol --> rootAdminAddsBob

        aliceAddsWriters --> rootAdminAddsAlice
    end

    subgraph writers
        direction TB

        bobAddsErin --> initWriters
        aliceAddsDan --> initWriters
    end

    bobRemovesCarol -.-> opA3
    bobRemovesCarol -...-> opB4

    aliceAddsWriters -.-> bobAddsErin
    aliceAddsWriters -.-> aliceAddsDan

    addAdminsGroup -.-> rootAdminAddsBob
```

# State Transition

The state of a 

# Delegated Authority

## Transitive Authority

## Applications to [Collection Sync]

# FAQ

## Differences from Access Control Lists (ACLs)

## Differences from Object Capabilities (ocap)

## Differences from Certificate Capabilities / SPKI

<!-- External Links -->

[Collection Sync]: ./collection_sync.md
