# Collection Sync

## Dependencies

* [Group Membership]

# Abstract

Synchronizing the operations for a single document involves finding which ops are not present on each replica. This naturally extends to _collections_ of documents. This introduces a new concern: how to efficiently track _which documents_ to sync, given that either peer may not be aware of the existence of all documents. This further interacts with [Pull Control], which provides a clean mechanism for determining which documents are available to a peer.

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Discovery

Collection sync proceeds from a specific replica's public key to the Document IDs (also public keys) that they have Pull Access to. This proceeds via traversal of the directed graph in reverse (from delegate to delegator), and collecting all reachable nodes.

```mermaid
flowchart
    subgraph Documents
        groceries[("Groceries")]

        hiking_plans[("Hiking Plans")]
        threat_model[("Keyhive\nThreat Model")]
        meeting_notes[("Meeting Notes")]

        w32[("Week 32 Notes")]
        w33[("Week 33 Notes")]
    end

    subgraph Groups
        ias{{"Ink & Switch"}}
        keyhive{{"Keyhive Team"}}
        jacquard{{"Jacquard Team"}}

        ajg{{"Alex"}}
        ajg_work{{"Alex Work"}}

        bez{{"Brooke"}}
        gl{{"Geoffrey"}}
        ps{{"Paul"}}
        pvh{{"Peter"}}
    end

    subgraph Devices
        alex_home(["Alex's Shared\nHome Computer"])
        alex_phone(["Alex's Phone"])
        alex_laptop(["Alex's Work Laptop"])

        bez_devices(["..."])

        gl_devices(["..."])
        ps_devices(["..."])

        pvh_phone(["Peter's Phone"])
        pvh_laptop(["Peter's Laptop"])
    end

    groceries --> ajg
    ajg --> alex_home

    ajg --> ajg_work
    ajg_work --> alex_phone
    ajg_work --> alex_laptop

    pvh --> pvh_laptop
    pvh --> pvh_phone

    bez --> bez_devices

    gl --> gl_devices
    ps --> ps_devices

    w32 --> meeting_notes
    w33 --> meeting_notes

    meeting_notes --> ias
    threat_model --> keyhive

    ias --> pvh
    ias --> keyhive
    ias --> jacquard

    keyhive --> ajg_work
    keyhive --> bez

    jacquard --> gl
    jacquard --> ps

    hiking_plans --> pvh
    
    linkStyle 0,1 stroke:red;
    linkStyle 5,10,11,12,14,21 stroke:red;
```

In this scenario, the following would need to be added to the sync collection for two of the devices:
* Alex's Shared Home Computer
  * Alex (group membership)
  * Groceries (content & group membership)
* Peter's Laptop
  * Peter (group membership)
  * Ink & Switch (group membership)
  * Hiking Plans (content & group membership)
  * Meeting Notes (content & group membership)
  * Week 32 Notes (content & group membership)
  * Week 33 Notes (content & group membership)
  
## Reverse Lookup
  
Even though this search involves a reverse lookup on the links, it can be treated as a valid materialization of the delegation operations. There is nothing preventing an implementation from materializing both forward and backward views of the data.

# Cycles

Recall that [cycles and redundant links are permitted in the authority graph].

```mermaid
flowchart
    subgraph Documents
        docA[("DocA")]
        docB[("DocB")]
    end

    subgraph Groups
        bob{{"Bob"}}
        alice{{"Alice"}}
    end

    subgraph Devices
        alice_phone(["Alice's Phone"])
        alice_laptop(["Alice's Laptop"])
        
        bob_phone(["Bob's Phone"])
        bob_tablet(["Bob's Tablet"])
    end

    docB --> docA
    docA --> alice
    docB --> bob

    alice --> bob
    bob --> alice

    alice --> alice_phone
    alice --> alice_laptop

    bob --> bob_phone
    bob --> bob_tablet
```

Due to this, the node discovery MUST be run to a fixed point. Memoization is RECOMMENDED to improve the performance of such lookups.

Using the example above, we know that any node that has a path to Alice automatically has a path to Doc A, Doc B, and Bob. Alice's Phone's reachable subgraph is given below:

```mermaid
flowchart
    subgraph Documents
        docA[("DocA")]
        docB[("DocB")]
    end

    subgraph Groups
        bob{{"Bob"}}
        alice{{"Alice"}}
    end

    subgraph Devices
        alice_phone(["Alice's Phone"])
    end

    docB -.-> docA
    docA --> alice
    docB --> bob

    alice -.-> bob
    bob --> alice

    alice --> alice_phone
```

Any node that has a path to Bob also has a path to Alice, Doc A and Doc B. Therefore, by virtue of a path to Alice, Alice's Laptop can automatically assume access to Doc A, Doc B, and Bob. Bob's Tablet's reachable subgraph is given below:

```mermaid
flowchart
    subgraph Documents
        docA[("DocA")]
        docB[("DocB")]
    end

    subgraph Groups
        bob{{"Bob"}}
        alice{{"Alice"}}
    end

    subgraph Devices
        bob_tablet(["Bob's Tablet"])
    end

    docB -.-> docA
    docA --> alice
    docB --> bob

    alice --> bob
    bob -.-> alice

    bob --> bob_tablet
```

<!-- External Links -->
[Group Membership]: ./group_membership.md
