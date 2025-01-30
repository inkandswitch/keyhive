# BeeKEM

## Definitions
*encrypter child*: the child node that last encrypted its parent.

*inner node*: a non-leaf node of the BeeKEM tree. It can either be blank (`None`) or contain one or more public keys. More than one public key indicates the merge of conflicting concurrent updates. Each public key on an inner node will be associated with a secret key which is separately encrypted for the encrypter child and all members of that encrypter child's sibling resolution.

*leaf node*: the leaf of the BeeKEM tree, which corresponds to a group member identifier and its latest public key/s. A leaf node can also be blank (`None`) if either (1) it is to the right of the last added member in the tree or (2) the member corresponding to that node was removed (in this case, the blank functions as an implicit tombstone).

*ownership of a tree*: you own a tree if you can use it to encrypt a new root secret. An owner will correspond to one of the members of the tree group (and hence one of its leaves).

*resolution*: either (1) the public key/s of a node or (2) if the node is blank or contains conflict keys, all of its highest non-blank, non-conflict descendants' public keys. The resolution is never taken at the root, so the worst case resolution is the n / 2 leaves of one of the root's child sub-trees if all of that sub-tree's inner nodes are blank or contain conflict keys.

## Invariants

* A group will always have at least one member. Hence, a tree will always have at least one non-blank leaf.
* In a subset of operations, concurrent adds and removes must be ordered last (because they blank inner nodes).

### Properties that must be ensured by Keyhive
* Causal ordering (and receipt) of CGKA operations.

### Public Key invariants
* After a node is updated and a new secret encrypted, it will have a single public key (corresponding to that new secret).
* A node encrypting its parent will always have a single public key. That's because
* * you can only encrypt starting from the leaf you own,
* * the leaf you own will always have a single public key in your copy since you will always have all causal predecessors and will have written the latest one, and
* * each parent you encrypt up your path will have a single public key after encryption.
* A node might have multiple conflicting public keys if concurrent updates from other members are merged into your tree. Each public key corresponds to a separate secret key.

## Notes

* A root secret will always correspond with a specific key rotation (update) at one of the leaves.
* After a merge of two concurrent operations, the tree will no longer have a root secret.
