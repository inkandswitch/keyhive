# TODO



## The big list
* Add signatures to commits and bundles
  * Signatures will need to be stored separately from commits because we can have multiple signatures per commit
  * Bundles will need signatures per run of commits in the bundle
* Bundle peer ID in with peer address
* Introduce a GroupId type instead of using PeerId for the group id
* Make sure we are incrementally saving ShareSecretKeys
* Find a better name than `sync_loops`
* Move change forwarding into it's own top level thing alongside the sync loop manager in run_inner
* Unify encoding of commits and strata
  * Handle encryption of bundles and commits at the type level
* Ensure that when a document is loaded we have incorporated any decrypted
events we received since the load was started into the return value so that
callers know they only have to listen to events from the point the document is
returned.
* Consider whether we can get rid of the list-one-level thing by keeping an index of all documents somewhere
