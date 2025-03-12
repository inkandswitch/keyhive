# TODO



## The big list

* Make sure we are incrementally saving ShareSecretKeys
* Find a better name than `sync_loops`
* Move change forwarding into it's own top level thing alongside the sync loop manager in run_inner
* Unify encoding of commits and strata
  * Handle encryption of bundles and commits at the type level
* Implement ticks
  * On each tick:
    * Expire old sessions
    * Rerun sync for sessions older than 1 minute
* Ensure that when a document is loaded we have incorporated any decrypted
events we received since the load was started into the return value so that
callers know they only have to listen to events from the point the document is
returned.
* Stop using async for stream processing, it's confusing
* Make connection tests clearer
* Consider whether we can get rid of the list-one-level thing by keeping an index of all documents somewhere
