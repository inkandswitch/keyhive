# TODO



## The big list

* Don't generate a contact card on load, instead do it on demand (i.e. create a command for creating a contact card). Otherwise we do a prekey rotation on every load!
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
* Figure out how to turn the async keyhive APIs (e.g. `Keyhive::revoke_member`) into a two stage API which produces signing requests and accepts signing responses. Otherwise we have to lock the whole event loop for every signing request.
* Make connection tests clearer
* Consider whether we can get rid of the list-one-level thing by keeping an index of all documents somewhere
