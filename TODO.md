# In Progress
* Move the auth manager out of the connection manager, don't clone signing keys

Needs some thought, the auth manager is initialized with a receive audience. This was fine when I was creating a new auth manager for each connection but now that I've moved all interaction with signing to the `effects` module I need to figure out some way of passing the receive audience in to the auth manager and then hang on to the receive audience state in the handshake state.

# Later
* Implement auth-failed error message and re-authentication flow
* Split InnerRpcResponse into things we send over the wire and things we don't
* Rename Story -> Command, change request ID to an enum over command or stream ID
  * Then, we can tell when a response is for a now closed stream even if we've forgotten the stream ID
* Review the blobmeta stuff, do we really needs blobs for loose commits in a separate storage area?
* Handle dynamic remote peers when forwarding listen requests
