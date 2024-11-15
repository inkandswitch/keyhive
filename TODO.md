* When a stream closes cancel all associated tasks
  * This is crucial for graceful shutdown
* Implement auth-failed error message and re-authentication flow
* Move the auth manager out of the connection manager, don't clone signing keys
* Unify story IDs and request IDs
* Move streams out of effects::State, it should be on `Beelay` I think
* Split InnerRpcResponse into things we send over the wire and things we don't
* Rename Story -> Command, change request ID to an enum over command or stream ID
  * Then, we can tell when a response is for a now closed stream even if we've forgotten the stream ID
* Fix task cancellation in `Io::cancel_job` to not be O(number of tasks we are executing)
