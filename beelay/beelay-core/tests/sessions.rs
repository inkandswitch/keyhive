use std::time::Duration;

use beelay_core::UnixTimestampMillis;
use network::Network;
use test_utils::init_logging;

mod network;

#[test]
fn sessions_are_expired() {
    init_logging();
    tracing::trace!(time=?UnixTimestampMillis::now(), "time at start");
    let mut network = Network::new();
    let client = network.create_peer("client").build();
    let server = network
        .create_peer("server")
        .session_duration(Duration::from_secs(1))
        .build();

    assert_eq!(network.beelay(&server).num_sessions(), 0);

    network.connect_stream(&client, &server);

    assert_eq!(network.beelay(&server).num_sessions(), 1);

    network.beelay(&server).advance_time(Duration::from_secs(2));
    assert_eq!(network.beelay(&server).num_sessions(), 0);
}
