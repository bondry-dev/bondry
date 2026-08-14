#![doc = "Linked size probe for the HTTP and TLS transport."]

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use bondry_transport::{
    Deadline, EndpointPolicy, HttpLimits, HttpRequest, HttpTransport as _, NetworkEndpoint,
};
use bondry_transport_net::NetHttpTransport;
use bytes::Bytes;
use http::{HeaderMap, Method};

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| unreachable!("current-thread runtime must build: {error}"));
    let transport = NetHttpTransport::new()
        .unwrap_or_else(|error| unreachable!("platform verifier must initialize: {error}"));
    let endpoint = NetworkEndpoint::new(
        "https://127.0.0.1:1/"
            .parse()
            .unwrap_or_else(|error| unreachable!("probe endpoint must parse: {error}")),
    )
    .unwrap_or_else(|error| unreachable!("probe endpoint must validate: {error}"));
    let request = HttpRequest::new(
        Method::GET,
        endpoint,
        HeaderMap::new(),
        Bytes::new(),
        Deadline::at(Instant::now() + Duration::from_secs(1)),
        EndpointPolicy::default(),
        HttpLimits::default(),
    )
    .unwrap_or_else(|error| unreachable!("probe request must validate: {error}"));
    drop(black_box(runtime.block_on(transport.send(request))));
}
