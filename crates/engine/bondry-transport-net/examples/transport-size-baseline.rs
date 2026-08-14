#![doc = "Baseline size probe for the transport executor."]

use std::hint::black_box;

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| unreachable!("current-thread runtime must build: {error}"));
    black_box(runtime);
}
