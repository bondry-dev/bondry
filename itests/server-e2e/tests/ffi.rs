#![allow(missing_docs)]

use bondry_local_server_ffi::BONDRY_SERVER_CONFIGURATION_VERSION_V1;
use bondry_runtime_ffi::{BONDRY_ABI_VERSION_V1, bondry_abi_version_v1};

#[test]
fn links_the_versioned_runtime_and_server_abis() {
    assert_eq!(bondry_abi_version_v1(), BONDRY_ABI_VERSION_V1);
    assert_eq!(BONDRY_SERVER_CONFIGURATION_VERSION_V1, 1);
}
