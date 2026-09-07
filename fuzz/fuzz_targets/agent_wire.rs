//! Every process running as the user can reach the agent socket, so the
//! request parser sees genuinely hostile bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_agent::protocol::Request;

fuzz_target!(|data: &[u8]| {
    let _ = Request::parse(data);
});
