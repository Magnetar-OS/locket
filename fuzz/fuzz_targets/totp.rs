//! TOTP seeds arrive from QR scans, pasted URIs and authenticator exports —
//! all foreign input. A parsed seed must also survive its own `to_uri`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::Totp;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(totp) = Totp::parse(text) {
        let uri = totp.to_uri();
        let _ = Totp::parse(&uri).expect("a seed's own URI failed to reparse");
        let _ = totp.code();
    }
    let _ = locket_import::totp::parse_any(text);
});
