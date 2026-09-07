//! `.env` files are read out of arbitrary project trees; the parser and the
//! secret classifier both see whatever those files hold.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for var in locket_import::dotenv::parse(text) {
        let _ = locket_import::dotenv::is_secret(&var.key, &var.value);
        let _ = locket_import::dotenv::service_of(&var.key);
    }
});
