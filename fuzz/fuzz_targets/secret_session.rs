//! The Secret Service session transport: a client's DH public key and,
//! once a session exists, the (parameters, value) pair of every secret it
//! sends. Both arrive from arbitrary processes on the session bus.

#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_secret::session::SessionStore;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let mut store = SessionStore::new();
    match selector % 3 {
        // A client opening a DH session with an arbitrary public key.
        0 => {
            let _ = store.open("dh-ietf1024-sha256-aes128-cbc-pkcs7", Some(rest), None);
        }
        // A plain session decoding arbitrary bytes.
        1 => {
            if let Ok((session, _)) = store.open("plain", None, None) {
                let _ = session.decode(&[], rest);
            }
        }
        // A DH session (opened with the fuzz input as the peer key, when
        // that succeeds) decoding an arbitrary parameters/value split.
        _ => {
            let mid = rest.len() / 2;
            let (peer, payload) = rest.split_at(mid);
            if let Ok((session, _)) =
                store.open("dh-ietf1024-sha256-aes128-cbc-pkcs7", Some(peer), None)
            {
                let cut = payload.len() / 2;
                let (params, value) = payload.split_at(cut);
                let _ = session.decode(params, value);
            }
        }
    }
});
