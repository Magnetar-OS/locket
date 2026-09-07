//! The vault file is the one input locket reads off disk before any
//! authentication has happened, so its parser gets arbitrary bytes. The body
//! (`VaultData`) is parsed only after the AEAD has authenticated it, but a
//! bug there is still a bug — an attacker who can write the file can also
//! write a valid one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::{VaultData, vault::VaultFile};

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = serde_json::from_slice::<VaultFile>(data) {
        // What parsed must serialize and parse again: the save path feeds
        // the AAD from these same structures.
        let bytes = serde_json::to_vec(&file).expect("a parsed vault file failed to serialize");
        let _ = serde_json::from_slice::<VaultFile>(&bytes)
            .expect("a serialized vault file failed to reparse");
    }
    if let Ok(body) = serde_json::from_slice::<VaultData>(data) {
        let bytes = serde_json::to_vec(&body).expect("a parsed body failed to serialize");
        let _ = serde_json::from_slice::<VaultData>(&bytes)
            .expect("a serialized body failed to reparse");
    }
});
