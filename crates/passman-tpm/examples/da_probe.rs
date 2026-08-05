//! Prove that the TPM's dictionary-attack lockout actually engages.
//!
//! The whole reason a short PIN is defensible is that guessing is rate-limited
//! in hardware, which only holds if the sealed object is *not* marked `noDA`.
//! This enrols a PIN-protected slot and hammers it, printing what the TPM says.
//!
//! Against swtpm with the default `MAX_AUTH_FAIL = 3`:
//!
//! ```text
//! attempt 1: refused (... DA counter incremented)
//! attempt 2: refused (... DA counter incremented)
//! attempt 3: refused (... TPM is in DA lockout mode)
//! correct PIN now refused too: ... DA lockout mode
//! ```
//!
//! Note the last line: lockout is a device-wide property, so a hammering
//! attacker also locks *you* out until the recovery interval elapses. That is
//! the cost of the protection, and the reason a passphrase slot must always
//! remain enrolled.
//!
//! ```sh
//! swtpm socket --tpm2 --tpmstate dir=/tmp/tpm --ctrl type=tcp,port=2322 \
//!   --server type=tcp,port=2321 --flags not-need-init,startup-clear &
//! TCTI="swtpm:host=localhost,port=2321" \
//!   cargo run -p passman-tpm --example da_probe
//! ```
fn main() {
    let (factor, _kek) = passman_tpm::enroll(Some("123456")).expect("enroll");
    println!("enrolled a PIN-protected slot");
    for attempt in 1..=6 {
        match passman_tpm::unseal(&factor, Some("000000")) {
            Ok(_) => println!("attempt {attempt}: UNSEALED WITH WRONG PIN  <-- BAD"),
            Err(e) => println!("attempt {attempt}: refused ({e})"),
        }
    }
    // The correct PIN after a hammering run: locked out, or still working?
    match passman_tpm::unseal(&factor, Some("123456")) {
        Ok(_) => println!("correct PIN still works (no lockout engaged)"),
        Err(e) => println!("correct PIN now refused too: {e}"),
    }
}
