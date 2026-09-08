//! `pam_locket.so` — unlock the vault at login.
//!
//! Takes the password PAM has already collected at the login screen and hands
//! it to the daemon over the unlock socket. When that password is also your
//! vault passphrase, logging in unlocks the vault, and every `libsecret`
//! application finds its secrets without a second prompt.
//!
//! # What this module is not
//!
//! It is a **session** module. It never decides whether you may log in, and it
//! never grants a privilege. `sm_authenticate` returns `PAM_IGNORE` — it only
//! observes the token PAM already collected — so a bug here cannot authorise
//! anybody. Authorising `sudo` from locket is a different module with a much
//! higher bar, and it is not this one.
//!
//! # Failure policy
//!
//! Every failure path returns success. A password manager that will not let
//! you log in is worse than one that does not auto-unlock, so a missing
//! daemon, a wrong passphrase, or a broken socket all leave the vault locked
//! and the login untouched. Install it as `optional` and it cannot lock you
//! out even if it panics.
//!
//! # Installation
//!
//! ```text
//! # /etc/pam.d/system-login, AFTER pam_systemd.so — the socket lives in
//! # /run/user/<uid>, which pam_systemd is what creates.
//! auth     optional  pam_locket.so
//! session  optional  pam_locket.so
//! ```

use std::ffi::CStr;

use pam::constants::{PamFlag, PamResultCode};
use pam::items::{AuthTok, OldAuthTok};
use pam::module::{PamHandle, PamHooks};
use zeroize::Zeroizing;

/// `PAM_PRELIM_CHECK` from `<security/_pam_types.h>`.
///
/// Spelled out here because `pam-bindings` does not re-export it, and reading
/// the flag wrong would mean rekeying the vault during the dry-run pass — the
/// one that exists precisely so nothing is changed yet.
const PAM_PRELIM_CHECK: PamFlag = 0x4000;

/// Key under which the token is stashed between `auth` and `session`.
///
/// PAM clears its own data at the end of the transaction, so nothing outlives
/// the login.
const STASH_KEY: &str = "locket_authtok";

struct PamLocket;

impl PamLocket {
    /// The uid whose runtime directory the socket lives in.
    fn target_uid(pamh: &mut PamHandle) -> Option<u32> {
        let user = pamh.get_user(None).ok()?;
        lookup_uid(&user)
    }
}

/// Resolve a username to a uid via `getpwnam_r`.
fn lookup_uid(user: &str) -> Option<u32> {
    let c_user = std::ffi::CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    // SAFETY: `getpwnam_r` writes into `pwd` and `buf`, both of which outlive
    // the call, and reports the outcome through `result`. The re-entrant form
    // is used precisely so this is safe inside a PAM module.
    let rc = unsafe {
        libc::getpwnam_r(
            c_user.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(pwd.pw_uid)
}

impl PamHooks for PamLocket {
    /// Observe the authentication token; never decide anything.
    ///
    /// Returning `PAM_IGNORE` keeps this module out of the authentication
    /// decision entirely — it cannot let anyone in, only remember what PAM
    /// already accepted.
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        match pamh.get_item::<AuthTok>() {
            Ok(Some(token)) => {
                // The item type exposes only bytes and redacts itself in
                // `Debug`, which is the right shape for a password — take a
                // zeroizing copy rather than anything longer-lived.
                if let Ok(s) = std::str::from_utf8(token.as_bytes())
                    && !s.is_empty()
                {
                    // Stashed for `sm_open_session`: at this point the user's
                    // runtime directory does not exist yet.
                    let _ = pamh.set_data(STASH_KEY, Box::new(Zeroizing::new(s.to_owned())));
                }
            }
            _ => {
                // No token — a passwordless or key-based login. Nothing to do.
            }
        }
        PamResultCode::PAM_IGNORE
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// Follow a login password change through to the vault.
    ///
    /// Without this, `passwd` silently ends the arrangement: the login
    /// password and the vault passphrase drift apart, auto-unlock stops
    /// working, and nothing anywhere says why. The daemon is handed both
    /// halves and re-wraps the vault key under the new one — it verifies the
    /// old passphrase itself, so a failure here means the vault was never
    /// using this password and there is nothing to change.
    ///
    /// PAM calls this twice. The first pass (`PAM_PRELIM_CHECK`) is for
    /// modules to object *before* anything is changed; this module has no
    /// grounds to object, and says so by ignoring it.
    fn sm_chauthtok(pamh: &mut PamHandle, _args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        if flags & PAM_PRELIM_CHECK != 0 {
            return PamResultCode::PAM_IGNORE;
        }

        let old = match pamh.get_item::<OldAuthTok>() {
            Ok(Some(token)) => token_string(token.as_bytes()),
            _ => None,
        };
        let new = match pamh.get_item::<AuthTok>() {
            Ok(Some(token)) => token_string(token.as_bytes()),
            _ => None,
        };
        let (Some(old), Some(new)) = (old, new) else {
            // A passwordless or non-interactive change. Nothing to carry over.
            return PamResultCode::PAM_IGNORE;
        };

        let Some(uid) = PamLocket::target_uid(pamh) else {
            return PamResultCode::PAM_IGNORE;
        };
        let socket = locket_ipc::socket_path_for_uid(uid);
        match locket_ipc::request_rekey(&socket, &old, &new) {
            Ok(true) => log("locket: vault passphrase updated to match"),
            Ok(false) => {
                // The vault was not using the login password. Common and fine.
                log("locket: login password changed; the vault uses a different one")
            }
            Err(locket_ipc::Error::NotListening) => {}
            Err(e) => log(&format!("locket: could not reach the daemon: {e}")),
        }

        // Never the reason a password change fails, for the same reason
        // `sm_authenticate` is never the reason a login does.
        PamResultCode::PAM_IGNORE
    }

    /// Hand the token to the daemon, if one is listening.
    fn sm_open_session(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // Every early return is PAM_SUCCESS: this module must never be the
        // reason a session fails to open.
        let Some(uid) = PamLocket::target_uid(pamh) else {
            return PamResultCode::PAM_SUCCESS;
        };

        let token: Option<&Zeroizing<String>> = unsafe { pamh.get_data(STASH_KEY) }.ok();
        let Some(token) = token else {
            return PamResultCode::PAM_SUCCESS;
        };

        let socket = locket_ipc::socket_path_for_uid(uid);
        match locket_ipc::request_unlock(&socket, token) {
            Ok(true) => {
                // Deliberately says nothing about the passphrase itself.
                log("locket: vault unlocked for the session");
            }
            Ok(false) => {
                // The login password is not the vault passphrase. Entirely
                // normal, and not something to nag about on every login.
                log("locket: login password did not match the vault; left locked");
            }
            Err(locket_ipc::Error::NotListening) => {
                // No daemon: the common case on a machine that does not run one.
            }
            Err(e) => log(&format!("locket: could not reach the daemon: {e}")),
        }

        PamResultCode::PAM_SUCCESS
    }

    fn sm_close_session(
        _pamh: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        // Locking on logout is the daemon's business — it knows whether other
        // sessions are still open. Doing it here would lock the vault out from
        // under a second, still-live login.
        PamResultCode::PAM_SUCCESS
    }
}

/// A PAM token as a `String`, if it is text and not empty.
fn token_string(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let s = std::str::from_utf8(bytes).ok()?;
    (!s.is_empty()).then(|| Zeroizing::new(s.to_owned()))
}

/// Write to syslog. A PAM module has no stderr worth using.
fn log(message: &str) {
    if let Ok(c) = std::ffi::CString::new(message) {
        // SAFETY: `syslog` copies the formatted string; `c` outlives the call.
        unsafe {
            libc::syslog(
                libc::LOG_AUTHPRIV | libc::LOG_INFO,
                c"%s".as_ptr(),
                c.as_ptr(),
            );
        }
    }
}

pam::pam_hooks!(PamLocket);
