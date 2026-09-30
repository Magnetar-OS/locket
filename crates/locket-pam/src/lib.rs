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
//! and the login untouched.
//!
//! That includes a panic. Each hook runs inside [`contained`], which turns a
//! panic into the hook's ordinary "nothing to report" code, so nothing
//! unwinds into libpam and no hook ever answers `PAM_ABORT`. `pam-bindings`
//! has a guard of its own underneath, and that one does answer `PAM_ABORT` —
//! reachable now only if libpam hands the module a null handle or argument,
//! which it does not.
//!
//! Install it as `optional` all the same. Linux-PAM reads `optional` as
//! `[success=ok new_authtok_reqd=ok default=ignore]` (`libpam/pam_handlers.c`),
//! and its dispatcher looks the action up by return code before anything else
//! (`_pam_dispatch_aux` in `libpam/pam_dispatch.c`): every code but those two,
//! `PAM_ABORT` included, is `_PAM_ACTION_IGNORE` and leaves the stack's
//! verdict alone. The one place the dispatcher singles `PAM_ABORT` out is
//! inside the `bad`/`die` actions, which an `optional` line never reaches.
//! Read from the 1.7.2 sources.
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

/// Run one hook's body, and answer `otherwise` if it panics.
///
/// `otherwise` is what the hook returns when it has nothing to do, so a
/// defect in here reads to PAM exactly as a login without a vault does.
fn contained(otherwise: PamResultCode, body: impl FnOnce() -> PamResultCode) -> PamResultCode {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(payload) => {
            // The payload's own destructor may panic; it is not worth running.
            std::mem::forget(payload);
            log("locket: internal error in pam_locket; the login is unaffected");
            otherwise
        }
    }
}

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
    // `c_char`, not `i8`: it is signed on x86_64 and unsigned on aarch64, and
    // hardcoding either one fails to compile on the other architecture.
    let mut buf = vec![0 as libc::c_char; 4096];
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
        contained(PamResultCode::PAM_IGNORE, || Self::stash_token(pamh))
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
        contained(PamResultCode::PAM_IGNORE, || Self::rekey(pamh, flags))
    }

    /// Hand the token to the daemon, if one is listening.
    fn sm_open_session(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        contained(PamResultCode::PAM_SUCCESS, || Self::unlock(pamh))
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

impl PamLocket {
    fn stash_token(pamh: &mut PamHandle) -> PamResultCode {
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

    fn rekey(pamh: &mut PamHandle, flags: PamFlag) -> PamResultCode {
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

    fn unlock(pamh: &mut PamHandle) -> PamResultCode {
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
}

/// A PAM token as a `String`, if it is text and not empty.
fn token_string(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let s = std::str::from_utf8(bytes).ok()?;
    (!s.is_empty()).then(|| Zeroizing::new(s.to_owned()))
}

/// Write to syslog. A PAM module has no stderr worth using.
fn log(message: &str) {
    // The tests run as an ordinary program, with no business in the
    // machine's auth log.
    if cfg!(test) {
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic inside a hook must reach PAM as the hook's ordinary "nothing
    /// to report" — never as an unwind through libpam's frames, and never as
    /// `PAM_ABORT`, which a `required` line would turn into a failed login.
    #[test]
    fn a_panicking_hook_answers_as_if_it_had_nothing_to_do() {
        // The default hook would print the panic into the login program.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let auth = contained(PamResultCode::PAM_IGNORE, || panic!("a defect in a hook"));
        let session = contained(PamResultCode::PAM_SUCCESS, || panic!("a defect in a hook"));
        std::panic::set_hook(hook);

        assert_eq!(auth, PamResultCode::PAM_IGNORE);
        assert_eq!(session, PamResultCode::PAM_SUCCESS);
    }

    #[test]
    fn a_hook_that_does_not_panic_answers_for_itself() {
        assert_eq!(
            contained(PamResultCode::PAM_IGNORE, || PamResultCode::PAM_SUCCESS),
            PamResultCode::PAM_SUCCESS
        );
    }

    /// The entry points libpam calls, given a handle that is not one. They
    /// must return rather than fault or unwind; `pam-bindings` answers for a
    /// null handle before any hook runs.
    #[test]
    fn the_entry_points_return_for_a_null_handle() {
        for entry in [
            pam_sm_authenticate,
            pam_sm_setcred,
            pam_sm_chauthtok,
            pam_sm_open_session,
            pam_sm_close_session,
        ] {
            // SAFETY: `invoke_hook` checks the handle for null before use, and
            // `argc == 0` means `argv` is never read.
            let code = unsafe { entry(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
            assert_eq!(code, PamResultCode::PAM_ABORT);
        }
    }
}
