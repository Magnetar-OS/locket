//! Asking before signing.
//!
//! An agent socket is reachable by every process running as you — the crate
//! docs say so, and it is the reason `ADD_IDENTITY` is refused. But a key that
//! signs silently on request is still a key that any of those processes can
//! use, once, for anything, without a trace beyond a log line.
//!
//! Marking an item `confirm-each-use` closes that: the signature waits for
//! someone to say yes. This is OpenSSH's `ssh-add -c`, moved to the vault so
//! it survives a restart and travels with the key rather than living in
//! whichever `ssh-add` invocation happened to add it.
//!
//! Deliberately per key. Confirming *every* signature trains people to click
//! yes, which is worse than not asking; the keys worth gating are the few that
//! authorise something expensive.

/// Asks the person at the keyboard whether a signature may go ahead.
///
/// Called from a blocking context and expected to block — the SSH client on
/// the other end is waiting for its signature, and there is nothing sensible
/// to do in the meantime.
pub trait SigningConfirmer: Send + Sync {
    /// `key` is the identity's comment: what the user will recognise it by.
    ///
    /// Returning false refuses the signature. So does taking too long, which
    /// is the implementation's business rather than this trait's.
    fn confirm(&self, key: &str) -> bool;
}

/// Refuses everything, for tests and for a daemon with no frontend.
pub struct AlwaysDeny;

impl SigningConfirmer for AlwaysDeny {
    fn confirm(&self, key: &str) -> bool {
        tracing::warn!("refusing to sign with `{key}`: nothing can ask for confirmation");
        false
    }
}
