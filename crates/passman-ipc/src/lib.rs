//! The unlock socket: how a passphrase reaches `passmand` from outside.
//!
//! Used by the PAM module at login, and by anything else that legitimately
//! holds the user's passphrase and wants the daemon unlocked. The protocol is
//! deliberately trivial — one length-prefixed passphrase in, one status byte
//! back — because the *interesting* security properties are in where the
//! socket lives, not in what is spoken over it:
//!
//! * The socket sits in `/run/user/<uid>/passman/`, a directory the kernel
//!   gives that user alone (mode 0700, owned by them). Only that uid and root
//!   can reach it, so no bus policy or peer-credential dance is needed.
//! * The socket itself is 0600, so a stray relaxation of the parent directory
//!   is not immediately fatal.
//! * Nothing is ever written to disk. A passphrase that arrives here goes into
//!   the daemon's memory and nowhere else.
//!
//! This crate has no dependencies beyond `zeroize` on purpose: it is linked
//! into a PAM module that loads on **every** login, including `sudo` and `su`.
//! Pulling an async runtime or a D-Bus client into that path would be
//! irresponsible.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::PathBuf;

use zeroize::Zeroizing;

/// Longest passphrase accepted, so a bad client cannot make the daemon
/// allocate without bound.
pub const MAX_PASSPHRASE_LEN: usize = 4096;

/// Reply byte: the vault is now unlocked.
pub const REPLY_UNLOCKED: u8 = 1;
/// Reply byte: the passphrase was refused.
pub const REPLY_REFUSED: u8 = 0;

/// Where the unlock socket lives for a given uid.
///
/// Derived from the uid rather than `$XDG_RUNTIME_DIR`, because a PAM module
/// runs as root in a process whose environment belongs to nobody in
/// particular.
pub fn socket_path_for_uid(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/passman/unlock.sock"))
}

/// The socket path for the current user.
pub fn socket_path() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join("passman").join("unlock.sock"))
}

#[derive(Debug)]
pub enum Error {
    /// No daemon is listening. Not a failure: passman runs fine without one.
    NotListening,
    TooLong(usize),
    Malformed,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotListening => f.write_str("no passman daemon is listening"),
            Error::TooLong(n) => write!(f, "passphrase of {n} bytes exceeds the limit"),
            Error::Malformed => f.write_str("malformed unlock request"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Frame a passphrase for the wire: `u32 big-endian length || bytes`.
pub fn encode_request(passphrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let bytes = passphrase.as_bytes();
    if bytes.len() > MAX_PASSPHRASE_LEN {
        return Err(Error::TooLong(bytes.len()));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + bytes.len()));
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Read one framed passphrase from a stream.
pub fn read_request<R: Read>(reader: &mut R) -> Result<Zeroizing<String>, Error> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_PASSPHRASE_LEN {
        return Err(Error::TooLong(len));
    }

    let mut buf = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut buf)?;
    let s = std::str::from_utf8(&buf).map_err(|_| Error::Malformed)?;
    Ok(Zeroizing::new(s.to_owned()))
}

/// Send a passphrase to the daemon and report whether it unlocked.
///
/// A missing socket is [`Error::NotListening`] rather than a generic I/O
/// error, so callers can treat "no daemon" as the ordinary case it is.
pub fn request_unlock(socket: &std::path::Path, passphrase: &str) -> Result<bool, Error> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            Error::NotListening
        }
        _ => Error::Io(e),
    })?;

    // A wedged daemon must not hang a login.
    let timeout = std::time::Duration::from_secs(10);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    stream.write_all(&encode_request(passphrase)?)?;
    stream.flush()?;

    let mut reply = [0u8; 1];
    stream.read_exact(&mut reply)?;
    Ok(reply[0] == REPLY_UNLOCKED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrips() {
        let encoded = encode_request("correct horse").unwrap();
        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        assert_eq!(&*read_request(&mut cursor).unwrap(), "correct horse");
    }

    #[test]
    fn an_empty_passphrase_still_frames() {
        let encoded = encode_request("").unwrap();
        assert_eq!(&encoded[..], &[0, 0, 0, 0]);
        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        assert_eq!(&**read_request(&mut cursor).unwrap(), "");
    }

    #[test]
    fn oversized_input_is_refused_on_both_sides() {
        let huge = "x".repeat(MAX_PASSPHRASE_LEN + 1);
        assert!(matches!(encode_request(&huge), Err(Error::TooLong(_))));

        // And a client that lies about its length cannot make us allocate.
        let mut lying = Vec::new();
        lying.extend_from_slice(&(u32::MAX).to_be_bytes());
        let mut cursor = std::io::Cursor::new(lying);
        assert!(matches!(read_request(&mut cursor), Err(Error::TooLong(_))));
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_hang() {
        // Claims 16 bytes, supplies 2.
        let mut buf = Vec::new();
        buf.extend_from_slice(&16u32.to_be_bytes());
        buf.extend_from_slice(b"ab");
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_request(&mut cursor).is_err());
    }

    #[test]
    fn non_utf8_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&[0xff, 0xfe]);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(read_request(&mut cursor), Err(Error::Malformed)));
    }

    #[test]
    fn socket_path_is_derived_from_the_uid_not_the_environment() {
        // A PAM module runs as root; the environment belongs to nobody.
        assert_eq!(
            socket_path_for_uid(1000),
            PathBuf::from("/run/user/1000/passman/unlock.sock")
        );
        assert_eq!(
            socket_path_for_uid(0),
            PathBuf::from("/run/user/0/passman/unlock.sock")
        );
    }

    #[test]
    fn connecting_to_a_missing_socket_says_so_clearly() {
        let dir = std::env::temp_dir().join("passman-ipc-absent");
        let _ = std::fs::remove_file(&dir);
        assert!(matches!(
            request_unlock(&dir, "pw"),
            Err(Error::NotListening)
        ));
    }
}
