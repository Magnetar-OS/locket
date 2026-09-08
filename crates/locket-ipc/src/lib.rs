//! The unlock socket: how a passphrase reaches `locketd` from outside.
//!
//! Used by the PAM module at login, and by anything else that legitimately
//! holds the user's passphrase and wants the daemon unlocked. The protocol is
//! deliberately trivial — one length-prefixed passphrase in, one status byte
//! back — because the *interesting* security properties are in where the
//! socket lives, not in what is spoken over it:
//!
//! * The socket sits in `/run/user/<uid>/locket/`, a directory the kernel
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

/// Reply byte: the vault is now unlocked, or the rekey went through.
pub const REPLY_UNLOCKED: u8 = 1;
/// Reply byte: the passphrase was refused.
pub const REPLY_REFUSED: u8 = 0;

/// Marks a request that is not a bare passphrase.
///
/// Set in the top bit of the length word. An older daemon reads the length as
/// an enormous number, exceeds [`MAX_PASSPHRASE_LEN`] and refuses — which is
/// the right answer for a request it does not understand, and much better than
/// a shared magic byte that a passphrase could conceivably start with.
const EXTENDED: u32 = 0x8000_0000;

/// Request opcodes, for the extended form.
const OP_REKEY: u8 = 1;

/// What arrived over the socket.
#[derive(Debug)]
pub enum Request {
    /// Open the vault with this passphrase.
    Unlock(Zeroizing<String>),
    /// The login password changed: re-wrap the vault key under the new one.
    ///
    /// Both halves are needed. The new passphrase is what the vault will use;
    /// the old one is proof that whoever is asking could already open it, so a
    /// daemon that is already unlocked cannot be told to change the passphrase
    /// by someone who never knew it.
    Rekey {
        old: Zeroizing<String>,
        new: Zeroizing<String>,
    },
}

/// Where the unlock socket lives for a given uid.
///
/// Derived from the uid rather than `$XDG_RUNTIME_DIR`, because a PAM module
/// runs as root in a process whose environment belongs to nobody in
/// particular.
pub fn socket_path_for_uid(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/locket/unlock.sock"))
}

/// The socket path for the current user.
pub fn socket_path() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("locket").join("unlock.sock"))
}

#[derive(Debug)]
pub enum Error {
    /// No daemon is listening. Not a failure: locket runs fine without one.
    NotListening,
    TooLong(usize),
    Malformed,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotListening => f.write_str("no locket daemon is listening"),
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

/// Frame a rekey request.
pub fn encode_rekey(old: &str, new: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    for p in [old, new] {
        if p.len() > MAX_PASSPHRASE_LEN {
            return Err(Error::TooLong(p.len()));
        }
    }
    let mut body = Zeroizing::new(Vec::with_capacity(9 + old.len() + new.len()));
    body.push(OP_REKEY);
    for p in [old, new] {
        body.extend_from_slice(&(p.len() as u32).to_be_bytes());
        body.extend_from_slice(p.as_bytes());
    }

    let mut out = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    out.extend_from_slice(&(EXTENDED | body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Read one request from a stream.
pub fn read_request<R: Read>(reader: &mut R) -> Result<Request, Error> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let raw = u32::from_be_bytes(len);

    if raw & EXTENDED == 0 {
        let len = raw as usize;
        if len > MAX_PASSPHRASE_LEN {
            return Err(Error::TooLong(len));
        }
        let mut buf = Zeroizing::new(vec![0u8; len]);
        reader.read_exact(&mut buf)?;
        let s = std::str::from_utf8(&buf).map_err(|_| Error::Malformed)?;
        return Ok(Request::Unlock(Zeroizing::new(s.to_owned())));
    }

    let len = (raw & !EXTENDED) as usize;
    // Two passphrases, two length words and an opcode.
    if len > 2 * MAX_PASSPHRASE_LEN + 9 {
        return Err(Error::TooLong(len));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body)?;

    let mut rest = &body[..];
    let opcode = *rest.first().ok_or(Error::Malformed)?;
    rest = &rest[1..];
    if opcode != OP_REKEY {
        return Err(Error::Malformed);
    }

    let take = |rest: &mut &[u8]| -> Result<Zeroizing<String>, Error> {
        let (len, tail) = rest.split_at_checked(4).ok_or(Error::Malformed)?;
        let len = u32::from_be_bytes(len.try_into().map_err(|_| Error::Malformed)?) as usize;
        if len > MAX_PASSPHRASE_LEN {
            return Err(Error::TooLong(len));
        }
        let (value, tail) = tail.split_at_checked(len).ok_or(Error::Malformed)?;
        *rest = tail;
        let s = std::str::from_utf8(value).map_err(|_| Error::Malformed)?;
        Ok(Zeroizing::new(s.to_owned()))
    };
    let old = take(&mut rest)?;
    let new = take(&mut rest)?;
    if !rest.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(Request::Rekey { old, new })
}

/// Tell the daemon the passphrase changed, and report whether it took.
///
/// Fails the same way [`request_unlock`] does when nothing is listening.
pub fn request_rekey(socket: &std::path::Path, old: &str, new: &str) -> Result<bool, Error> {
    send(socket, &encode_rekey(old, new)?)
}

/// Send a passphrase to the daemon and report whether it unlocked.
///
/// A missing socket is [`Error::NotListening`] rather than a generic I/O
/// error, so callers can treat "no daemon" as the ordinary case it is.
pub fn request_unlock(socket: &std::path::Path, passphrase: &str) -> Result<bool, Error> {
    send(socket, &encode_request(passphrase)?)
}

fn send(socket: &std::path::Path, request: &[u8]) -> Result<bool, Error> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Error::NotListening,
        _ => Error::Io(e),
    })?;

    // A wedged daemon must not hang a login.
    let timeout = std::time::Duration::from_secs(10);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    stream.write_all(request)?;
    stream.flush()?;

    let mut reply = [0u8; 1];
    stream.read_exact(&mut reply)?;
    Ok(reply[0] == REPLY_UNLOCKED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rekey_request_round_trips() {
        let encoded = encode_rekey("old one", "new one").unwrap();
        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        match read_request(&mut cursor).unwrap() {
            Request::Rekey { old, new } => {
                assert_eq!(&*old, "old one");
                assert_eq!(&*new, "new one");
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn an_unlock_and_a_rekey_cannot_be_confused() {
        // A passphrase that happens to start with the rekey opcode byte must
        // still parse as a passphrase: the two are told apart by the length
        // word's top bit, not by anything inside the payload.
        let encoded = encode_request("\u{1}some passphrase").unwrap();
        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        match read_request(&mut cursor).unwrap() {
            Request::Unlock(p) => assert_eq!(&*p, "\u{1}some passphrase"),
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn an_older_daemon_refuses_a_rekey_rather_than_misreading_it() {
        // The extended marker lives in the top bit of the length word, so a
        // daemon that predates rekeying sees an impossible length and bails.
        let encoded = encode_rekey("a", "b").unwrap();
        let len = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert!(
            len > MAX_PASSPHRASE_LEN,
            "an old daemon would have tried to read this as a passphrase"
        );
    }

    #[test]
    fn a_truncated_rekey_is_rejected() {
        let encoded = encode_rekey("old", "new").unwrap();
        for cut in [5, 8, encoded.len() - 1] {
            let mut cursor = std::io::Cursor::new(encoded[..cut].to_vec());
            assert!(
                read_request(&mut cursor).is_err(),
                "accepted a rekey truncated to {cut} bytes"
            );
        }
    }

    #[test]
    fn framing_roundtrips() {
        let encoded = encode_request("correct horse").unwrap();
        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        assert!(
            matches!(read_request(&mut cursor).unwrap(), Request::Unlock(p) if &*p == "correct horse")
        );
    }

    #[test]
    fn an_empty_passphrase_still_frames() {
        let encoded = encode_request("").unwrap();
        assert_eq!(&encoded[..], &[0, 0, 0, 0]);
        let mut cursor = std::io::Cursor::new(encoded.to_vec());
        assert!(matches!(read_request(&mut cursor).unwrap(), Request::Unlock(p) if p.is_empty()));
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
            PathBuf::from("/run/user/1000/locket/unlock.sock")
        );
        assert_eq!(
            socket_path_for_uid(0),
            PathBuf::from("/run/user/0/locket/unlock.sock")
        );
    }

    #[test]
    fn connecting_to_a_missing_socket_says_so_clearly() {
        let dir = std::env::temp_dir().join("locket-ipc-absent");
        let _ = std::fs::remove_file(&dir);
        assert!(matches!(
            request_unlock(&dir, "pw"),
            Err(Error::NotListening)
        ));
    }
}
