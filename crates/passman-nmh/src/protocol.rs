//! Chrome/Firefox native messaging framing and message types.
//!
//! The transport is trivial — a 32-bit **native-endian** length followed by
//! UTF-8 JSON — and both browsers cap a message at 1 MiB. The interesting part
//! is the message design, which is shaped by one assumption:
//!
//! **A browser extension is not trusted.** It runs alongside every page you
//! visit and is one supply-chain compromise away from hostile. So the host
//! never exposes the vault wholesale:
//!
//! * `Search` returns *metadata only* — labels and usernames, never a
//!   password — and only for entries matching the origin the caller names.
//! * `Get` returns exactly one secret, for one id the extension already had to
//!   learn from a matching `Search`.
//! * Nothing unlocks the vault. A locked vault answers `Locked` and stops;
//!   the passphrase is typed into passman's own window, never a web page.

use serde::{Deserialize, Serialize};

/// Both browsers refuse messages larger than this.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("message of {0} bytes exceeds the 1 MiB native messaging limit")]
    TooLarge(usize),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// What the extension asks for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Is a vault reachable, and is it unlocked?
    Status,
    /// Credentials whose stored URL matches this origin. Metadata only.
    Search { url: String },
    /// One secret, by an id previously returned from `Search`.
    Get { id: String },
}

/// What the host answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status { unlocked: bool, daemon: bool },
    /// Deliberately carries no passwords.
    Matches { items: Vec<Match> },
    Secret { id: String, password: String },
    /// The vault is locked; the user must unlock in passman itself.
    Locked,
    Error { message: String },
}

/// One candidate credential, without its secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Match {
    pub id: String,
    pub label: String,
    pub username: String,
    pub url: String,
}

/// Read one framed message from `reader`.
///
/// Returns `Ok(None)` at clean EOF, which is how the browser says "the
/// extension went away" and is not an error.
pub fn read_message<R: std::io::Read>(reader: &mut R) -> Result<Option<Request>, Error> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    }

    // Native endianness, per the native messaging specification — not network
    // byte order, which is the easy mistake here.
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(Error::TooLarge(len));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| Error::Malformed(e.to_string()))
}

/// Frame and write one response.
pub fn write_message<W: std::io::Write>(writer: &mut W, response: &Response) -> Result<(), Error> {
    let body = serde_json::to_vec(response).map_err(|e| Error::Malformed(e.to_string()))?;
    if body.len() > MAX_MESSAGE_LEN {
        return Err(Error::TooLarge(body.len()));
    }
    writer.write_all(&(body.len() as u32).to_ne_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

/// Reduce a URL to the host used for matching.
///
/// `www.` is dropped so a credential saved on `www.example.com` still matches
/// `example.com`; anything unparseable falls back to the raw string so a bare
/// hostname works too.
pub fn origin_of(url: &str) -> String {
    let parsed = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    let host = parsed.unwrap_or_else(|| url.trim().to_owned());
    host.strip_prefix("www.").unwrap_or(&host).to_lowercase()
}

/// Whether a stored credential belongs to the origin being asked about.
///
/// Matching is on registrable-ish suffix boundaries: `mail.example.com`
/// matches a credential for `example.com`, but `notexample.com` must not, and
/// `example.com.evil.test` must not either. Getting this wrong is how a
/// password manager hands credentials to a lookalike domain.
pub fn origin_matches(stored: &str, requested: &str) -> bool {
    let stored = origin_of(stored);
    let requested = origin_of(requested);
    if stored.is_empty() || requested.is_empty() {
        return false;
    }
    if stored == requested {
        return true;
    }
    // Only accept the request being a subdomain of what was stored.
    requested.ends_with(&format!(".{stored}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrips() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Response::Status { unlocked: true, daemon: true }).unwrap();

        // The length prefix is native-endian, not big-endian.
        let len = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len() - 4);

        let request = serde_json::to_vec(&Request::Status).unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(request.len() as u32).to_ne_bytes());
        framed.extend_from_slice(&request);
        let mut cursor = std::io::Cursor::new(framed);
        assert_eq!(read_message(&mut cursor).unwrap(), Some(Request::Status));
    }

    #[test]
    fn clean_eof_is_not_an_error() {
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_message(&mut empty).unwrap(), None);
    }

    #[test]
    fn an_oversized_length_is_refused_before_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_LEN as u32 + 1).to_ne_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(read_message(&mut cursor), Err(Error::TooLarge(_))));
    }

    #[test]
    fn garbage_json_is_reported_not_panicked_on() {
        let body = b"{not json";
        let mut buf = Vec::new();
        buf.extend_from_slice(&(body.len() as u32).to_ne_bytes());
        buf.extend_from_slice(body);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(read_message(&mut cursor), Err(Error::Malformed(_))));
    }

    #[test]
    fn requests_parse_from_the_wire_shape_the_extension_sends() {
        let search: Request = serde_json::from_str(r#"{"type":"search","url":"https://github.com/login"}"#).unwrap();
        assert_eq!(search, Request::Search { url: "https://github.com/login".into() });
        let get: Request = serde_json::from_str(r#"{"type":"get","id":"abc"}"#).unwrap();
        assert_eq!(get, Request::Get { id: "abc".into() });
    }

    #[test]
    fn origin_extraction_handles_the_shapes_pages_send() {
        assert_eq!(origin_of("https://www.example.com/login?next=1"), "example.com");
        assert_eq!(origin_of("http://Example.COM:8443/"), "example.com");
        assert_eq!(origin_of("example.com"), "example.com");
        assert_eq!(origin_of(""), "");
    }

    #[test]
    fn subdomains_match_but_lookalikes_do_not() {
        assert!(origin_matches("example.com", "example.com"));
        assert!(origin_matches("https://example.com", "https://mail.example.com/x"));

        // The attacks this guards against.
        assert!(!origin_matches("example.com", "notexample.com"));
        assert!(!origin_matches("example.com", "example.com.evil.test"));
        assert!(!origin_matches("example.com", "evil.test"));
        // And the reverse direction: a credential for a subdomain must not
        // leak to the parent.
        assert!(!origin_matches("mail.example.com", "example.com"));
        assert!(!origin_matches("", "example.com"));
    }

    #[test]
    fn a_match_carries_no_password() {
        // Compile-time-ish guarantee: serialising a Match must not produce a
        // password field, whatever else changes about the struct.
        let json = serde_json::to_string(&Match {
            id: "1".into(),
            label: "GitHub".into(),
            username: "ada".into(),
            url: "https://github.com".into(),
        })
        .unwrap();
        assert!(!json.contains("password"), "Match leaked a password field");
    }
}
