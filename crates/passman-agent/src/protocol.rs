//! Agent message numbers and framing.

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

// Client -> agent.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

// Agent -> client.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

// Signature request flags.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    RequestIdentities,
    Sign {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Recognised but refused; see the crate docs for why.
    AddIdentity,
    RemoveIdentity {
        key_blob: Vec<u8>,
    },
    RemoveAllIdentities,
    Lock,
    Unlock,
    Extension {
        name: String,
    },
    /// Any message number we do not implement.
    Unknown(u8),
}

impl Request {
    /// Parse one message body (the outer length prefix already stripped).
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let kind = r.read_u8()?;
        Ok(match kind {
            SSH_AGENTC_REQUEST_IDENTITIES => Request::RequestIdentities,
            SSH_AGENTC_SIGN_REQUEST => {
                let key_blob = r.read_string()?.to_vec();
                let data = r.read_string()?.to_vec();
                // Older clients omit the flags word entirely.
                let flags = if r.remaining() >= 4 { r.read_u32()? } else { 0 };
                Request::Sign {
                    key_blob,
                    data,
                    flags,
                }
            }
            SSH_AGENTC_ADD_IDENTITY => Request::AddIdentity,
            SSH_AGENTC_REMOVE_IDENTITY => Request::RemoveIdentity {
                key_blob: r.read_string()?.to_vec(),
            },
            SSH_AGENTC_REMOVE_ALL_IDENTITIES => Request::RemoveAllIdentities,
            SSH_AGENTC_LOCK => Request::Lock,
            SSH_AGENTC_UNLOCK => Request::Unlock,
            SSH_AGENTC_EXTENSION => Request::Extension {
                name: r.read_utf8()?,
            },
            other => Request::Unknown(other),
        })
    }
}

/// A single agent failure message, framed and ready to write.
pub fn failure() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(SSH_AGENT_FAILURE);
    w.into_framed()
}

pub fn success() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(SSH_AGENT_SUCCESS);
    w.into_framed()
}

pub fn extension_failure() -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(SSH_AGENT_EXTENSION_FAILURE);
    w.into_framed()
}

/// Strip the outer length prefix from a buffer, if a whole message is present.
///
/// Returns the body and the number of bytes consumed, or `None` when more
/// input is needed — clients may split a message across reads.
pub fn take_message(buf: &[u8]) -> Result<Option<(&[u8], usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 {
        return Err(Error::Malformed("zero-length agent message"));
    }
    if len > crate::MAX_MESSAGE_LEN {
        return Err(Error::TooLarge(len));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    Ok(Some((&buf[4..4 + len], 4 + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_identities() {
        assert_eq!(
            Request::parse(&[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap(),
            Request::RequestIdentities
        );
    }

    #[test]
    fn parses_sign_request_with_flags() {
        let mut w = Writer::new();
        w.write_u8(SSH_AGENTC_SIGN_REQUEST)
            .write_string(b"key-blob")
            .write_string(b"data-to-sign")
            .write_u32(SSH_AGENT_RSA_SHA2_512);
        let body = w.into_bytes();

        assert_eq!(
            Request::parse(&body).unwrap(),
            Request::Sign {
                key_blob: b"key-blob".to_vec(),
                data: b"data-to-sign".to_vec(),
                flags: SSH_AGENT_RSA_SHA2_512,
            }
        );
    }

    #[test]
    fn sign_request_without_flags_defaults_to_zero() {
        let mut w = Writer::new();
        w.write_u8(SSH_AGENTC_SIGN_REQUEST)
            .write_string(b"k")
            .write_string(b"d");
        assert_eq!(
            Request::parse(&w.into_bytes()).unwrap(),
            Request::Sign {
                key_blob: b"k".to_vec(),
                data: b"d".to_vec(),
                flags: 0,
            }
        );
    }

    #[test]
    fn unknown_message_numbers_are_reported_not_fatal() {
        assert_eq!(Request::parse(&[99]).unwrap(), Request::Unknown(99));
    }

    #[test]
    fn empty_body_is_an_error() {
        assert!(Request::parse(&[]).is_err());
    }

    #[test]
    fn take_message_waits_for_a_whole_message() {
        // Length says 4, only 2 bytes of body present.
        assert!(take_message(&[0, 0, 0, 4, 1, 2]).unwrap().is_none());
        // Not even a full length prefix.
        assert!(take_message(&[0, 0]).unwrap().is_none());

        let (body, used) = take_message(&[0, 0, 0, 2, 11, 22]).unwrap().unwrap();
        assert_eq!(body, &[11, 22]);
        assert_eq!(used, 6);
    }

    #[test]
    fn take_message_rejects_oversized_and_empty_frames() {
        let huge = (crate::MAX_MESSAGE_LEN as u32 + 1).to_be_bytes();
        assert!(matches!(take_message(&huge), Err(Error::TooLarge(_))));
        assert!(matches!(
            take_message(&[0, 0, 0, 0]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn take_message_handles_two_messages_in_one_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]);
        buf.extend_from_slice(&[0, 0, 0, 1, SSH_AGENTC_REMOVE_ALL_IDENTITIES]);

        let (first, used) = take_message(&buf).unwrap().unwrap();
        assert_eq!(first, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        let (second, _) = take_message(&buf[used..]).unwrap().unwrap();
        assert_eq!(second, &[SSH_AGENTC_REMOVE_ALL_IDENTITIES]);
    }

    #[test]
    fn failure_and_success_are_framed() {
        assert_eq!(failure(), vec![0, 0, 0, 1, SSH_AGENT_FAILURE]);
        assert_eq!(success(), vec![0, 0, 0, 1, SSH_AGENT_SUCCESS]);
    }
}
