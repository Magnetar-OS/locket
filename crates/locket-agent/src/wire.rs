//! SSH wire encoding (RFC 4251 §5).
//!
//! Everything in the agent protocol is built from these primitives: `uint32`
//! big-endian, `string` as a length-prefixed byte run, `byte`. Getting the
//! bounds checks right here is what keeps a malformed client from panicking
//! the daemon, so each reader validates before it slices.

use crate::error::{Error, Result};

/// Reads SSH-encoded values from a buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(Error::Truncated {
                wanted: 1,
                have: self.remaining(),
            });
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(Error::Truncated {
                wanted: 4,
                have: self.remaining(),
            });
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// A length-prefixed byte string.
    pub fn read_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if self.remaining() < len {
            return Err(Error::Truncated {
                wanted: len,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    pub fn read_utf8(&mut self) -> Result<String> {
        let bytes = self.read_string()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Malformed("string is not UTF-8"))
    }
}

/// Builds SSH-encoded values.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn write_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn write_string(&mut self, v: &[u8]) -> &mut Self {
        self.write_u32(v.len() as u32);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Wrap the accumulated body in the outer `uint32` length the agent
    /// transport puts in front of every message.
    pub fn into_framed(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len() + 4);
        out.extend_from_slice(&(self.buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.buf);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        let mut w = Writer::new();
        w.write_u8(11)
            .write_u32(0xDEAD_BEEF)
            .write_string(b"ssh-ed25519");
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 11);
        assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
        assert!(r.is_empty());
    }

    #[test]
    fn framing_prefixes_the_length() {
        let mut w = Writer::new();
        w.write_u8(6);
        let framed = w.into_framed();
        assert_eq!(framed, vec![0, 0, 0, 1, 6]);
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        // Claims a 16-byte string but supplies 2.
        let bytes = [0u8, 0, 0, 16, 0xAA, 0xBB];
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.read_string(), Err(Error::Truncated { .. })));

        let mut r = Reader::new(&[0u8, 0]);
        assert!(matches!(r.read_u32(), Err(Error::Truncated { .. })));

        let mut r = Reader::new(&[]);
        assert!(matches!(r.read_u8(), Err(Error::Truncated { .. })));
    }

    #[test]
    fn absurd_length_prefix_does_not_allocate() {
        // u32::MAX length against a 4-byte buffer must fail immediately.
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.read_string(), Err(Error::Truncated { .. })));
    }

    #[test]
    fn non_utf8_string_is_rejected() {
        let mut w = Writer::new();
        w.write_string(&[0xFF, 0xFE]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.read_utf8(), Err(Error::Malformed(_))));
    }
}
