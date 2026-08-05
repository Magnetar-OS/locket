//! RFC 6238 TOTP, and the `otpauth://` URI format authenticator apps use.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// A parsed TOTP configuration.
#[derive(Debug, Clone)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        }
    }
}

impl Totp {
    /// Parse either a bare base32 secret or a full `otpauth://totp/...` URI.
    ///
    /// Bare secrets are accepted because that is what most websites actually
    /// print next to the QR code.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.starts_with("otpauth://") {
            Self::parse_uri(input)
        } else {
            Ok(Self {
                secret: decode_base32(input)?,
                ..Default::default()
            })
        }
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let parsed = url::Url::parse(uri).map_err(|e| Error::Totp(e.to_string()))?;
        if !parsed.host_str().is_some_and(|h| h.eq_ignore_ascii_case("totp")) {
            return Err(Error::Totp(
                "only otpauth://totp/ URIs are supported (HOTP is not)".into(),
            ));
        }

        let mut totp = Totp::default();

        // Label is `Issuer:Account`, percent-decoded by `Url` already.
        let label = parsed.path().trim_start_matches('/');
        if !label.is_empty() {
            match label.split_once(':') {
                Some((issuer, account)) => {
                    totp.issuer = Some(issuer.trim().to_owned());
                    totp.account = Some(account.trim().to_owned());
                }
                None => totp.account = Some(label.to_owned()),
            }
        }

        let mut have_secret = false;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "secret" => {
                    totp.secret = decode_base32(&v)?;
                    have_secret = true;
                }
                // An explicit issuer parameter wins over the label prefix.
                "issuer" => totp.issuer = Some(v.into_owned()),
                "algorithm" => {
                    totp.algorithm = Algorithm::parse(&v)
                        .ok_or_else(|| Error::Totp(format!("unknown algorithm `{v}`")))?;
                }
                "digits" => {
                    totp.digits = v
                        .parse()
                        .map_err(|_| Error::Totp(format!("bad digits `{v}`")))?;
                }
                "period" => {
                    totp.period = v
                        .parse()
                        .map_err(|_| Error::Totp(format!("bad period `{v}`")))?;
                }
                _ => {}
            }
        }

        if !have_secret {
            return Err(Error::Totp("URI has no `secret` parameter".into()));
        }
        totp.validate()?;
        Ok(totp)
    }

    fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(Error::Totp("secret is empty".into()));
        }
        if !(6..=10).contains(&self.digits) {
            return Err(Error::Totp(format!(
                "digits must be between 6 and 10, got {}",
                self.digits
            )));
        }
        if self.period == 0 {
            return Err(Error::Totp("period must be greater than zero".into()));
        }
        Ok(())
    }

    /// The code for a given Unix timestamp.
    pub fn code_at(&self, unix_time: u64) -> Result<String> {
        self.validate()?;
        let counter = unix_time / self.period;
        let msg = counter.to_be_bytes();

        let digest: Vec<u8> = match self.algorithm {
            Algorithm::Sha1 => {
                let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&self.secret)
                    .map_err(|e| Error::Totp(e.to_string()))?;
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
                    .map_err(|e| Error::Totp(e.to_string()))?;
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&self.secret)
                    .map_err(|e| Error::Totp(e.to_string()))?;
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // RFC 4226 dynamic truncation.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let modulus = 10u32.pow(self.digits);
        Ok(format!(
            "{:0width$}",
            binary % modulus,
            width = self.digits as usize
        ))
    }

    /// The code for right now.
    pub fn code(&self) -> Result<String> {
        self.code_at(crate::model::now())
    }

    /// Seconds until the current code expires — drives the countdown ring.
    pub fn seconds_remaining(&self) -> u64 {
        let now = crate::model::now();
        self.period - (now % self.period)
    }
}

/// Decode an RFC 4648 base32 secret, tolerating lowercase, spaces and missing
/// padding — all of which appear on real enrolment pages.
fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .ok_or_else(|| Error::Totp("secret is not valid base32".into()))
}

// SHA-1 appears here only because RFC 6238's default — and therefore
// essentially every real TOTP enrolment — specifies it. It is used for
// nothing else in passman.

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors. Secret is "12345678901234567890".
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn rfc_totp(algorithm: Algorithm, secret: &[u8]) -> Totp {
        Totp {
            secret: secret.to_vec(),
            algorithm,
            digits: 8,
            period: 30,
            ..Default::default()
        }
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let t = rfc_totp(Algorithm::Sha1, RFC_SECRET);
        assert_eq!(t.code_at(59).unwrap(), "94287082");
        assert_eq!(t.code_at(1111111109).unwrap(), "07081804");
        assert_eq!(t.code_at(1111111111).unwrap(), "14050471");
        assert_eq!(t.code_at(1234567890).unwrap(), "89005924");
        assert_eq!(t.code_at(2000000000).unwrap(), "69279037");
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let t = rfc_totp(Algorithm::Sha256, b"12345678901234567890123456789012");
        assert_eq!(t.code_at(59).unwrap(), "46119246");
        assert_eq!(t.code_at(1111111109).unwrap(), "68084774");
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        let t = rfc_totp(
            Algorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234",
        );
        assert_eq!(t.code_at(59).unwrap(), "90693936");
        assert_eq!(t.code_at(1111111109).unwrap(), "25091201");
    }

    #[test]
    fn parses_full_otpauth_uri() {
        let t = Totp::parse(
            "otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("alice@example.com"));
        assert_eq!(t.algorithm, Algorithm::Sha256);
        assert_eq!(t.digits, 8);
        assert_eq!(t.period, 60);
    }

    #[test]
    fn parses_bare_base32_with_human_formatting() {
        // Lowercase, spaced and unpadded, the way sites print it.
        let t = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.code().unwrap().len(), 6);
    }

    #[test]
    fn rejects_hotp_and_bad_input() {
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=nope").is_err());
        assert!(Totp::parse("!!!not base32!!!").is_err());
    }

    #[test]
    fn code_is_stable_within_a_period() {
        let t = rfc_totp(Algorithm::Sha1, RFC_SECRET);
        assert_eq!(t.code_at(30).unwrap(), t.code_at(59).unwrap());
        assert_ne!(t.code_at(59).unwrap(), t.code_at(60).unwrap());
    }
}
