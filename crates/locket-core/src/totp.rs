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

    fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// A parsed TOTP configuration.
#[derive(Clone)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// Everything but the seed, which is the whole secret: anyone holding it can
/// generate the codes.
impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field(
                "secret",
                &format_args!("[redacted; {} bytes]", self.secret.len()),
            )
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish()
    }
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
            // `validate` here for the same reason `parse_uri` calls it: an
            // empty string is valid base32 that decodes to no bytes, and
            // without this a bare "" became a Totp with an empty HMAC key
            // that cheerfully produced codes and could not reparse its own
            // `to_uri` output.
            let totp = Self {
                secret: decode_base32(input)?,
                ..Default::default()
            };
            totp.validate()?;
            Ok(totp)
        }
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let parsed = url::Url::parse(uri).map_err(|e| Error::Totp(e.to_string()))?;
        if !parsed
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case("totp"))
        {
            return Err(Error::Totp(
                "only otpauth://totp/ URIs are supported (HOTP is not)".into(),
            ));
        }

        let mut totp = Totp::default();

        // Label is `Issuer:Account`. `Url::path` returns it still
        // percent-encoded, and the separator itself may arrive as `%3A`, so it
        // is decoded before it is split.
        let label = percent_decode(parsed.path().trim_start_matches('/'))?;
        if !label.is_empty() {
            match label.split_once(':') {
                Some((issuer, account)) => {
                    totp.issuer = Some(issuer.trim().to_owned());
                    totp.account = Some(account.trim().to_owned());
                }
                None => totp.account = Some(label),
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
        // In u64: `validate` allows ten digits, and 10^10 does not fit a u32.
        let modulus = 10u64.pow(self.digits);
        Ok(format!(
            "{:0width$}",
            u64::from(binary) % modulus,
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

    /// The `otpauth://totp/` URI for this configuration.
    ///
    /// The inverse of the URI parser: this is what goes into a QR code so an
    /// authenticator app on a phone ends up with the same seed, algorithm and
    /// period rather than the defaults it would assume from a bare secret.
    ///
    /// ```
    /// # use locket_core::Totp;
    /// let totp = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
    /// assert!(totp.to_uri().starts_with("otpauth://totp/"));
    /// ```
    pub fn to_uri(&self) -> String {
        let label = match (&self.issuer, &self.account) {
            (Some(issuer), Some(account)) => format!("{issuer}:{account}"),
            (Some(one), None) | (None, Some(one)) => one.clone(),
            (None, None) => String::new(),
        };

        // `issuer` is repeated as a parameter as well as in the label: the
        // label is what older apps display, the parameter is what current ones
        // read, and the Key Uri Format asks for both.
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair(
            "secret",
            &base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.secret),
        );
        if let Some(issuer) = &self.issuer {
            query.append_pair("issuer", issuer);
        }
        query.append_pair("algorithm", self.algorithm.as_str());
        query.append_pair("digits", &self.digits.to_string());
        query.append_pair("period", &self.period.to_string());

        format!("otpauth://totp/{}?{}", encode_label(&label), query.finish())
    }
}

/// Percent-encode the label segment of an `otpauth://` URI.
///
/// `:` stays literal because it separates issuer from account, and `@` because
/// accounts are usually email addresses and encoding it only makes the URI
/// harder to read. Everything else outside the unreserved set is escaped —
/// including `/`, which would otherwise split the label into two path
/// segments.
fn encode_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for byte in label.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Undo the percent-encoding [`url::Url::path`] leaves in place.
///
/// A `%` that is not followed by two hex digits stays as it is, which is how
/// browsers read it too; the decoded bytes must be UTF-8 like the rest of the
/// URI.
fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = s.get(i + 1..i + 3)
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::Totp("the label is not valid UTF-8".into()))
}

/// Decode an RFC 4648 base32 secret, tolerating lowercase, spaces and missing
/// padding — all of which appear on real enrolment pages.
fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let cleaned = zeroize::Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .to_ascii_uppercase(),
    );
    // Padding carries no bits, and the unpadded alphabet rejects `=` outright,
    // so a correctly padded secret is decoded as if it had none.
    let cleaned = cleaned.trim_end_matches('=');
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, cleaned)
        .ok_or_else(|| Error::Totp("secret is not valid base32".into()))
}

// SHA-1 appears here only because RFC 6238's default — and therefore
// essentially every real TOTP enrolment — specifies it. It is used for
// nothing else in locket.

#[cfg(test)]
mod tests {
    use super::*;

    // Found by the `totp` fuzz target: the empty input decodes as valid
    // base32 to zero bytes, so `parse` accepted it while `to_uri`'s output
    // was correctly rejected on the way back in.
    #[test]
    fn an_empty_seed_is_rejected_rather_than_parsed_into_an_empty_key() {
        for input in ["", " ", "\n", "  \t "] {
            assert!(
                Totp::parse(input).is_err(),
                "empty seed {input:?} parsed into a Totp with no key"
            );
        }
    }

    // The seed is the whole secret: anyone holding it generates the codes.
    // A derived `Debug` printed it byte for byte into whatever logged it.
    #[test]
    fn debug_output_does_not_contain_the_seed() {
        let totp = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let shown = format!("{totp:?}");
        assert!(!shown.contains("72, 101, 108"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn a_parsed_seed_reparses_from_its_own_uri() {
        let totp = Totp::parse("JBSWY3DPEHPK3PXP").expect("valid base32 seed");
        let uri = totp.to_uri();
        let back = Totp::parse(&uri).expect("a seed's own URI must reparse");
        assert_eq!(totp.secret, back.secret);
        assert_eq!(totp.digits, back.digits);
        assert_eq!(totp.period, back.period);
    }

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

    // RFC 4226 Appendix D, count 3: the truncated value is 1726969429. Ten
    // digits pass `validate`, and 10^10 does not fit the u32 the modulus was
    // computed in — debug builds panicked, release builds wrapped it.
    #[test]
    fn ten_digit_codes_do_not_overflow() {
        let t = Totp {
            digits: 10,
            ..rfc_totp(Algorithm::Sha1, RFC_SECRET)
        };
        assert_eq!(t.code_at(90).unwrap(), "1726969429");
        assert_eq!(t.code_at(59).unwrap(), "1094287082");
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

    // RFC 4648 pads to a multiple of eight characters, and some sites print
    // the padding. "Missing padding" being tolerated does not make present
    // padding an error.
    #[test]
    fn a_padded_secret_decodes_like_its_unpadded_form() {
        assert_eq!(Totp::parse("JBSWY3DPEE======").unwrap().secret, b"Hello!");
        assert_eq!(Totp::parse("JBSWY3DPEE").unwrap().secret, b"Hello!");
        let uri = "otpauth://totp/x?secret=JBSWY3DPEE%3D%3D%3D%3D%3D%3D";
        assert_eq!(Totp::parse(uri).unwrap().secret, b"Hello!");
    }

    #[test]
    fn rejects_hotp_and_bad_input() {
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=nope").is_err());
        assert!(Totp::parse("!!!not base32!!!").is_err());
    }

    #[test]
    fn uri_round_trips_through_the_parser() {
        let original = Totp {
            secret: RFC_SECRET.to_vec(),
            algorithm: Algorithm::Sha512,
            digits: 8,
            period: 60,
            issuer: Some("ACME Co".into()),
            account: Some("alice@example.com".into()),
        };
        let parsed = Totp::parse(&original.to_uri()).unwrap();
        assert_eq!(parsed.secret, original.secret);
        assert_eq!(parsed.algorithm, original.algorithm);
        assert_eq!(parsed.digits, original.digits);
        assert_eq!(parsed.period, original.period);
        assert_eq!(parsed.issuer, original.issuer);
        assert_eq!(parsed.account, original.account);
    }

    #[test]
    fn a_slash_in_the_label_does_not_become_a_path_segment() {
        let totp = Totp {
            issuer: Some("ACME/EU".into()),
            account: Some("alice".into()),
            ..Totp::parse("JBSWY3DPEHPK3PXP").unwrap()
        };
        assert!(totp.to_uri().contains("ACME%2FEU:alice"));
        assert_eq!(
            Totp::parse(&totp.to_uri()).unwrap().issuer.as_deref(),
            Some("ACME/EU")
        );
    }

    // `Url::path` hands the path back still percent-encoded, so a label with
    // a space or an escaped `@` has to be decoded here — and with no
    // `issuer` parameter to fall back on, the label is all there is.
    #[test]
    fn a_label_only_uri_is_percent_decoded() {
        let t = Totp::parse("otpauth://totp/My%20Bank:ada%40example.com?secret=JBSWY3DPEHPK3PXP")
            .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("My Bank"));
        assert_eq!(t.account.as_deref(), Some("ada@example.com"));

        // The separator may itself arrive escaped, and a space after it is
        // decoration, not part of the account.
        let t = Totp::parse("otpauth://totp/ACME%3A%20alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME"));
        assert_eq!(t.account.as_deref(), Some("alice"));

        // And what we print for a phone does not get escaped twice.
        let uri = Totp::parse("otpauth://totp/My%20Bank:ada%40example.com?secret=JBSWY3DPEHPK3PXP")
            .unwrap()
            .to_uri();
        assert!(!uri.contains("%25"), "{uri}");
    }

    #[test]
    fn a_label_with_spaces_and_percents_round_trips() {
        let original = Totp {
            issuer: Some("100% Co".into()),
            account: Some("Alice Smith".into()),
            ..Totp::parse("JBSWY3DPEHPK3PXP").unwrap()
        };
        let parsed = Totp::parse(&original.to_uri()).unwrap();
        assert_eq!(parsed.issuer, original.issuer);
        assert_eq!(parsed.account, original.account);

        // Without the `issuer` parameter to paper over the label.
        let label_only = Totp {
            issuer: None,
            ..original.clone()
        };
        let parsed = Totp::parse(&label_only.to_uri()).unwrap();
        assert_eq!(parsed.account.as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn a_bare_secret_becomes_a_uri_an_app_can_read() {
        let totp = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        let uri = totp.to_uri();
        // No label to speak of, but the parameters must still be there.
        assert!(uri.starts_with("otpauth://totp/?"), "{uri}");
        assert_eq!(Totp::parse(&uri).unwrap().secret, totp.secret);
    }

    #[test]
    fn code_is_stable_within_a_period() {
        let t = rfc_totp(Algorithm::Sha1, RFC_SECRET);
        assert_eq!(t.code_at(30).unwrap(), t.code_at(59).unwrap());
        assert_ne!(t.code_at(59).unwrap(), t.code_at(60).unwrap());
    }
}
