//! Have I Been Pwned range queries, the k-anonymity way.
//!
//! This is the only crate in the workspace that talks to the network, and it
//! exists so that fact stays legible: locket-core does no I/O, and anything
//! wanting a breach check has to reach for this crate on purpose, behind an
//! explicit user opt-in.
//!
//! What actually leaves the machine: the first five hex characters of the
//! SHA-1 of a password — 20 bits, shared by every one of the ~16 million
//! passwords per bucket — never the password, never its full hash. The
//! server returns the whole bucket and the matching is done here. The
//! `Add-Padding` header is sent so even the response length does not say
//! whether anything matched.
//!
//! SHA-1 is fine here: it is the dataset's index, not a security boundary.

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

pub const API: &str = "https://api.pwnedpasswords.com/range";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the range request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("the range response was not in the expected format")]
    Malformed,
}

/// A client with the settings the API asks for. Reuse it across checks —
/// each new client is a new connection pool and a new TLS session.
pub fn client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("locket/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .build()?)
}

/// How many times this exact password appears in known breaches; 0 is good
/// news. One HTTPS round trip per call.
pub async fn pwned_count(client: &reqwest::Client, password: &str) -> Result<u64, Error> {
    let (prefix, suffix) = hash_split(password);
    let body = client
        .get(format!("{API}/{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    match_suffix(&body, &suffix).ok_or(Error::Malformed)
}

/// SHA-1 the password and split the uppercase hex at the k-anonymity
/// boundary: five characters that leave, thirty-five that never do.
fn hash_split(password: &str) -> (String, Zeroizing<String>) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = Zeroizing::new(
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>(),
    );
    let prefix = hex[..5].to_owned();
    let suffix = Zeroizing::new(hex[5..].to_owned());
    (prefix, suffix)
}

/// Scan a range response (`SUFFIX:COUNT` per line) for our suffix.
///
/// `Some(0)` when the bucket parses but holds no match — absence is an
/// answer, not an error. `None` only when the body is not a range response
/// at all. Padding entries arrive with count 0 and fall out naturally.
fn match_suffix(body: &str, suffix: &str) -> Option<u64> {
    let mut saw_a_line = false;
    for line in body.lines() {
        let (candidate, count) = line.trim().split_once(':')?;
        saw_a_line = true;
        if candidate.eq_ignore_ascii_case(suffix) {
            return count.trim().parse().ok();
        }
    }
    saw_a_line.then_some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published test vector: SHA-1("password") =
    /// 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
    #[test]
    fn the_split_matches_the_known_vector() {
        let (prefix, suffix) = hash_split("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(&*suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn a_bucket_with_the_suffix_returns_its_count() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:10437277\n\
                    2D6980B9098804E7A83DC5831BFBAF3927F:0";
        assert_eq!(
            match_suffix(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            Some(10_437_277)
        );
    }

    #[test]
    fn a_bucket_without_the_suffix_is_a_clean_zero_not_an_error() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1";
        assert_eq!(
            match_suffix(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            Some(0)
        );
    }

    #[test]
    fn padding_entries_with_zero_count_do_not_read_as_breached() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0";
        assert_eq!(
            match_suffix(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            Some(0)
        );
    }

    #[test]
    fn suffix_matching_is_case_insensitive() {
        let body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:5";
        assert_eq!(
            match_suffix(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            Some(5)
        );
    }

    #[test]
    fn garbage_is_malformed_not_zero() {
        assert_eq!(match_suffix("<html>rate limited</html>", "X"), None);
        assert_eq!(match_suffix("", "X"), None);
    }
}
