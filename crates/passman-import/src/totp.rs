//! Import TOTP seeds from authenticator-app exports.
//!
//! Only formats that actually contain the seed are handled. That rules out
//! most authenticators — Google Authenticator and Authy deliberately do not
//! export in a readable form, and the "migration" QR codes are a protobuf
//! blob that changes shape between versions. What is supported is what people
//! can genuinely get out:
//!
//! * a plain list of `otpauth://` URIs, which is what almost everything can
//!   be coaxed into producing;
//! * **Aegis** plain-text JSON exports;
//! * **andOTP** plain-text JSON exports.
//!
//! Encrypted Aegis and andOTP backups are refused rather than half-read. They
//! use their own password-based KDFs, and asking for that password to decrypt
//! a backup is a materially different promise from reading a file — worth
//! doing deliberately, not as a side effect of pointing at a directory.
//!
//! Every seed is validated by parsing it as a real TOTP before it is stored,
//! so an import that reports success cannot have written a code that will
//! never generate.

use std::path::Path;

use passman_core::{
    Vault,
    model::{Field, FieldKind, Item, ItemKind, field_names},
    totp::Totp,
};

use crate::{Error, ImportSummary, Result};

/// One seed, however it was written down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The service, e.g. `GitHub`.
    pub issuer: Option<String>,
    /// The account within it, e.g. `ada@example.com`.
    pub account: String,
    /// The canonical `otpauth://` URI, which is what actually gets stored.
    pub uri: String,
}

impl Entry {
    fn label(&self) -> String {
        match &self.issuer {
            Some(issuer) if !issuer.is_empty() => format!("{issuer} ({})", self.account),
            _ => self.account.clone(),
        }
    }
}

/// Build an `otpauth://` URI from parts, percent-encoding the label.
fn build_uri(
    issuer: Option<&str>,
    account: &str,
    secret: &str,
    algorithm: Option<&str>,
    digits: Option<u32>,
    period: Option<u64>,
) -> String {
    let label = match issuer {
        Some(i) if !i.is_empty() => format!("{}:{}", encode(i), encode(account)),
        _ => encode(account),
    };
    let mut uri = format!("otpauth://totp/{label}?secret={secret}");
    if let Some(i) = issuer.filter(|i| !i.is_empty()) {
        uri.push_str(&format!("&issuer={}", encode(i)));
    }
    if let Some(a) = algorithm.filter(|a| !a.is_empty()) {
        uri.push_str(&format!("&algorithm={}", a.to_ascii_uppercase()));
    }
    if let Some(d) = digits {
        uri.push_str(&format!("&digits={d}"));
    }
    if let Some(p) = period {
        uri.push_str(&format!("&period={p}"));
    }
    uri
}

/// Percent-encode the characters that would otherwise break the URI.
///
/// Not a general encoder: labels are the only user-controlled part here, and
/// the set that matters is the delimiters plus space.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            ':' => out.push_str("%3A"),
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '%' => out.push_str("%25"),
            _ => out.push(c),
        }
    }
    out
}

/// Pull the issuer and account out of an `otpauth://` URI for labelling.
fn describe(uri: &str) -> (Option<String>, String) {
    let after_scheme = uri
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(uri);
    let path = after_scheme
        .split_once('/')
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let (label, query) = path.split_once('?').unwrap_or((path, ""));
    let label = decode(label);

    let issuer_param = query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.eq_ignore_ascii_case("issuer")).then(|| decode(v))
    });

    match label.split_once(':') {
        // The label's own issuer prefix wins only if the query has none.
        Some((issuer, account)) => (
            issuer_param.or_else(|| Some(issuer.trim().to_owned())),
            account.trim().to_owned(),
        ),
        None => (issuer_param, label),
    }
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Formats
// ---------------------------------------------------------------------------

/// A file of `otpauth://` URIs, one per line. Blank lines and `#` comments
/// are ignored, so an exported list with notes in it still works.
pub fn parse_uri_list(text: &str) -> Vec<Entry> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("otpauth://"))
        .filter(|l| Totp::parse(l).is_ok())
        .map(|uri| {
            let (issuer, account) = describe(uri);
            Entry {
                issuer,
                account,
                uri: uri.to_owned(),
            }
        })
        .collect()
}

/// Aegis plain-text JSON export: `{"db":{"entries":[...]}}`.
///
/// An encrypted export has a string `db` rather than an object, which is how
/// this tells the two apart without guessing from the file name.
pub fn parse_aegis(text: &str) -> Result<Vec<Entry>> {
    let json: serde_json::Value =
        serde_json::from_str(text).map_err(|e| Error::Database(e.to_string()))?;

    let db = json.get("db").ok_or_else(|| {
        Error::Database("not an Aegis export: no `db`".to_owned())
    })?;
    if db.is_string() {
        return Err(Error::Decrypt(
            "this Aegis export is encrypted; export again without a password".to_owned(),
        ));
    }
    let entries = db
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| Error::Database("no `db.entries` array".to_owned()))?;

    Ok(entries
        .iter()
        .filter(|e| {
            // HOTP and Steam entries use the same file but are not TOTP.
            e.get("type")
                .and_then(|t| t.as_str())
                .is_none_or(|t| t.eq_ignore_ascii_case("totp"))
        })
        .filter_map(|e| {
            let info = e.get("info")?;
            let secret = info.get("secret")?.as_str()?;
            let account = e.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let issuer = e.get("issuer").and_then(|v| v.as_str());
            let uri = build_uri(
                issuer,
                account,
                secret,
                info.get("algo").and_then(|v| v.as_str()),
                info.get("digits").and_then(|v| v.as_u64()).map(|d| d as u32),
                info.get("period").and_then(|v| v.as_u64()),
            );
            Totp::parse(&uri).ok()?;
            Some(Entry {
                issuer: issuer.map(str::to_owned),
                account: account.to_owned(),
                uri,
            })
        })
        .collect())
}

/// andOTP plain-text JSON export: a bare array of entries.
pub fn parse_andotp(text: &str) -> Result<Vec<Entry>> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(text).map_err(|e| Error::Database(e.to_string()))?;

    Ok(entries
        .iter()
        .filter(|e| {
            e.get("type")
                .and_then(|t| t.as_str())
                .is_none_or(|t| t.eq_ignore_ascii_case("totp"))
        })
        .filter_map(|e| {
            let secret = e.get("secret")?.as_str()?;
            // andOTP's `label` is often already "Issuer - account".
            let label = e.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let issuer = e.get("issuer").and_then(|v| v.as_str());
            let account = match (issuer, label.split_once(" - ")) {
                (Some(_), Some((_, account))) => account,
                _ => label,
            };
            let uri = build_uri(
                issuer,
                account,
                secret,
                e.get("algorithm").and_then(|v| v.as_str()),
                e.get("digits").and_then(|v| v.as_u64()).map(|d| d as u32),
                e.get("period").and_then(|v| v.as_u64()),
            );
            Totp::parse(&uri).ok()?;
            Some(Entry {
                issuer: issuer.map(str::to_owned),
                account: account.to_owned(),
                uri,
            })
        })
        .collect())
}

/// Read a file in whichever of the supported shapes it turns out to be.
///
/// Sniffed from the content rather than the extension: an Aegis export and an
/// andOTP export are both `.json`, and a URI list has no conventional suffix
/// at all.
pub fn parse_any(text: &str) -> Result<Vec<Entry>> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return parse_aegis(text);
    }
    if trimmed.starts_with('[') {
        return parse_andotp(text);
    }
    let entries = parse_uri_list(text);
    if entries.is_empty() {
        return Err(Error::Database(
            "no otpauth:// URIs, and not an Aegis or andOTP export".to_owned(),
        ));
    }
    Ok(entries)
}

pub fn item_for(entry: &Entry) -> Item {
    let mut item = Item::new(ItemKind::Login, entry.label()).with_field(Field::new(
        field_names::TOTP,
        FieldKind::Totp,
        &entry.uri,
    ));
    if !entry.account.is_empty() {
        item = item.with_field(Field::new(
            field_names::USERNAME,
            FieldKind::Text,
            &entry.account,
        ));
    }
    item.attributes
        .insert("totp:account".to_owned(), entry.account.clone());
    if let Some(issuer) = &entry.issuer {
        item.attributes
            .insert("totp:issuer".to_owned(), issuer.clone());
    }
    item.tags = vec!["2fa".to_owned()];
    item
}

/// Import every seed in `path`. Does not save.
pub fn import_file(
    vault: &mut Vault,
    path: &Path,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let entries = parse_any(&text)?;

    let target = crate::target_collection(vault, into_collection.unwrap_or("2FA"));
    let mut summary = ImportSummary::default();

    for entry in &entries {
        let item = item_for(entry);
        if crate::already_present(vault, &item.attributes) {
            summary.skipped_duplicate += 1;
            continue;
        }
        vault
            .add_item(target, item)
            .map_err(|e| Error::Vault(e.to_string()))?;
        summary.imported += 1;
    }

    summary.collections = 1;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "JBSWY3DPEHPK3PXP";

    #[test]
    fn a_uri_list_is_read_and_labelled() {
        let entries = parse_uri_list(&format!(
            "# my codes\n\
             otpauth://totp/GitHub:ada@example.com?secret={SEED}&issuer=GitHub\n\
             \n\
             not a uri\n"
        ));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(entries[0].account, "ada@example.com");
    }

    #[test]
    fn a_uri_with_an_unusable_seed_is_dropped_rather_than_stored() {
        let entries = parse_uri_list("otpauth://totp/Broken?secret=not-base32-!!!\n");
        assert!(entries.is_empty(), "an unparseable seed was imported");
    }

    #[test]
    fn a_percent_encoded_label_is_decoded() {
        let entries = parse_uri_list(&format!(
            "otpauth://totp/Big%20Corp:ada%40example.com?secret={SEED}\n"
        ));
        assert_eq!(entries[0].issuer.as_deref(), Some("Big Corp"));
        assert_eq!(entries[0].account, "ada@example.com");
    }

    #[test]
    fn aegis_exports_are_read() {
        let json = format!(
            r#"{{"db":{{"entries":[
                {{"type":"totp","name":"ada","issuer":"GitHub",
                  "info":{{"secret":"{SEED}","algo":"SHA1","digits":6,"period":30}}}},
                {{"type":"hotp","name":"counter","issuer":"X",
                  "info":{{"secret":"{SEED}","counter":1}}}}
            ]}}}}"#
        );
        let entries = parse_aegis(&json).unwrap();
        assert_eq!(entries.len(), 1, "a HOTP entry was imported as TOTP");
        assert_eq!(entries[0].issuer.as_deref(), Some("GitHub"));
        assert!(Totp::parse(&entries[0].uri).is_ok());
    }

    #[test]
    fn an_encrypted_aegis_export_says_so_instead_of_importing_nothing() {
        let err = parse_aegis(r#"{"version":1,"header":{},"db":"base64ciphertext"}"#).unwrap_err();
        assert!(
            err.to_string().contains("encrypted"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn andotp_exports_are_read_and_the_label_is_split() {
        let json = format!(
            r#"[{{"secret":"{SEED}","issuer":"GitLab","label":"GitLab - ada",
                 "type":"TOTP","algorithm":"SHA1","digits":6,"period":30}}]"#
        );
        let entries = parse_andotp(&json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].account, "ada", "the issuer prefix was kept in the account");
    }

    #[test]
    fn the_format_is_sniffed_from_the_content_not_the_name() {
        let aegis = format!(
            r#"{{"db":{{"entries":[{{"name":"a","issuer":"B","info":{{"secret":"{SEED}"}}}}]}}}}"#
        );
        assert_eq!(parse_any(&aegis).unwrap().len(), 1);

        let andotp = format!(r#"[{{"secret":"{SEED}","label":"a"}}]"#);
        assert_eq!(parse_any(&andotp).unwrap().len(), 1);

        let list = format!("otpauth://totp/a?secret={SEED}\n");
        assert_eq!(parse_any(&list).unwrap().len(), 1);
    }

    #[test]
    fn a_file_of_nothing_useful_is_an_error_not_an_empty_success() {
        assert!(parse_any("hello\nworld\n").is_err());
    }

    #[test]
    fn a_built_uri_survives_a_round_trip_through_the_parser() {
        let uri = build_uri(
            Some("Big Corp"),
            "ada@example.com",
            SEED,
            Some("sha256"),
            Some(8),
            Some(60),
        );
        let totp = Totp::parse(&uri).expect("built an unparseable URI");
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.period, 60);

        let (issuer, account) = describe(&uri);
        assert_eq!(issuer.as_deref(), Some("Big Corp"));
        assert_eq!(account, "ada@example.com");
    }

    #[test]
    fn the_item_carries_a_live_totp_field() {
        let entries = parse_uri_list(&format!(
            "otpauth://totp/GitHub:ada?secret={SEED}&issuer=GitHub\n"
        ));
        let item = item_for(&entries[0]);
        let field = item.field(field_names::TOTP).expect("no totp field");
        assert_eq!(field.kind, FieldKind::Totp);
        let totp = Totp::parse(field.value.expose()).expect("stored seed does not parse");
        assert_eq!(totp.code().unwrap().len(), 6);
    }

    #[test]
    fn importing_twice_does_not_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("codes.txt");
        std::fs::write(
            &file,
            format!("otpauth://totp/GitHub:ada?secret={SEED}&issuer=GitHub\n"),
        )
        .unwrap();

        let vpath = dir.path().join("v.vault");
        let mut v =
            Vault::create(&vpath, "pw", passman_core::crypto::KdfParams::insecure_fast()).unwrap();

        assert_eq!(import_file(&mut v, &file, None).unwrap().imported, 1);
        let second = import_file(&mut v, &file, None).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 1);
    }
}
