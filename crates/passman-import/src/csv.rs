//! Importing CSV exports — Chrome, Firefox, Safari, Edge, Bitwarden, 1Password,
//! KeePassXC.
//!
//! Every one of these exports "a CSV of passwords" with a different header, and
//! new ones appear whenever a vendor reshuffles their exporter. Hardcoding
//! dialects would mean a new branch per vendor and silent breakage when a
//! column is renamed, so instead each *logical* field owns a list of column
//! aliases and the header is matched against those. Chrome's `name,url,
//! username,password,note` and Bitwarden's `login_uri,login_username,
//! login_password,login_totp` both fall out of the same table.
//!
//! ## A word on these files
//!
//! A browser password export is a plaintext file containing every credential
//! you own. It is the single most dangerous file on the disk while it exists.
//! [`import_reader`] therefore never writes one, and the CLI reminds you to
//! delete it afterwards — shredding it here would be presumptuous, but saying
//! nothing would be negligent.

use std::collections::BTreeMap;
use std::path::Path;

use passman_core::{Field, FieldKind, Item, ItemKind, Vault, model::field_names};

use crate::{Error, ImportSummary, Result};

/// Logical fields, and the column names various exporters use for them.
///
/// Order matters: the first alias found wins, so more specific names come
/// before generic ones.
const ALIASES: &[(Logical, &[&str])] = &[
    (
        Logical::Title,
        &["name", "title", "account", "display name", "item name"],
    ),
    (
        Logical::Url,
        &["url", "login_uri", "website", "uri", "login uri", "web site"],
    ),
    (
        Logical::Username,
        &[
            "username",
            "login_username",
            "login name",
            "user name",
            "user",
            "login",
        ],
    ),
    (
        Logical::Password,
        &["password", "login_password", "pwd", "passwd"],
    ),
    (
        Logical::Totp,
        &["totp", "login_totp", "otpauth", "otp", "two-factor secret"],
    ),
    (Logical::Notes, &["notes", "note", "comment", "comments"]),
    (Logical::Group, &["folder", "group", "category", "grouping"]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Logical {
    Title,
    Url,
    Username,
    Password,
    Totp,
    Notes,
    Group,
}

/// Which column index holds each logical field.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Mapping {
    columns: BTreeMap<Logical, usize>,
    /// Header columns that matched nothing; preserved as custom fields so an
    /// unrecognised export loses nothing.
    extras: Vec<(usize, String)>,
}

impl Mapping {
    /// Work out the column layout from a header row.
    pub fn from_header(header: &[String]) -> Self {
        let mut columns: BTreeMap<Logical, usize> = BTreeMap::new();
        let mut claimed = vec![false; header.len()];

        for (logical, aliases) in ALIASES {
            for alias in *aliases {
                if let Some(idx) = header.iter().position(|h| {
                    !claimed[header.iter().position(|x| x == h).unwrap_or(0)]
                        && normalise(h) == normalise(alias)
                }) && !claimed[idx]
                {
                    columns.insert(*logical, idx);
                    claimed[idx] = true;
                    break;
                }
            }
        }

        let extras = header
            .iter()
            .enumerate()
            .filter(|(i, h)| !claimed[*i] && !h.trim().is_empty())
            .map(|(i, h)| (i, h.clone()))
            .collect();

        Self { columns, extras }
    }

    fn get<'a>(&self, row: &'a [String], field: Logical) -> Option<&'a str> {
        let idx = *self.columns.get(&field)?;
        row.get(idx).map(String::as_str).filter(|s| !s.is_empty())
    }

    /// Whether this looks like a password export at all.
    pub fn is_usable(&self) -> bool {
        self.columns.contains_key(&Logical::Password)
            && (self.columns.contains_key(&Logical::Title)
                || self.columns.contains_key(&Logical::Url))
    }
}

fn normalise(s: &str) -> String {
    s.trim()
        .trim_start_matches('\u{feff}') // Excel-flavoured exports carry a BOM
        .to_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build an item from one CSV row.
pub fn map_row(mapping: &Mapping, row: &[String]) -> Option<Item> {
    let password = mapping.get(row, Logical::Password).unwrap_or_default();
    let url = mapping.get(row, Logical::Url);
    let title = mapping
        .get(row, Logical::Title)
        // Firefox exports have no name column at all, so fall back to the host.
        .or_else(|| url.map(host_of))
        .unwrap_or("Untitled");

    // A row with neither a password nor a TOTP holds nothing worth importing.
    let totp = mapping.get(row, Logical::Totp);
    if password.is_empty() && totp.is_none() {
        return None;
    }

    let mut item = Item::new(ItemKind::Login, title).with_secret(password);

    if let Some(u) = mapping.get(row, Logical::Username) {
        item.set_field(Field::text(field_names::USERNAME, u));
        item.attributes.insert("username".into(), u.to_owned());
    }
    if let Some(u) = url {
        item.set_field(Field::new(field_names::URL, FieldKind::Url, u));
        item.attributes.insert("url".into(), u.to_owned());
    }
    if let Some(t) = totp {
        item.set_field(Field::new(field_names::TOTP, FieldKind::Totp, t));
    }
    if let Some(n) = mapping.get(row, Logical::Notes) {
        item.set_field(Field::new(field_names::NOTES, FieldKind::Note, n));
    }
    if let Some(g) = mapping.get(row, Logical::Group) {
        item.tags = g.split('/').map(str::to_owned).collect();
    }

    // Unrecognised columns become plain fields rather than vanishing.
    for (idx, name) in &mapping.extras {
        if let Some(value) = row.get(*idx).filter(|v| !v.is_empty()) {
            item.set_field(Field::text(name.clone(), value.clone()));
        }
    }

    item.attributes.insert("passman:source".into(), "csv".into());
    item.attributes.insert(
        "csv:key".into(),
        format!("{title}\u{1f}{}", item.field_value(field_names::USERNAME).unwrap_or("")),
    );
    Some(item)
}

/// Strip a URL down to its host, for exports with no name column.
fn host_of(url: &str) -> &str {
    let rest = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    host.split('@').next_back().unwrap_or(host)
}

/// Import from any `Read`. Returns the summary plus the items.
pub fn import_reader<R: std::io::Read>(
    vault: &mut Vault,
    reader: R,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(reader);

    let header: Vec<String> = rdr
        .headers()
        .map_err(|e| Error::Database(format!("could not read the CSV header: {e}")))?
        .iter()
        .map(str::to_owned)
        .collect();

    let mapping = Mapping::from_header(&header);
    if !mapping.is_usable() {
        return Err(Error::Database(format!(
            "this CSV has no recognisable password column (header: {})",
            header.join(", ")
        )));
    }

    let target = crate::target_collection(vault, into_collection.unwrap_or("Imported"));
    let mut summary = ImportSummary::default();

    for record in rdr.records() {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("skipping malformed CSV row: {e}");
                summary.skipped_unreadable += 1;
                continue;
            }
        };
        let row: Vec<String> = record.iter().map(str::to_owned).collect();

        let Some(item) = map_row(&mapping, &row) else {
            summary.skipped_unreadable += 1;
            continue;
        };
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

/// Import from a file on disk.
pub fn import_file(
    vault: &mut Vault,
    path: &Path,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let file = std::fs::File::open(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    import_reader(vault, file, into_collection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use passman_core::crypto::KdfParams;

    fn vault(dir: &tempfile::TempDir) -> Vault {
        Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap()
    }

    fn import(csv: &str) -> (Vault, ImportSummary, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let s = import_reader(&mut v, csv.as_bytes(), None).unwrap();
        (v, s, dir)
    }

    /// Chrome, Edge, Brave, Opera all emit this.
    #[test]
    fn chrome_export() {
        let (v, s, _d) = import(
            "name,url,username,password,note\n\
             github.com,https://github.com/login,ada,hunter2,my note\n",
        );
        assert_eq!(s.imported, 1);
        let (_, item) = v.data().all_items().next().unwrap();
        assert_eq!(item.label, "github.com");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(item.field_value(field_names::URL), Some("https://github.com/login"));
        assert_eq!(item.field_value(field_names::NOTES), Some("my note"));
    }

    /// Firefox has no name column; the host has to stand in.
    #[test]
    fn firefox_export() {
        let (v, s, _d) = import(
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\"\n\
             \"https://mail.example.org\",\"ada\",\"hunter2\",\"\",\"https://mail.example.org\",\"{abc}\",\"1700000000\"\n",
        );
        assert_eq!(s.imported, 1);
        let (_, item) = v.data().all_items().next().unwrap();
        assert_eq!(item.label, "mail.example.org", "host did not stand in for a name");
        assert_eq!(item.secret.expose(), "hunter2");
        // Unmapped columns survive rather than being dropped.
        assert_eq!(item.field_value("guid"), Some("{abc}"));
    }

    #[test]
    fn bitwarden_export() {
        let (v, s, _d) = import(
            "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
             Work,,login,Jira,,,https://jira.corp,ada,hunter2,otpauth://totp/Jira?secret=JBSWY3DPEHPK3PXP\n",
        );
        assert_eq!(s.imported, 1);
        let (_, item) = v.data().all_items().next().unwrap();
        assert_eq!(item.label, "Jira");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.tags, vec!["Work"]);
        let totp = item.field(field_names::TOTP).unwrap();
        assert!(passman_core::Totp::parse(totp.value.expose()).is_ok());
    }

    /// KeePassXC and 1Password use Group/Title/…
    #[test]
    fn keepassxc_csv_export() {
        let (v, s, _d) = import(
            "Group,Title,Username,Password,URL,Notes\n\
             Root/Web,GitHub,ada,hunter2,https://github.com,note\n",
        );
        assert_eq!(s.imported, 1);
        let (_, item) = v.data().all_items().next().unwrap();
        assert_eq!(item.label, "GitHub");
        assert_eq!(item.tags, vec!["Root", "Web"]);
    }

    #[test]
    fn safari_export_with_otp() {
        let (v, s, _d) = import(
            "Title,URL,Username,Password,Notes,OTPAuth\n\
             Bank,https://bank.example,ada,hunter2,,otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP\n",
        );
        assert_eq!(s.imported, 1);
        let (_, item) = v.data().all_items().next().unwrap();
        assert!(item.field(field_names::TOTP).is_some());
    }

    #[test]
    fn quoted_fields_with_commas_and_newlines_survive() {
        let (v, _s, _d) = import(
            "name,url,username,password,note\n\
             \"Acme, Inc\",https://acme.example,ada,\"pa,ss\",\"line one\nline two\"\n",
        );
        let (_, item) = v.data().all_items().next().unwrap();
        assert_eq!(item.label, "Acme, Inc");
        assert_eq!(item.secret.expose(), "pa,ss");
        assert_eq!(item.field_value(field_names::NOTES), Some("line one\nline two"));
    }

    #[test]
    fn a_bom_prefixed_header_still_matches() {
        let (v, s, _d) = import("\u{feff}name,url,username,password\nX,https://x,ada,pw\n");
        assert_eq!(s.imported, 1);
        assert_eq!(v.data().all_items().next().unwrap().1.label, "X");
    }

    #[test]
    fn rows_with_no_secret_are_skipped_not_imported_blank() {
        let (_v, s, _d) = import(
            "name,url,username,password\n\
             Empty,https://x,ada,\n\
             Real,https://y,ada,pw\n",
        );
        assert_eq!(s.imported, 1);
        assert_eq!(s.skipped_unreadable, 1);
    }

    #[test]
    fn a_csv_that_is_not_a_password_export_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let err = import_reader(&mut v, "date,amount,payee\n2026-01-01,5,shop\n".as_bytes(), None);
        assert!(err.is_err(), "a bank statement was accepted as passwords");
    }

    #[test]
    fn importing_twice_does_not_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let csv = "name,url,username,password\nX,https://x,ada,pw\n";
        let first = import_reader(&mut v, csv.as_bytes(), None).unwrap();
        let second = import_reader(&mut v, csv.as_bytes(), None).unwrap();
        assert_eq!(first.imported, 1);
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 1);
    }

    #[test]
    fn host_extraction_handles_the_shapes_urls_come_in() {
        assert_eq!(host_of("https://example.org/login?x=1"), "example.org");
        assert_eq!(host_of("http://user@example.org:8080/"), "example.org:8080");
        assert_eq!(host_of("example.org"), "example.org");
        assert_eq!(host_of(""), "");
    }

    #[test]
    fn header_matching_is_case_and_separator_insensitive() {
        let m = Mapping::from_header(&[
            "Login_URI".into(),
            "Login Username".into(),
            "PASSWORD".into(),
        ]);
        assert!(m.is_usable());
        let row = vec!["https://x".into(), "ada".into(), "pw".into()];
        let item = map_row(&m, &row).unwrap();
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(item.secret.expose(), "pw");
    }
}
