//! Import credentials that developer CLIs leave in plaintext.
//!
//! `aws`, `gcloud`, `az`, `gh`, `docker` and `npm` all cache long-lived
//! credentials in your home directory with no encryption at all — an AWS
//! secret access key in an INI file, a Google refresh token in a SQLite blob,
//! a GitHub OAuth token in YAML. Between them they are usually the most
//! valuable unprotected material on a developer's machine, and unlike `.env`
//! files they are not even project-scoped: they authorise everything.
//!
//! As with every other importer here the sources are read and left alone.
//! Deleting them would break the very tools that wrote them; the point is to
//! have a copy somewhere encrypted, and to know what is lying around.
//!
//! gcloud's store is a SQLite database, read through the `sqlite3` binary
//! rather than a linked library — the same choice [`crate::pass`] makes in
//! shelling out to `gpg`. It keeps a C dependency out of the build for one
//! file, and if `sqlite3` is missing that source is reported as skipped
//! instead of silently contributing nothing.

use std::path::{Path, PathBuf};

use passman_core::{
    Vault,
    model::{Field, FieldKind, Item, ItemKind, field_names},
};

use crate::{Error, ImportSummary, Result};

/// One credential store this importer knows how to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    Aws,
    GoogleCloud,
    Azure,
    GitHubCli,
    Docker,
    Npm,
}

impl Store {
    pub const ALL: &'static [Store] = &[
        Store::Aws,
        Store::GoogleCloud,
        Store::Azure,
        Store::GitHubCli,
        Store::Docker,
        Store::Npm,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Store::Aws => "AWS CLI",
            Store::GoogleCloud => "Google Cloud CLI",
            Store::Azure => "Azure CLI",
            Store::GitHubCli => "GitHub CLI",
            Store::Docker => "Docker",
            Store::Npm => "npm",
        }
    }

    /// Where this store keeps its credentials, relative to the home directory.
    fn path_in(self, home: &Path) -> PathBuf {
        match self {
            Store::Aws => home.join(".aws/credentials"),
            Store::GoogleCloud => home.join(".config/gcloud/credentials.db"),
            Store::Azure => home.join(".azure/msal_token_cache.json"),
            Store::GitHubCli => home.join(".config/gh/hosts.yml"),
            Store::Docker => home.join(".docker/config.json"),
            Store::Npm => home.join(".npmrc"),
        }
    }
}

/// A store that is actually present on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub store: Store,
    pub path: PathBuf,
}

/// Which of the known stores exist under `home`.
pub fn scan(home: &Path) -> Vec<Found> {
    Store::ALL
        .iter()
        .filter_map(|&store| {
            let path = store.path_in(home);
            path.exists().then_some(Found { store, path })
        })
        .collect()
}

pub fn home() -> Option<PathBuf> {
    dirs::home_dir()
}

// ---------------------------------------------------------------------------
// AWS — ~/.aws/credentials, an INI file, one section per profile
// ---------------------------------------------------------------------------

/// Parse an INI file into `(section, [(key, value)])`, in file order.
///
/// Deliberately minimal: these files are written by tooling, so the exotic
/// corners of the INI "spec" do not arise. Anything unparseable is skipped
/// rather than failing the file.
fn parse_ini(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push((name.trim().to_owned(), Vec::new()));
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && let Some((_, entries)) = out.last_mut()
        {
            entries.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    out
}

pub fn aws_items(text: &str) -> Vec<Item> {
    parse_ini(text)
        .into_iter()
        .filter_map(|(profile, entries)| {
            let get = |k: &str| {
                entries
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(k))
                    .map(|(_, v)| v.as_str())
            };
            // A profile with no secret key is a region/output block, not a
            // credential — ~/.aws/config style entries end up here too.
            let secret = get("aws_secret_access_key")?;

            let mut item = Item::new(ItemKind::ApiToken, format!("AWS · {profile}"));
            item.secret = secret.to_owned().into();
            if let Some(id) = get("aws_access_key_id") {
                item = item.with_field(Field::new("access-key-id", FieldKind::Text, id));
                item.attributes
                    .insert("aws:access-key-id".to_owned(), id.to_owned());
            }
            if let Some(token) = get("aws_session_token") {
                item = item.with_field(Field::new(
                    field_names::ACCESS_TOKEN,
                    FieldKind::Secret,
                    token,
                ));
            }
            item.attributes
                .insert("cloud:store".to_owned(), "aws".to_owned());
            item.attributes
                .insert("aws:profile".to_owned(), profile.clone());
            item.tags = vec!["aws".to_owned(), "cloud".to_owned()];
            Some(item)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Google Cloud — ~/.config/gcloud/credentials.db, via the sqlite3 binary
// ---------------------------------------------------------------------------

/// Read `credentials.db` as `(account, credential json)` pairs.
///
/// Opened read-only so a running `gcloud` cannot be disturbed and the file
/// cannot be modified even by accident.
fn gcloud_rows(path: &Path, sqlite_bin: &str) -> Result<Vec<(String, String)>> {
    let output = std::process::Command::new(sqlite_bin)
        .arg("-readonly")
        .arg("-json")
        .arg(path)
        .arg("select account_id, value from credentials;")
        .output()
        .map_err(|e| Error::Tool(format!("could not run `{sqlite_bin}`: {e}")))?;

    if !output.status.success() {
        return Err(Error::Tool(format!(
            "{sqlite_bin} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| Error::Database(e.to_string()))?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let account = row.get("account_id")?.as_str()?.to_owned();
            let value = row.get("value")?.as_str()?.to_owned();
            Some((account, value))
        })
        .collect())
}

/// Build an item from one gcloud credential blob.
pub fn gcloud_item(account: &str, value: &str) -> Option<Item> {
    let json: serde_json::Value = serde_json::from_str(value).ok()?;
    let get = |k: &str| json.get(k).and_then(|v| v.as_str());

    // The refresh token is the durable secret; access tokens expire in an hour
    // and are not worth storing.
    let refresh = get("refresh_token")?;

    let mut item = Item::new(ItemKind::OAuth, format!("Google Cloud · {account}"));
    item.secret = refresh.to_owned().into();
    item = item.with_field(Field::new(
        field_names::REFRESH_TOKEN,
        FieldKind::Secret,
        refresh,
    ));
    if let Some(id) = get("client_id") {
        item = item.with_field(Field::new(field_names::CLIENT_ID, FieldKind::Text, id));
    }
    if let Some(secret) = get("client_secret") {
        item = item.with_field(Field::new(
            field_names::CLIENT_SECRET,
            FieldKind::Secret,
            secret,
        ));
    }
    if let Some(uri) = get("token_uri") {
        item = item.with_field(Field::new(field_names::TOKEN_ENDPOINT, FieldKind::Url, uri));
    }
    item.attributes
        .insert("cloud:store".to_owned(), "gcloud".to_owned());
    item.attributes
        .insert("gcloud:account".to_owned(), account.to_owned());
    item.tags = vec!["gcloud".to_owned(), "cloud".to_owned()];
    Some(item)
}

// ---------------------------------------------------------------------------
// Azure — ~/.azure/msal_token_cache.json
// ---------------------------------------------------------------------------

pub fn azure_items(text: &str) -> Vec<Item> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(tokens) = json.get("RefreshToken").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    tokens
        .values()
        .filter_map(|entry| {
            let secret = entry.get("secret")?.as_str()?;
            let account = entry
                .get("home_account_id")
                .and_then(|v| v.as_str())
                .unwrap_or("account");

            let mut item = Item::new(ItemKind::OAuth, format!("Azure · {account}"));
            item.secret = secret.to_owned().into();
            item = item.with_field(Field::new(
                field_names::REFRESH_TOKEN,
                FieldKind::Secret,
                secret,
            ));
            if let Some(id) = entry.get("client_id").and_then(|v| v.as_str()) {
                item = item.with_field(Field::new(field_names::CLIENT_ID, FieldKind::Text, id));
            }
            item.attributes
                .insert("cloud:store".to_owned(), "azure".to_owned());
            item.attributes
                .insert("azure:account".to_owned(), account.to_owned());
            item.tags = vec!["azure".to_owned(), "cloud".to_owned()];
            Some(item)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// GitHub CLI — ~/.config/gh/hosts.yml
// ---------------------------------------------------------------------------

/// Extract `(host, user, token)` from `gh`'s hosts file.
///
/// Hand-parsed rather than pulled through a YAML library: the file is written
/// by `gh` with a fixed two-to-three level shape, and the alternative is a
/// whole YAML dependency for six lines. Indentation decides nesting, a
/// zero-indent key is a host, and `user:` names the account a token belongs
/// to.
pub fn gh_entries(text: &str) -> Vec<(String, Option<String>, String)> {
    let mut out = Vec::new();
    let mut host: Option<String> = None;
    let mut user: Option<String> = None;
    // Under `users:`, each nested key is an account name.
    let mut current_account: Option<String> = None;

    for raw in text.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if indent == 0 {
            host = Some(key.to_owned());
            user = None;
            current_account = None;
            continue;
        }
        match key {
            "user" => user = Some(value.to_owned()),
            "oauth_token" if !value.is_empty() => {
                if let Some(host) = host.clone() {
                    // A token nested under `users:` belongs to that account;
                    // one at host level belongs to `user`.
                    out.push((host, current_account.clone().or_else(|| user.clone()), value.to_owned()));
                }
            }
            // A key with no value that is not one we know is an account name
            // under `users:`.
            _ if value.is_empty() && key != "users" => current_account = Some(key.to_owned()),
            _ => {}
        }
    }
    out
}

pub fn gh_items(text: &str) -> Vec<Item> {
    gh_entries(text)
        .into_iter()
        .map(|(host, user, token)| {
            let label = match &user {
                Some(u) => format!("GitHub CLI · {u}@{host}"),
                None => format!("GitHub CLI · {host}"),
            };
            let mut item = Item::new(ItemKind::ApiToken, label);
            item.secret = token.into();
            if let Some(u) = &user {
                item = item.with_field(Field::new(field_names::USERNAME, FieldKind::Text, u));
            }
            item = item.with_field(Field::new(
                field_names::URL,
                FieldKind::Url,
                format!("https://{host}"),
            ));
            item.attributes
                .insert("cloud:store".to_owned(), "gh".to_owned());
            item.attributes.insert("gh:host".to_owned(), host);
            if let Some(u) = user {
                item.attributes.insert("gh:user".to_owned(), u);
            }
            item.tags = vec!["github".to_owned()];
            item
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Docker — ~/.docker/config.json
// ---------------------------------------------------------------------------

pub fn docker_items(text: &str) -> Vec<Item> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(auths) = json.get("auths").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    auths
        .iter()
        .filter_map(|(registry, entry)| {
            // `auth` is base64 of "user:password" — not encryption, just
            // encoding, which is exactly why it is worth moving into a vault.
            let encoded = entry.get("auth")?.as_str()?;
            if encoded.is_empty() {
                return None;
            }
            let decoded = {
                use base64ct::Encoding as _;
                base64ct::Base64::decode_vec(encoded).ok()?
            };
            let decoded = String::from_utf8(decoded).ok()?;
            let (user, password) = decoded.split_once(':')?;

            let mut item = Item::new(ItemKind::Login, format!("Docker · {registry}"));
            item.secret = password.to_owned().into();
            item = item
                .with_field(Field::new(field_names::USERNAME, FieldKind::Text, user))
                .with_field(Field::new(field_names::URL, FieldKind::Url, registry));
            item.attributes
                .insert("cloud:store".to_owned(), "docker".to_owned());
            item.attributes
                .insert("docker:registry".to_owned(), registry.clone());
            item.tags = vec!["docker".to_owned()];
            Some(item)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// npm — ~/.npmrc
// ---------------------------------------------------------------------------

pub fn npm_items(text: &str) -> Vec<Item> {
    text.lines()
        .filter_map(|raw| {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            // `//registry.npmjs.org/:_authToken=npm_xxx`
            let registry = key.strip_suffix(":_authToken")?.trim_start_matches("//");
            if value.is_empty() {
                return None;
            }

            let mut item = Item::new(ItemKind::ApiToken, format!("npm · {registry}"));
            item.secret = value.to_owned().into();
            item = item.with_field(Field::new(
                field_names::URL,
                FieldKind::Url,
                format!("https://{registry}"),
            ));
            item.attributes
                .insert("cloud:store".to_owned(), "npm".to_owned());
            item.attributes
                .insert("npm:registry".to_owned(), registry.to_owned());
            item.tags = vec!["npm".to_owned()];
            Some(item)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Build the items one store contributes, reading it from disk.
fn items_for(found: &Found, sqlite_bin: &str) -> Result<Vec<Item>> {
    if found.store == Store::GoogleCloud {
        return Ok(gcloud_rows(&found.path, sqlite_bin)?
            .into_iter()
            .filter_map(|(account, value)| gcloud_item(&account, &value))
            .collect());
    }

    let text = std::fs::read_to_string(&found.path).map_err(|e| Error::Io {
        path: found.path.clone(),
        source: e,
    })?;

    Ok(match found.store {
        Store::Aws => aws_items(&text),
        Store::Azure => azure_items(&text),
        Store::GitHubCli => gh_items(&text),
        Store::Docker => docker_items(&text),
        Store::Npm => npm_items(&text),
        Store::GoogleCloud => unreachable!("handled above"),
    })
}

/// Import every credential store found under `home`. Does not save.
///
/// A store that cannot be read is counted and skipped rather than aborting:
/// a missing `sqlite3`, or an Azure cache written by a version whose shape
/// changed, should not cost you the other five.
pub fn import_home(
    vault: &mut Vault,
    home: &Path,
    sqlite_bin: &str,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let target = crate::target_collection(vault, into_collection.unwrap_or("Cloud"));
    let mut summary = ImportSummary::default();

    for found in scan(home) {
        let items = match items_for(&found, sqlite_bin) {
            Ok(items) => items,
            Err(e) => {
                tracing::warn!("skipping {}: {e}", found.store.label());
                summary.skipped_unreadable += 1;
                continue;
            }
        };
        for item in items {
            if crate::already_present(vault, &item.attributes) {
                summary.skipped_duplicate += 1;
                continue;
            }
            vault
                .add_item(target, item)
                .map_err(|e| Error::Vault(e.to_string()))?;
            summary.imported += 1;
        }
    }

    summary.collections = 1;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_profiles_become_items_keyed_on_the_secret_key() {
        let items = aws_items(
            "[default]\n\
             aws_access_key_id = AKIAEXAMPLE\n\
             aws_secret_access_key = wJalrXUtnFEMI\n\n\
             [work]\n\
             aws_access_key_id = AKIAWORK\n\
             aws_secret_access_key = shhh\n\
             aws_session_token = FwoGZXIvYXdz\n",
        );
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "AWS · default");
        assert_eq!(items[0].secret.expose(), "wJalrXUtnFEMI");
        assert_eq!(
            items[1].field_value(field_names::ACCESS_TOKEN),
            Some("FwoGZXIvYXdz")
        );
    }

    #[test]
    fn an_aws_section_without_a_secret_key_is_not_a_credential() {
        // ~/.aws/config style content: region and output, no key material.
        let items = aws_items("[profile work]\nregion = eu-west-1\noutput = json\n");
        assert!(items.is_empty(), "a config-only profile was imported");
    }

    #[test]
    fn gcloud_keeps_the_refresh_token_and_drops_the_access_token() {
        let item = gcloud_item(
            "ada@example.com",
            r#"{"client_id":"cid.apps.googleusercontent.com",
                "client_secret":"csecret",
                "refresh_token":"1//refresh",
                "token_uri":"https://oauth2.googleapis.com/token",
                "access_token":"ya29.expires-in-an-hour"}"#,
        )
        .expect("no item built");

        assert_eq!(item.kind, ItemKind::OAuth);
        assert_eq!(item.secret.expose(), "1//refresh");
        assert_eq!(
            item.field_value(field_names::CLIENT_ID),
            Some("cid.apps.googleusercontent.com")
        );
        assert!(
            item.fields
                .iter()
                .all(|f| !f.value.expose().starts_with("ya29.")),
            "a short-lived access token was stored"
        );
    }

    #[test]
    fn a_gcloud_row_without_a_refresh_token_is_skipped() {
        assert!(gcloud_item("x@y.z", r#"{"access_token":"ya29.only"}"#).is_none());
    }

    #[test]
    fn azure_refresh_tokens_are_read_from_the_msal_cache() {
        let items = azure_items(
            r#"{"RefreshToken":{"key1":{"home_account_id":"abc.tenant",
                "client_id":"04b07795","secret":"0.AXkA-refresh"}}}"#,
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].secret.expose(), "0.AXkA-refresh");
        assert_eq!(items[0].attributes.get("azure:account").unwrap(), "abc.tenant");
    }

    #[test]
    fn gh_tokens_are_found_under_users_and_attributed_to_the_account() {
        let entries = gh_entries(
            "github.com:\n\
             \x20   git_protocol: https\n\
             \x20   users:\n\
             \x20       ada:\n\
             \x20           oauth_token: gho_nested\n\
             \x20   user: ada\n",
        );
        assert_eq!(
            entries,
            vec![("github.com".to_owned(), Some("ada".to_owned()), "gho_nested".to_owned())]
        );
    }

    #[test]
    fn a_host_level_gh_token_is_attributed_to_user() {
        let entries = gh_entries(
            "github.com:\n\
             \x20   oauth_token: gho_flat\n\
             \x20   user: ada\n",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "github.com");
        assert_eq!(entries[0].2, "gho_flat");
    }

    #[test]
    fn two_gh_hosts_stay_separate() {
        let items = gh_items(
            "github.com:\n\
             \x20   oauth_token: gho_a\n\
             \x20   user: ada\n\
             ghe.corp.example:\n\
             \x20   oauth_token: gho_b\n\
             \x20   user: bob\n",
        );
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].secret.expose(), "gho_a");
        assert_eq!(items[1].attributes.get("gh:host").unwrap(), "ghe.corp.example");
    }

    #[test]
    fn docker_auth_is_decoded_into_a_username_and_password() {
        // base64("ada:hunter2")
        let items = docker_items(r#"{"auths":{"ghcr.io":{"auth":"YWRhOmh1bnRlcjI="}}}"#);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(items[0].secret.expose(), "hunter2");
    }

    #[test]
    fn a_docker_entry_with_no_auth_is_skipped() {
        let items = docker_items(r#"{"auths":{"ghcr.io":{}},"credsStore":"pass"}"#);
        assert!(items.is_empty());
    }

    #[test]
    fn npm_auth_tokens_are_found_and_other_settings_are_not() {
        let items = npm_items(
            "//registry.npmjs.org/:_authToken=npm_abc\n\
             ; a comment\n\
             registry=https://registry.npmjs.org/\n\
             save-exact=true\n\
             //npm.pkg.github.com/:_authToken=ghp_def\n",
        );
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].secret.expose(), "npm_abc");
        assert_eq!(
            items[1].attributes.get("npm:registry").unwrap(),
            "npm.pkg.github.com/"
        );
    }

    fn home_with_files() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".aws")).unwrap();
        std::fs::write(
            dir.path().join(".aws/credentials"),
            "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = s1\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join(".docker")).unwrap();
        std::fs::write(
            dir.path().join(".docker/config.json"),
            r#"{"auths":{"ghcr.io":{"auth":"YWRhOmh1bnRlcjI="}}}"#,
        )
        .unwrap();
        dir
    }

    #[test]
    fn the_scan_reports_only_stores_that_exist() {
        let home = home_with_files();
        let found: Vec<_> = scan(home.path()).into_iter().map(|f| f.store).collect();
        assert_eq!(found, vec![Store::Aws, Store::Docker]);
    }

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let v = Vault::create(&path, "pw", passman_core::crypto::KdfParams::insecure_fast())
            .unwrap();
        (dir, v)
    }

    #[test]
    fn importing_twice_does_not_duplicate() {
        let home = home_with_files();
        let (_d, mut v) = vault();
        let first = import_home(&mut v, home.path(), "sqlite3", None).unwrap();
        let second = import_home(&mut v, home.path(), "sqlite3", None).unwrap();
        assert_eq!(first.imported, 2);
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 2);
    }

    #[test]
    fn a_missing_sqlite3_costs_only_the_gcloud_store() {
        let home = home_with_files();
        std::fs::create_dir_all(home.path().join(".config/gcloud")).unwrap();
        std::fs::write(home.path().join(".config/gcloud/credentials.db"), b"not-a-db").unwrap();

        let (_d, mut v) = vault();
        let summary =
            import_home(&mut v, home.path(), "definitely-not-a-real-binary", None).unwrap();
        assert_eq!(summary.imported, 2, "the other stores did not import");
        assert_eq!(summary.skipped_unreadable, 1);
    }

    #[test]
    fn the_source_files_are_left_alone() {
        let home = home_with_files();
        let before = std::fs::read_to_string(home.path().join(".aws/credentials")).unwrap();
        let (_d, mut v) = vault();
        import_home(&mut v, home.path(), "sqlite3", None).unwrap();
        let after = std::fs::read_to_string(home.path().join(".aws/credentials")).unwrap();
        assert_eq!(before, after);
    }
}
