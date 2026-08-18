//! Import `.env` files from a tree of projects.
//!
//! A developer's `.env` files are usually the largest pile of unencrypted
//! credentials on the machine — production database URLs, Stripe keys, and
//! service-account tokens sitting in plaintext across dozens of checkouts.
//! Pulling them into the vault is the single highest-value import locket can
//! offer, so this walks a directory of projects rather than taking one file.
//!
//! Two judgement calls are worth stating outright:
//!
//! * **The source files are never touched.** This is an import, not a
//!   migration. Deleting a `.env` out from under a running dev server would be
//!   a hostile surprise, and the file is still needed until the project reads
//!   its config from locket instead.
//! * **`.env.example` and friends are skipped.** They exist precisely because
//!   they hold no secrets, and importing `DATABASE_URL=changeme` a hundred
//!   times would bury the real credentials.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use locket_core::{
    Vault,
    model::{Field, FieldKind, Item, ItemKind},
};

use crate::{Error, ImportSummary, Result};

/// Directories that never contain a project's own configuration, and would
/// otherwise dominate the walk. `node_modules` alone can hold thousands of
/// vendored `.env` fixtures belonging to other people's test suites.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
    ".terraform",
    ".cache",
    ".tox",
    "Pods",
];

/// Suffixes that mark a template rather than a real environment file.
const TEMPLATE_SUFFIXES: &[&str] = &[
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".defaults",
    ".tpl",
];

/// How to slice a project's variables into vault items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Grouping {
    /// One item per `.env` file, every variable a field. The default: it
    /// preserves "these belong together", which is how the file is used.
    #[default]
    PerFile,
    /// One item per inferred service within a file — `STRIPE_*` in one item,
    /// `AWS_*` in another. Useful when a project's `.env` has grown to fifty
    /// variables spanning a dozen vendors.
    PerService,
    /// One item per variable. The most granular, and the easiest to search
    /// for a single key across every project.
    PerVariable,
}

/// One environment file found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFile {
    /// Directory name of the project the file belongs to.
    pub project: String,
    /// Path relative to the scan root, for display and for deduplication.
    pub relative: PathBuf,
    pub path: PathBuf,
    /// The file's own name, e.g. `.env.local`.
    pub name: String,
}

/// A parsed variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Var {
    pub key: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse `.env` text into variables, in file order.
///
/// Follows the dialect every `dotenv` library agrees on: `KEY=value`, an
/// optional `export ` prefix, `#` comments, and single- or double-quoted
/// values. Escapes are only interpreted inside double quotes, which is what
/// the shell does and therefore what people expect.
///
/// Malformed lines are skipped rather than failing the file: a stray line in
/// one `.env` should not cost you the other forty credentials in it.
pub fn parse(text: &str) -> Vec<Var> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();

    while let Some(raw) = lines.next() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();

        let Some((key, rest)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            continue;
        }

        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                // A quoted value may span lines; keep consuming until the
                // closing quote so multi-line PEM keys survive intact.
                let mut body = rest[q.len_utf8()..].to_owned();
                let mut closed = close_quote(&body, q).is_some();
                while !closed {
                    match lines.next() {
                        Some(next) => {
                            body.push('\n');
                            body.push_str(next);
                            closed = close_quote(&body, q).is_some();
                        }
                        None => break,
                    }
                }
                let end = close_quote(&body, q).unwrap_or(body.len());
                let raw_value = &body[..end];
                if q == '"' {
                    unescape(raw_value)
                } else {
                    raw_value.to_owned()
                }
            }
            _ => strip_inline_comment(rest).trim_end().to_owned(),
        };

        out.push(Var {
            key: key.to_owned(),
            value,
        });
    }
    out
}

/// Byte offset of the unescaped closing quote, if the value is terminated.
fn close_quote(body: &str, quote: char) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && quote == '"' {
            i += 2;
            continue;
        }
        if c as char == quote {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Drop a trailing ` # comment` from an unquoted value.
///
/// Only a `#` preceded by whitespace counts, so a value that legitimately
/// contains one — a URL fragment, a colour, a generated password — survives.
fn strip_inline_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'#' && i > 0 && (bytes[i - 1] as char).is_whitespace() {
            return &s[..i];
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Key fragments that mean "this is a credential".
const SECRET_KEY_MARKERS: &[&str] = &[
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "PASSPHRASE", "CREDENTIAL", "PRIVATE",
    "APIKEY", "API_KEY", "ACCESS_KEY", "SIGNING", "SIGNATURE", "SALT", "CERT", "DSN", "AUTH",
    "SESSION", "COOKIE", "ENCRYPT", "WEBHOOK", "CLIENT_ID",
];

/// Keys that look secret by the rule above but are conventionally public.
const NOT_SECRET_KEYS: &[&str] = &[
    "NODE_ENV",
    "ENVIRONMENT",
    "PORT",
    "HOST",
    "HOSTNAME",
    "DEBUG",
    "LOG_LEVEL",
    "LOGLEVEL",
    "TZ",
    "CI",
    "PUBLIC_URL",
    "BASE_URL",
    "APP_ENV",
    "APP_NAME",
    "APP_URL",
    "RAILS_ENV",
];

/// Value prefixes that identify a credential regardless of the key's name.
const SECRET_VALUE_PREFIXES: &[&str] = &[
    "sk-", "sk_live_", "sk_test_", "rk_live_", "ghp_", "gho_", "ghu_", "ghs_", "github_pat_",
    "xoxb-", "xoxp-", "xapp-", "AKIA", "ASIA", "AIza", "ya29.", "eyJ", "-----BEGIN", "glpat-",
    "npm_", "dop_v1_", "shpat_", "SG.", "hf_",
];

/// Whether a variable holds something worth encrypting.
///
/// Deliberately generous: a false positive costs a needlessly-masked field,
/// while a false negative leaves a live credential unprotected in the item's
/// plaintext-shaped metadata. When in doubt, treat it as a secret.
pub fn is_secret(key: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let upper = key.to_ascii_uppercase();
    if NOT_SECRET_KEYS.contains(&upper.as_str()) {
        return false;
    }
    if SECRET_KEY_MARKERS.iter().any(|m| upper.contains(m)) {
        return true;
    }
    if SECRET_VALUE_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    // A connection string with embedded credentials: postgres://u:pw@host/db
    if let Some((scheme, rest)) = value.split_once("://")
        && !scheme.is_empty()
        && rest.split('/').next().is_some_and(|a| a.contains(':') && a.contains('@'))
    {
        return true;
    }
    // Anything long and unbroken is almost certainly a key rather than config.
    value.len() >= 32 && !value.contains(char::is_whitespace)
}

/// The service a variable appears to belong to: the first `_`-separated token.
///
/// `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` share `STRIPE`; a key with
/// no underscore has no inferable service and stays with the file.
pub fn service_of(key: &str) -> Option<String> {
    let (head, rest) = key.split_once('_')?;
    if head.is_empty() || rest.is_empty() {
        return None;
    }
    // Framework-mandated prefixes name the bundler, not the vendor, so look
    // past them: NEXT_PUBLIC_SUPABASE_URL belongs to Supabase.
    const PREFIXES: &[&str] = &["NEXT", "VITE", "REACT", "NUXT", "PUBLIC", "EXPO", "GATSBY"];
    let head_upper = head.to_ascii_uppercase();
    if PREFIXES.contains(&head_upper.as_str()) {
        return service_of(rest.strip_prefix("PUBLIC_").unwrap_or(rest));
    }
    Some(head_upper)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Whether a file name is an environment file we should import.
pub fn is_env_file(name: &str) -> bool {
    if !(name == ".env" || name.starts_with(".env.") || name == "env" || name.ends_with(".env")) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    !TEMPLATE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Find every environment file under `root`, deepest-last, sorted.
///
/// Symlinked directories are not followed: a `node_modules` symlink into a
/// shared store would otherwise turn a project scan into a filesystem crawl.
pub fn scan(root: &Path) -> Result<Vec<EnvFile>> {
    if !root.is_dir() {
        return Err(Error::NotFound(root.to_path_buf()));
    }

    fn walk(root: &Path, dir: &Path, depth: usize, out: &mut Vec<EnvFile>) -> std::io::Result<()> {
        // Deep enough for a monorepo's packages/*/apps/*, shallow enough that
        // a mistyped root does not scan the whole home directory.
        if depth > 6 {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();

            let meta = entry.metadata()?;
            if meta.is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                walk(root, &path, depth + 1, out)?;
            } else if meta.is_file() && is_env_file(&name) {
                let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                let project = path
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "env".to_owned());
                out.push(EnvFile {
                    project,
                    relative,
                    path: path.clone(),
                    name,
                });
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    walk(root, root, 0, &mut out).map_err(|e| Error::Io {
        path: root.to_path_buf(),
        source: e,
    })?;
    out.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Item construction
// ---------------------------------------------------------------------------

fn field_for(var: &Var) -> Field {
    let kind = if is_secret(&var.key, &var.value) {
        FieldKind::Secret
    } else if var.value.contains("://") {
        FieldKind::Url
    } else if var.value.contains('\n') {
        FieldKind::Note
    } else {
        FieldKind::Text
    };
    Field::new(&var.key, kind, &var.value)
}

fn base_attributes(file: &EnvFile) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("env:project".to_owned(), file.project.clone()),
        ("env:file".to_owned(), file.name.clone()),
        (
            "env:path".to_owned(),
            file.relative.to_string_lossy().into_owned(),
        ),
    ])
}

/// Build the items one environment file contributes under `grouping`.
pub fn items_for(file: &EnvFile, vars: &[Var], grouping: Grouping) -> Vec<Item> {
    if vars.is_empty() {
        return Vec::new();
    }
    let label_for_file = format!("{} ({})", file.project, file.name);

    match grouping {
        Grouping::PerFile => {
            let mut item = Item::new(ItemKind::Environment, label_for_file);
            item.attributes = base_attributes(file);
            item.tags = vec![file.project.clone()];
            for var in vars {
                item = item.with_field(field_for(var));
            }
            vec![item]
        }

        Grouping::PerService => {
            // Preserve file order within each service, and emit services in
            // first-appearance order so the result reads like the file did.
            let mut order: Vec<String> = Vec::new();
            let mut buckets: BTreeMap<String, Vec<&Var>> = BTreeMap::new();
            for var in vars {
                let service = service_of(&var.key).unwrap_or_else(|| "General".to_owned());
                if !buckets.contains_key(&service) {
                    order.push(service.clone());
                }
                buckets.entry(service).or_default().push(var);
            }

            order
                .into_iter()
                .map(|service| {
                    let group = &buckets[&service];
                    let mut item = Item::new(
                        ItemKind::Environment,
                        format!("{} · {}", file.project, service),
                    );
                    item.attributes = base_attributes(file);
                    item.attributes
                        .insert("env:service".to_owned(), service.clone());
                    item.tags = vec![file.project.clone(), service];
                    for var in group {
                        item = item.with_field(field_for(var));
                    }
                    item
                })
                .collect()
        }

        Grouping::PerVariable => vars
            .iter()
            .map(|var| {
                // The variable's own value is the item's secret, so
                // `secret-tool lookup env:key STRIPE_SECRET_KEY` returns it
                // directly and scripts can consume it without a field lookup.
                let mut item = Item::new(
                    ItemKind::Environment,
                    format!("{}: {}", file.project, var.key),
                );
                item.attributes = base_attributes(file);
                item.attributes
                    .insert("env:key".to_owned(), var.key.clone());
                item.secret = var.value.clone().into();
                item.tags = vec![file.project.clone()];
                if let Some(service) = service_of(&var.key) {
                    item.attributes
                        .insert("env:service".to_owned(), service.clone());
                    item.tags.push(service);
                }
                item
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Import every `.env` file under `root` into `vault`. Does not save.
///
/// `into_collection` defaults to `Environment`, keeping development
/// credentials out of the login keyring that browsers and desktop apps read.
pub fn import_dir(
    vault: &mut Vault,
    root: &Path,
    grouping: Grouping,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let files = scan(root)?;
    let target = crate::target_collection(vault, into_collection.unwrap_or("Environment"));
    let mut summary = ImportSummary::default();

    for file in &files {
        let text = match std::fs::read_to_string(&file.path) {
            Ok(t) => t,
            Err(e) => {
                // Unreadable or not UTF-8. Both happen; neither should stop
                // the rest of the scan.
                tracing::warn!("skipping {}: {e}", file.path.display());
                summary.skipped_unreadable += 1;
                continue;
            }
        };

        let vars = parse(&text);
        if vars.is_empty() {
            continue;
        }

        for item in items_for(file, &vars, grouping) {
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
    fn the_common_dotenv_dialect_parses() {
        let vars = parse(
            r#"
# a comment
FOO=bar
export BAZ=qux
QUOTED="hello world"
SINGLE='raw $NOT_EXPANDED'
TRAILING=value # trailing comment
HASH_IN_VALUE=ab#cd
EMPTY=
"#,
        );
        let get = |k: &str| vars.iter().find(|v| v.key == k).map(|v| v.value.as_str());
        assert_eq!(get("FOO"), Some("bar"));
        assert_eq!(get("BAZ"), Some("qux"), "`export ` prefix was not stripped");
        assert_eq!(get("QUOTED"), Some("hello world"));
        assert_eq!(get("SINGLE"), Some("raw $NOT_EXPANDED"));
        assert_eq!(get("TRAILING"), Some("value"));
        assert_eq!(get("HASH_IN_VALUE"), Some("ab#cd"), "a `#` inside a value was eaten");
        assert_eq!(get("EMPTY"), Some(""));
    }

    #[test]
    fn a_quoted_value_may_span_lines() {
        let vars = parse("KEY=\"-----BEGIN KEY-----\nabc\n-----END KEY-----\"\nNEXT=1\n");
        assert_eq!(vars.len(), 2, "the multi-line value swallowed the next key");
        assert!(vars[0].value.contains("\nabc\n"));
        assert_eq!(vars[1].key, "NEXT");
    }

    #[test]
    fn escapes_apply_inside_double_quotes_only() {
        let vars = parse("A=\"a\\nb\"\nB='a\\nb'\n");
        assert_eq!(vars[0].value, "a\nb");
        assert_eq!(vars[1].value, "a\\nb");
    }

    #[test]
    fn credentials_are_recognised_and_config_is_not() {
        assert!(is_secret("STRIPE_SECRET_KEY", "sk_test_abc"));
        assert!(is_secret("DATABASE_URL", "postgres://u:pw@host:5432/db"));
        assert!(is_secret("ANYTHING", "ghp_0123456789abcdef"));
        assert!(is_secret("OPAQUE", "0123456789abcdef0123456789abcdef01"));

        assert!(!is_secret("NODE_ENV", "production"));
        assert!(!is_secret("PORT", "3000"));
        assert!(!is_secret("BASE_URL", "https://example.com"));
        assert!(!is_secret("EMPTY", ""));
    }

    #[test]
    fn a_public_database_url_without_credentials_is_not_flagged() {
        assert!(!is_secret("REDIS_URL", "redis://localhost:6379"));
    }

    #[test]
    fn framework_prefixes_do_not_hide_the_service() {
        assert_eq!(service_of("STRIPE_SECRET_KEY").as_deref(), Some("STRIPE"));
        assert_eq!(
            service_of("NEXT_PUBLIC_SUPABASE_URL").as_deref(),
            Some("SUPABASE")
        );
        assert_eq!(service_of("VITE_SENTRY_DSN").as_deref(), Some("SENTRY"));
        assert_eq!(service_of("PORT"), None);
    }

    #[test]
    fn templates_are_not_imported_but_real_env_files_are() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file(".env.sample"));
        assert!(!is_env_file(".env.template"));
        assert!(!is_env_file("README.md"));
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("project-a");
        std::fs::create_dir_all(a.join("node_modules/dep")).unwrap();
        std::fs::write(a.join(".env"), "STRIPE_SECRET_KEY=sk_test_1\nPORT=3000\n").unwrap();
        std::fs::write(a.join(".env.example"), "STRIPE_SECRET_KEY=changeme\n").unwrap();
        std::fs::write(a.join("node_modules/dep/.env"), "NOISE=1\n").unwrap();

        let b = dir.path().join("project-b");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join(".env.local"), "AWS_ACCESS_KEY_ID=AKIA1\n").unwrap();
        dir
    }

    #[test]
    fn the_scan_skips_vendored_trees_and_templates() {
        let dir = tree();
        let found = scan(dir.path()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|f| f.relative.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["project-a/.env", "project-b/.env.local"]);
        assert_eq!(found[0].project, "project-a");
    }

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let vault =
            Vault::create(&path, "pw", locket_core::crypto::KdfParams::insecure_fast()).unwrap();
        (dir, vault)
    }

    #[test]
    fn per_file_grouping_makes_one_item_per_env_file() {
        let src = tree();
        let (_d, mut v) = vault();
        let s = import_dir(&mut v, src.path(), Grouping::PerFile, None).unwrap();
        assert_eq!(s.imported, 2);

        let item = v
            .data()
            .all_items()
            .map(|(_, i)| i)
            .find(|i| i.label.starts_with("project-a"))
            .expect("project-a was not imported");
        assert_eq!(item.kind, ItemKind::Environment);
        assert_eq!(item.fields.len(), 2, "both variables should be fields");

        let secret = item.fields.iter().find(|f| f.name == "STRIPE_SECRET_KEY").unwrap();
        assert_eq!(secret.kind, FieldKind::Secret);
        let port = item.fields.iter().find(|f| f.name == "PORT").unwrap();
        assert_ne!(port.kind, FieldKind::Secret, "PORT was masked as a secret");
    }

    #[test]
    fn per_variable_grouping_puts_the_value_in_the_secret_service_secret() {
        let src = tree();
        let (_d, mut v) = vault();
        import_dir(&mut v, src.path(), Grouping::PerVariable, None).unwrap();

        let item = v
            .data()
            .all_items()
            .map(|(_, i)| i)
            .find(|i| i.attributes.get("env:key").is_some_and(|k| k == "STRIPE_SECRET_KEY"))
            .expect("no item for STRIPE_SECRET_KEY");
        assert_eq!(item.secret.expose(), "sk_test_1");
        assert_eq!(item.attributes.get("env:service").unwrap(), "STRIPE");
    }

    #[test]
    fn per_service_grouping_splits_a_file_by_vendor() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("app");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(
            p.join(".env"),
            "STRIPE_SECRET_KEY=sk_1\nSTRIPE_WEBHOOK_SECRET=wh_1\nAWS_SECRET_ACCESS_KEY=a\n",
        )
        .unwrap();

        let (_d, mut v) = vault();
        let s = import_dir(&mut v, dir.path(), Grouping::PerService, None).unwrap();
        assert_eq!(s.imported, 2, "expected one item for STRIPE and one for AWS");

        let stripe = v
            .data()
            .all_items()
            .map(|(_, i)| i)
            .find(|i| i.attributes.get("env:service").is_some_and(|s| s == "STRIPE"))
            .unwrap();
        assert_eq!(stripe.fields.len(), 2);
    }

    #[test]
    fn re_running_an_import_does_not_duplicate() {
        let src = tree();
        let (_d, mut v) = vault();
        let first = import_dir(&mut v, src.path(), Grouping::PerFile, None).unwrap();
        let second = import_dir(&mut v, src.path(), Grouping::PerFile, None).unwrap();
        assert_eq!(first.imported, 2);
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 2);
    }

    #[test]
    fn the_source_files_are_left_alone() {
        let src = tree();
        let before = std::fs::read_to_string(src.path().join("project-a/.env")).unwrap();
        let (_d, mut v) = vault();
        import_dir(&mut v, src.path(), Grouping::PerFile, None).unwrap();
        let after = std::fs::read_to_string(src.path().join("project-a/.env")).unwrap();
        assert_eq!(before, after, "the importer modified the source file");
    }
}
