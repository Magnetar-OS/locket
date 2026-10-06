//! Exporting the vault — the way *out*.
//!
//! A password manager you cannot leave is a trap, so leaving is as supported
//! as arriving, in three shapes:
//!
//! - **JSON** (`locket-export-v1`): every item's secret, attributes, fields,
//!   tags, favourite flag, expiry and attachments (as base64). Not written:
//!   the secret's content type, the created and modified times, and revision
//!   history. Plaintext, and nothing in locket reads it back in.
//! - **CSV**: the lowest common denominator every manager imports. Columns
//!   follow Bitwarden's naming, which the CSV *importers* of other managers
//!   (ours included) all recognise. Loses custom structure; says so.
//! - **KDBX 4**: a real encrypted database KeePass and KeePassXC open
//!   directly. The one export that is not plaintext — it is sealed under a
//!   passphrase the caller supplies.
//!
//! The plaintext formats are the most dangerous files on the disk while they
//! exist. Writing them 0600 and telling the user to delete them is the
//! callers' contract, same as the importers' warnings in the other
//! direction.
//!
//! Every format is written through [`write_file`]: complete and synced
//! beside its destination, then moved into place. An export that fails
//! leaves no part of itself behind.

use std::path::Path;

use locket_core::{Vault, model::field_names};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Csv,
    Kdbx,
}

impl Format {
    pub fn is_plaintext(self) -> bool {
        !matches!(self, Format::Kdbx)
    }
}

/// What an export does about a file already at its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refuse, and leave that file as it is. For a path somebody typed.
    Refuse,
    /// Replace it, once the new file is complete. For a path a save dialog
    /// has already asked about.
    Replace,
}

fn io_at(path: &Path) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.to_path_buf();
    move |source| Error::Io { path, source }
}

/// Create `path` refusing to overwrite, 0600 before any content reaches it.
fn create_0600(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path).map_err(io_at(path))
}

/// Where an export to `path` is written until it is complete.
fn part_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    path.with_file_name(name)
}

/// Write a file whole or not at all: `write` fills a 0600 file beside `path`,
/// which is synced and only then moved into place.
///
/// Every file locket writes out of the vault comes through here. A write that
/// stops half-way — a full disk, a stick pulled out — leaves nothing at
/// `path` that was not there before, and removes what it had written: half a
/// plaintext export is still every secret it got to, half a KDBX is a
/// database nothing can open under the name of the backup, and with
/// [`Existing::Replace`] the file being replaced is lost only once its
/// successor is complete.
///
/// The file is written as `<name>.part`. One left there by a run that was
/// killed is removed first; it is never anything a person chose.
pub fn write_file(
    path: &Path,
    existing: Existing,
    write: impl FnOnce(&mut dyn std::io::Write) -> Result<()>,
) -> Result<()> {
    // Asked again when the file is moved into place; asked here so that a
    // name already taken is refused before any work is done for it.
    if existing == Existing::Refuse && path.symlink_metadata().is_ok() {
        return Err(io_at(path)(std::io::ErrorKind::AlreadyExists.into()));
    }

    let part = part_path(path);
    match std::fs::remove_file(&part) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_at(&part)(e)),
    }
    let mut file = create_0600(&part)?;
    let filled = write(&mut file).and_then(|()| file.sync_all().map_err(io_at(&part)));
    drop(file);

    let Err(error) = filled.and_then(|()| move_into_place(&part, path, existing)) else {
        return Ok(());
    };
    match std::fs::remove_file(&part) {
        Ok(()) => Err(error),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(error),
        Err(e) => Err(io_at(&part)(std::io::Error::new(
            e.kind(),
            format!("{error}; and the partly written file could not be removed: {e}"),
        ))),
    }
}

/// Give the finished file its name.
fn move_into_place(part: &Path, path: &Path, existing: Existing) -> Result<()> {
    if existing == Existing::Refuse {
        // A rename replaces whatever holds the name, and the form that does
        // not is beyond FAT and exFAT — a USB stick. Creating the name
        // exclusively works everywhere and fails if anything is there, so
        // what the rename then replaces is this empty file and nothing else.
        drop(create_0600(path)?);
    }
    let Err(e) = std::fs::rename(part, path) else {
        return Ok(());
    };
    if existing == Existing::Refuse {
        // The name was only reserved a moment ago, by the line above.
        let _ = std::fs::remove_file(path);
    }
    Err(io_at(path)(e))
}

/// [`write_file`] for bytes already in hand: an attachment saved out of the
/// vault.
pub fn write_bytes(path: &Path, existing: Existing, data: &[u8]) -> Result<()> {
    write_file(path, existing, |out| {
        out.write_all(data).map_err(io_at(path))
    })
}

/// Everything, as JSON. Returns how many items were written.
pub fn to_json(vault: &Vault, path: &Path, existing: Existing) -> Result<usize> {
    let mut count = 0;
    write_file(path, existing, |out| {
        count = json_into(vault, out, path)?;
        Ok(())
    })?;
    Ok(count)
}

fn json_into(vault: &Vault, out: &mut dyn std::io::Write, path: &Path) -> Result<usize> {
    let mut items = Vec::new();
    for (collection, item) in vault.data().all_items() {
        items.push(serde_json::json!({
            "collection": collection.label,
            "id": item.id,
            "kind": item.kind,
            "label": item.label,
            "secret": item.secret.expose(),
            "attributes": item.attributes,
            "tags": item.tags,
            "favorite": item.favorite,
            "expires": item.expires.map(locket_core::model::format_date),
            "fields": item.fields.iter().map(|f| serde_json::json!({
                "name": f.name,
                "kind": f.kind,
                "value": f.value.expose(),
            })).collect::<Vec<_>>(),
            "attachments": item.attachments.iter().map(|a| serde_json::json!({
                "name": a.name,
                "mime": a.mime,
                "data_base64": locket_core::slots::base64_encode(a.data.expose()),
            })).collect::<Vec<_>>(),
        }));
    }
    let count = items.len();
    let document = serde_json::json!({
        "format": "locket-export-v1",
        "items": items,
    });

    let bytes = serde_json::to_vec_pretty(&document).map_err(|e| Error::Vault(e.to_string()))?;
    out.write_all(&bytes).map_err(io_at(path))?;
    Ok(count)
}

/// The flat CSV, Bitwarden's column names. Returns `(written, lossy)`:
/// `lossy` counts items that had fields or attachments CSV cannot carry.
pub fn to_csv(vault: &Vault, path: &Path, existing: Existing) -> Result<(usize, usize)> {
    let mut written = 0usize;
    let mut lossy = 0usize;
    write_file(path, existing, |out| {
        csv_into(vault, out, path, &mut written, &mut lossy)
    })?;
    Ok((written, lossy))
}

fn csv_into(
    vault: &Vault,
    out: &mut dyn std::io::Write,
    path: &Path,
    written: &mut usize,
    lossy: &mut usize,
) -> Result<()> {
    let mut writer = csv::Writer::from_writer(out);
    writer
        .write_record([
            "folder",
            "favorite",
            "type",
            "name",
            "notes",
            "login_uri",
            "login_username",
            "login_password",
            "login_totp",
        ])
        .map_err(|e| Error::Vault(e.to_string()))?;

    for (collection, item) in vault.data().all_items() {
        let notes = item.field_value(field_names::NOTES).unwrap_or_default();
        let carried: &[&str] = &[
            field_names::USERNAME,
            field_names::URL,
            field_names::TOTP,
            field_names::NOTES,
        ];
        if !item.attachments.is_empty()
            || item
                .fields
                .iter()
                .any(|f| !carried.contains(&f.name.as_str()))
        {
            *lossy += 1;
        }
        writer
            .write_record([
                collection.label.as_str(),
                if item.favorite { "1" } else { "" },
                "login",
                item.label.as_str(),
                notes,
                item.field_value(field_names::URL).unwrap_or_default(),
                item.field_value(field_names::USERNAME).unwrap_or_default(),
                item.secret.expose(),
                item.field_value(field_names::TOTP).unwrap_or_default(),
            ])
            .map_err(|e| Error::Vault(e.to_string()))?;
        *written += 1;
    }
    writer.flush().map_err(io_at(path))
}

/// A KDBX 4 database KeePassXC opens directly, sealed under `passphrase`.
/// One top-level group per collection; tags, TOTP seeds and custom fields
/// carried; field protection mirrors locket's own masking.
pub fn to_kdbx(vault: &Vault, path: &Path, passphrase: &str, existing: Existing) -> Result<usize> {
    if passphrase.is_empty() {
        return Err(Error::Vault(
            "a KDBX export needs a passphrase; it is the whole point of the format".into(),
        ));
    }
    let mut written = 0;
    write_file(path, existing, |out| {
        written = kdbx_into(vault, passphrase, out)?;
        Ok(())
    })?;
    Ok(written)
}

fn kdbx_into(vault: &Vault, passphrase: &str, mut out: &mut dyn std::io::Write) -> Result<usize> {
    use keepass::{Database, DatabaseKey, config::KdfConfig};

    let mut db = Database::new();
    db.root_mut().name = "locket".to_owned();
    // The crate's default derivation is Argon2d over 1 MiB, far cheaper to
    // guess against than the vault this came from. The file is meant to
    // leave the machine, so it gets the vault's own default cost.
    let cost = locket_core::crypto::KdfParams::default();
    if let KdfConfig::Argon2 {
        iterations,
        memory,
        parallelism,
        ..
    } = &mut db.config.kdf_config
    {
        *memory = u64::from(cost.m_cost) * 1024;
        *iterations = u64::from(cost.t_cost);
        *parallelism = cost.p_cost;
    }

    let mut written = 0usize;
    for collection in &vault.data().collections {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = collection.label.clone();
        for item in &collection.items {
            let mut entry = group.add_entry();
            entry.set_unprotected("Title", item.label.clone());
            entry.set_protected("Password", item.secret.expose());
            if let Some(username) = item.field_value(field_names::USERNAME) {
                entry.set_unprotected("UserName", username);
            }
            if let Some(url) = item.field_value(field_names::URL) {
                entry.set_unprotected("URL", url);
            }
            if let Some(notes) = item.field_value(field_names::NOTES) {
                entry.set_unprotected("Notes", notes);
            }
            if let Some(totp) = item.field_value(field_names::TOTP) {
                // The field KeePassXC reads its TOTP configuration from.
                entry.set_protected("otp", totp);
            }
            let standard = [
                field_names::USERNAME,
                field_names::URL,
                field_names::NOTES,
                field_names::TOTP,
            ];
            for field in &item.fields {
                if standard.contains(&field.name.as_str()) {
                    continue;
                }
                // A custom field named like one of kdbx's own would replace
                // that value — `Password` overwrote the item's secret — so
                // it is written under a name of its own.
                let name = if crate::keepass::STANDARD_FIELDS.contains(&field.name.as_str()) {
                    format!("{} (custom)", field.name)
                } else {
                    field.name.clone()
                };
                // Mirror locket's own masking onto kdbx's protection flag.
                if field.kind.is_sensitive() {
                    entry.set_protected(name, field.value.expose());
                } else {
                    entry.set_unprotected(name, field.value.expose());
                }
            }
            entry.tags = item.tags.clone();
            written += 1;
        }
    }

    db.save(&mut out, DatabaseKey::new().with_password(passphrase))
        .map_err(|e| Error::Database(format!("could not write the kdbx: {e}")))?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::{Field, FieldKind, Item, ItemKind, crypto::KdfParams};

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut v =
            Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let mut item = Item::new(ItemKind::Login, "GitHub")
            .with_secret("hunter2")
            .with_field(Field::text(field_names::USERNAME, "ada"))
            .with_field(Field::new(
                field_names::TOTP,
                FieldKind::Totp,
                "otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP",
            ))
            .with_field(Field::secret("recovery", "codes"));
        item.tags = vec!["work".into()];
        v.add_item_default(item);
        v.add_item_default(Item::new(ItemKind::Note, "Plain note").with_secret("body"));
        v
    }

    /// A writer that takes so many bytes and then fails the way a full disk
    /// does.
    struct FullAfter<'a> {
        out: &'a mut dyn std::io::Write,
        room: usize,
    }

    impl std::io::Write for FullAfter<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.room == 0 {
                return Err(std::io::ErrorKind::StorageFull.into());
            }
            let n = self.out.write(&buf[..buf.len().min(self.room)])?;
            self.room -= n;
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.out.flush()
        }
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Each format, with the disk "filling up" after its first bytes are
    /// down. A KDBX export used to be written straight to its name and left
    /// there cut short: an encrypted database nothing could open, called
    /// what the backup was to be called.
    #[test]
    fn an_export_that_fails_part_way_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out_dir = dir.path().join("out");
        std::fs::create_dir(&out_dir).unwrap();

        type Exporter = fn(&Vault, &mut dyn std::io::Write, &Path) -> Result<()>;
        let formats: [(&str, Exporter); 3] = [
            ("export.kdbx", |v, out, _| {
                kdbx_into(v, "kdbx-pw", out).map(drop)
            }),
            ("export.json", |v, out, path| {
                json_into(v, out, path).map(drop)
            }),
            ("export.csv", |v, out, path| {
                csv_into(v, out, path, &mut 0, &mut 0)
            }),
        ];
        for (name, export) in formats {
            let path = out_dir.join(name);
            let mut reached_the_disk = false;
            let result = write_file(&path, Existing::Refuse, |out| {
                let mut full = FullAfter { out, room: 24 };
                let result = export(&v, &mut full, &path);
                reached_the_disk = full.room == 0;
                result
            });
            assert!(result.is_err(), "{name}: the failed write went unreported");
            assert!(
                reached_the_disk,
                "{name}: nothing was written before it failed"
            );
            assert_eq!(names_in(&out_dir), [""; 0], "{name}: left behind");

            // And the name is free for the next attempt.
            write_file(&path, Existing::Refuse, |out| export(&v, out, &path)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
            std::fs::remove_file(&path).unwrap();
        }
    }

    /// A save dialog lets the person pick a file that exists, and has asked
    /// about replacing it. That file must outlive an export that fails, and
    /// its permissions must not be the new file's: a decrypted attachment
    /// written over a 0644 file used to stay 0644.
    #[test]
    fn replacing_keeps_the_old_file_until_the_new_one_is_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.kdbx");
        std::fs::write(&path, b"last week's backup").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let failed = write_file(&path, Existing::Replace, |out| {
            out.write_all(b"half an export").unwrap();
            Err(Error::Vault("the disk filled up".into()))
        });
        assert!(failed.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"last week's backup");
        assert_eq!(names_in(dir.path()), ["backup.kdbx"]);

        write_bytes(&path, Existing::Replace, b"this week's").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"this week's");
        assert_eq!(
            names_in(dir.path()),
            ["backup.kdbx"],
            "debris left beside it"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "written with mode {mode:o}");
        }
    }

    /// Refusing to overwrite has to hold when the file turns up while the
    /// export is being written, not only when it was there at the start.
    #[test]
    fn a_file_that_appears_meanwhile_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");

        let result = write_file(&path, Existing::Refuse, |out| {
            std::fs::write(&path, b"somebody else's").unwrap();
            out.write_all(b"ours").map_err(io_at(&path))
        });
        assert!(result.is_err(), "replaced a file it was to refuse");
        assert_eq!(std::fs::read(&path).unwrap(), b"somebody else's");
        assert_eq!(names_in(dir.path()), ["export.json"]);

        assert!(write_bytes(&path, Existing::Refuse, b"ours").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"somebody else's");
    }

    /// What a killed export leaves is its `.part`, which must not stop the
    /// next one.
    #[test]
    fn a_part_file_left_by_a_killed_export_is_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(dir.path().join("export.csv.part"), b"half of everything").unwrap();

        write_bytes(&path, Existing::Refuse, b"whole").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"whole");
        assert_eq!(names_in(dir.path()), ["export.csv"]);
    }

    #[test]
    fn json_round_trips_and_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.json");
        assert_eq!(to_json(&v, &out, Existing::Refuse).unwrap(), 2);

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(parsed["format"], "locket-export-v1");
        assert_eq!(parsed["items"].as_array().unwrap().len(), 2);

        assert!(
            to_json(&v, &out, Existing::Refuse).is_err(),
            "overwrote an existing export"
        );
    }

    #[test]
    fn csv_counts_what_it_could_not_carry() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.csv");
        let (written, lossy) = to_csv(&v, &out, Existing::Refuse).unwrap();
        assert_eq!(written, 2);
        assert_eq!(lossy, 1, "the custom `recovery` field went uncounted");

        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.starts_with("folder,favorite,type,name,notes,login_uri"));
        assert!(text.contains("hunter2"));
    }

    /// The keepass crate's default key derivation is Argon2d over 1 MiB,
    /// far cheaper to guess against than the vault the export came from.
    #[test]
    fn a_kdbx_export_costs_as_much_to_open_as_the_vault() {
        use keepass::{Database, DatabaseKey, config::KdfConfig};

        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.kdbx");
        to_kdbx(&v, &out, "kdbx-pw", Existing::Refuse).unwrap();

        let db = Database::open(
            &mut std::fs::File::open(&out).unwrap(),
            DatabaseKey::new().with_password("kdbx-pw"),
        )
        .unwrap();
        let vault_cost = KdfParams::default();
        match db.config.kdf_config {
            KdfConfig::Argon2 {
                memory,
                iterations,
                parallelism,
                ..
            }
            | KdfConfig::Argon2id {
                memory,
                iterations,
                parallelism,
                ..
            } => {
                assert!(
                    memory >= u64::from(vault_cost.m_cost) * 1024,
                    "{memory} bytes"
                );
                assert!(iterations >= u64::from(vault_cost.t_cost));
                assert_eq!(parallelism, vault_cost.p_cost);
            }
            other => panic!("not an Argon2 key derivation: {other:?}"),
        }
    }

    /// KeePass allows two entries with one title in one group. With no
    /// username they had the same attributes, and the second password was
    /// reported "already present" and lost. Each entry's own UUID now tells
    /// them apart, and a second import of the file still skips both.
    #[test]
    fn two_kdbx_entries_with_one_title_both_import() {
        let dir = tempfile::tempdir().unwrap();
        let mut v =
            Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        v.add_item_default(Item::new(ItemKind::Login, "Router").with_secret("first"));
        v.add_item_default(Item::new(ItemKind::Login, "Router").with_secret("second"));
        let out = dir.path().join("export.kdbx");
        to_kdbx(&v, &out, "kdbx-pw", Existing::Refuse).unwrap();

        let mut target =
            Vault::create(dir.path().join("t.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let first = crate::keepass::import_kdbx(&mut target, &out, "kdbx-pw", None, None).unwrap();
        assert_eq!(first.imported, 2);
        let second = crate::keepass::import_kdbx(&mut target, &out, "kdbx-pw", None, None).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 2);

        // A vault that imported this file before the UUID was recorded holds
        // the entries without it; they are still recognised.
        let mut earlier =
            Vault::create(dir.path().join("e.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let mut legacy = target.data().all_items().next().unwrap().1.clone();
        legacy.attributes.remove("keepass:uuid");
        earlier.add_item_default(legacy);
        let again = crate::keepass::import_kdbx(&mut earlier, &out, "kdbx-pw", None, None).unwrap();
        assert_eq!(again.imported, 1);
        assert_eq!(again.skipped_duplicate, 1);
    }

    /// Our own CSV has to come back through our own CSV importer as it went
    /// out: the `favorite` and `type` columns used to arrive as custom
    /// fields on every item, and favourites lost their flag.
    #[test]
    fn our_own_csv_round_trips_without_junk_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut v =
            Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let mut item = Item::new(ItemKind::Login, "GitHub")
            .with_secret("hunter2")
            .with_field(Field::text(field_names::USERNAME, "ada"));
        item.favorite = true;
        v.add_item_default(item);
        let out = dir.path().join("export.csv");
        to_csv(&v, &out, Existing::Refuse).unwrap();

        let mut target =
            Vault::create(dir.path().join("t.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        crate::csv::import_file(&mut target, &out, None).unwrap();
        let (_, back) = target
            .data()
            .all_items()
            .find(|(_, i)| i.label == "GitHub")
            .unwrap();
        assert!(back.favorite, "the favourite flag was lost");
        assert!(back.field("type").is_none(), "`type` became a field");
        assert!(
            back.field("favorite").is_none(),
            "`favorite` became a field"
        );
    }

    /// A custom field named like one of kdbx's own (`Password`, `Title`, …)
    /// overwrote that value in the export, and the importer never read
    /// kdbx tags back, so a round trip lost both.
    #[test]
    fn a_kdbx_round_trip_keeps_the_secret_and_the_tags() {
        let dir = tempfile::tempdir().unwrap();
        let mut v =
            Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let mut item = Item::new(ItemKind::Login, "GitHub")
            .with_secret("real")
            .with_field(Field::text("Password", "other"));
        item.tags = vec!["work".into()];
        v.add_item_default(item);
        let out = dir.path().join("export.kdbx");
        to_kdbx(&v, &out, "kdbx-pw", Existing::Refuse).unwrap();

        let mut target =
            Vault::create(dir.path().join("t.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        crate::keepass::import_kdbx(&mut target, &out, "kdbx-pw", None, None).unwrap();
        let (_, back) = target.data().all_items().next().unwrap();
        assert_eq!(back.label, "GitHub");
        assert_eq!(
            back.secret.expose(),
            "real",
            "a custom field overwrote the password"
        );
        assert!(
            back.fields.iter().any(|f| f.value.expose() == "other"),
            "the custom field was lost"
        );
        assert!(back.tags.contains(&"work".to_owned()), "{:?}", back.tags);
    }

    /// A vault that imported a KeePass database before entries carried
    /// their UUID holds the entry without one. If its password has changed
    /// since, re-importing used to add it a second time; it is the same
    /// entry, and it gains the UUID it was missing.
    #[test]
    fn an_entry_imported_before_uuids_is_found_even_after_a_password_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut v =
            Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        v.add_item_default(
            Item::new(ItemKind::Login, "GitHub")
                .with_secret("new")
                .with_field(Field::text(field_names::USERNAME, "ada")),
        );
        let out = dir.path().join("export.kdbx");
        to_kdbx(&v, &out, "kdbx-pw", Existing::Refuse).unwrap();

        // What the importer made of this entry before it recorded UUIDs, with
        // the password it had then.
        let mut scratch =
            Vault::create(dir.path().join("s.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        crate::keepass::import_kdbx(&mut scratch, &out, "kdbx-pw", None, None).unwrap();
        let mut earlier_item = scratch.data().all_items().next().unwrap().1.clone();
        let uuid = earlier_item.attributes.remove("keepass:uuid").unwrap();
        earlier_item.secret = "old".into();

        let mut earlier =
            Vault::create(dir.path().join("e.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let id = earlier.add_item_default(earlier_item);
        let summary =
            crate::keepass::import_kdbx(&mut earlier, &out, "kdbx-pw", None, None).unwrap();
        assert_eq!(summary.imported, 0, "the entry was imported a second time");
        assert_eq!(summary.skipped_duplicate, 1);
        assert_eq!(earlier.data().item_count(), 1);
        assert_eq!(
            earlier.item(id).unwrap().attributes.get("keepass:uuid"),
            Some(&uuid),
            "the existing item did not gain its UUID"
        );
    }

    #[test]
    fn kdbx_seals_and_reopens_with_everything_that_fits() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.kdbx");
        assert_eq!(to_kdbx(&v, &out, "kdbx-pw", Existing::Refuse).unwrap(), 2);

        // No plaintext on disk: it is a real encrypted database.
        let raw = std::fs::read(&out).unwrap();
        let raw_text = String::from_utf8_lossy(&raw);
        assert!(!raw_text.contains("hunter2"), "the kdbx leaked a secret");
        assert!(!raw_text.contains("GitHub"), "the kdbx leaked a title");

        // And our own importer — the same library KeePassXC's format
        // implements — reads it back whole.
        let vault2_path = dir.path().join("reimported.vault");
        let mut vault2 = Vault::create(&vault2_path, "pw", KdfParams::insecure_fast()).unwrap();
        let summary =
            crate::keepass::import_kdbx(&mut vault2, &out, "kdbx-pw", None, None).unwrap();
        assert_eq!(summary.imported, 2);
        let (_, item) = vault2
            .data()
            .all_items()
            .find(|(_, i)| i.label == "GitHub")
            .expect("the login survived the round trip");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        assert!(
            item.field(field_names::TOTP).is_some(),
            "the TOTP seed was lost"
        );
        assert_eq!(
            item.field("recovery").map(|f| f.kind),
            Some(FieldKind::Secret),
            "field protection did not survive"
        );

        assert!(
            to_kdbx(&v, &dir.path().join("x.kdbx"), "", Existing::Refuse).is_err(),
            "an empty kdbx passphrase was accepted"
        );
    }
}
