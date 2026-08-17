//! `passman-cli` — scriptable access to a passman vault.
//!
//! Operates directly on the vault file. It deliberately does not talk to
//! `passmand`, so it keeps working for recovery when the daemon will not start.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use passman_core::{
    Vault,
    crypto::KdfParams,
    generator::{self, PasswordRecipe},
    model::{Field, Item, ItemKind, field_names},
};

#[derive(Parser)]
#[command(name = "passman-cli", version, about = "passman command line interface")]
struct Args {
    /// Vault file. Defaults to $XDG_DATA_HOME/passman/default.vault
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    /// Read the passphrase from this environment variable instead of the tty.
    #[arg(long, global = true, value_name = "VAR")]
    passphrase_env: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault.
    Init,
    /// List items, optionally filtered.
    List {
        /// Substring match on label, tags and non-secret fields.
        query: Option<String>,
        /// Emit JSON metadata (never secret values).
        #[arg(long)]
        json: bool,
    },
    /// Print one item's secret to stdout.
    Get {
        /// Label or id, matched case-insensitively.
        query: String,
        /// Print a named field instead of the primary secret.
        #[arg(long)]
        field: Option<String>,
    },
    /// Add a login.
    Add {
        label: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Generate the password instead of prompting for it.
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: usize,
    },
    /// Change an item in place.
    ///
    /// Every part is optional; what you do not name is left alone. This is the
    /// recovery-shaped counterpart to the GUI editor — enough to fix a wrong
    /// username or rotate a password from a terminal, without a mouse.
    Edit {
        /// Label or id, matched case-insensitively.
        query: String,
        /// New label.
        #[arg(long)]
        label: Option<String>,
        /// Replace the primary secret. Prompts unless --generate is given.
        #[arg(long)]
        secret: bool,
        /// Generate the new secret instead of prompting for it.
        #[arg(long, requires = "secret")]
        generate: bool,
        #[arg(long, default_value_t = 20, requires = "generate")]
        length: usize,
        /// Set a field: `--set username=ada`. Repeatable.
        #[arg(long, value_name = "NAME=VALUE")]
        set: Vec<String>,
        /// Remove a field by name. Repeatable.
        #[arg(long, value_name = "NAME")]
        unset: Vec<String>,
        /// Mark or unmark as a favourite.
        #[arg(long)]
        favorite: Option<bool>,
    },

    /// Delete an item.
    Rm {
        /// Label or id, matched case-insensitively.
        query: String,
        /// Do not ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },

    /// List the vault's unlock factors.
    Slots,
    /// Import every readable secret from a running Secret Service.
    ///
    /// Reads from gnome-keyring by default. Idempotent: an item whose
    /// attributes already exist in the vault is skipped, so re-running after
    /// adding a few secrets does not duplicate anything.
    Import {
        /// Bus name to read from.
        #[arg(long, default_value = "org.freedesktop.secrets")]
        from: String,
        /// Put everything in one named collection instead of mirroring the
        /// source's layout.
        #[arg(long)]
        into: Option<String>,
        /// Report what would be imported without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Overwrite items the vault already holds instead of skipping them.
        ///
        /// The way out of a bad import: the attributes match, but the secret
        /// in the vault is not the secret the source has.
        #[arg(long)]
        replace: bool,
    },
    /// Import a `pass` (password-store) tree.
    ImportPass {
        /// Store directory. Defaults to $PASSWORD_STORE_DIR or ~/.password-store
        #[arg(long)]
        store: Option<PathBuf>,
        /// gpg binary to decrypt with.
        #[arg(long, default_value = "gpg")]
        gpg: String,
        #[arg(long)]
        into: Option<String>,
    },
    /// Import a KeePass/KeePassXC `.kdbx` database.
    ImportKeepass {
        /// Path to the .kdbx file.
        database: PathBuf,
        /// Read the database password from this environment variable.
        #[arg(long, value_name = "VAR")]
        db_passphrase_env: Option<String>,
        /// Optional key file.
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        into: Option<String>,
    },
    /// Import a browser/manager CSV export.
    ///
    /// Understands Chrome, Edge, Brave, Firefox, Safari, Bitwarden, 1Password
    /// and KeePassXC exports by matching column aliases rather than guessing a
    /// dialect, so a renamed column does not break the import.
    ImportCsv {
        /// The exported .csv file.
        file: PathBuf,
        #[arg(long)]
        into: Option<String>,
    },
    /// Import `.env` files from a tree of projects.
    ///
    /// Walks the directory, skipping `node_modules`, `target`, `.git` and
    /// friends, and ignoring `.env.example`-style templates. Source files are
    /// never modified — the project still needs them until it reads its
    /// configuration from passman instead.
    ImportEnv {
        /// Directory to scan, e.g. ~/GitHub
        dir: PathBuf,
        /// How to slice variables into items.
        #[arg(long, value_enum, default_value_t = EnvGrouping::File)]
        group_by: EnvGrouping,
        /// List what would be imported without opening the vault.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        into: Option<String>,
    },
    /// Import SSH private keys so the built-in agent can serve them.
    ///
    /// Your key files are copied, not moved: OpenSSH keeps reading them and
    /// nothing breaks if you decide against this.
    ImportSsh {
        /// Directory to scan. Defaults to ~/.ssh
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        into: Option<String>,
    },
    /// Import credentials the aws, gcloud, az, gh, docker and npm CLIs leave
    /// unencrypted in your home directory.
    ImportCloud {
        /// Home directory to scan. Defaults to yours.
        #[arg(long)]
        home: Option<PathBuf>,
        /// Binary used to read gcloud's SQLite store.
        #[arg(long, default_value = "sqlite3")]
        sqlite: String,
        /// List what would be imported without opening the vault.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        into: Option<String>,
    },
    /// Import TOTP seeds from an authenticator export.
    ///
    /// Accepts a list of `otpauth://` URIs, or a plain-text Aegis or andOTP
    /// export. Encrypted backups are refused rather than half-read.
    ImportTotp {
        /// The export file.
        file: PathBuf,
        #[arg(long)]
        into: Option<String>,
    },
    /// Change the vault's passphrase.
    ///
    /// Rewraps the data-encryption key under a key derived from the new
    /// passphrase; the vault body is not re-encrypted, so this is fast even on
    /// a large vault. Every other unlock factor keeps working.
    Passwd {
        /// Read the new passphrase from this environment variable instead of
        /// the tty.
        #[arg(long, value_name = "VAR")]
        new_passphrase_env: Option<String>,
    },

    /// Write every item, secrets included, to a plaintext file.
    ///
    /// The way *out*. A password manager you cannot leave is a trap, and the
    /// only honest export is the one that includes the secrets — so this
    /// writes 0600 and tells you to delete it, exactly as the importers say
    /// about the files they read.
    Export {
        /// Where to write. Refused if it already exists.
        file: PathBuf,
        /// Required, so nobody produces a plaintext copy of every credential
        /// they own by tab-completing their way through `--help`.
        #[arg(long)]
        i_understand_this_is_plaintext: bool,
    },

    /// Generate a password without storing it.
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Generation needs no vault, so handle it before asking for a passphrase.
    if let Command::Generate { length, no_symbols } = &args.command {
        let recipe = PasswordRecipe {
            length: *length,
            symbols: !no_symbols,
            ..Default::default()
        };
        let pw = generator::password(&recipe)?;
        eprintln!("~{:.0} bits of entropy", recipe.entropy_bits());
        println!("{}", pw.expose());
        return Ok(());
    }

    if let Command::ImportCloud {
        home, dry_run: true, ..
    } = &args.command
    {
        let home = match home.clone().or_else(passman_import::cloud::home) {
            Some(h) => h,
            None => return Err("cannot find your home directory".into()),
        };
        let found = passman_import::cloud::scan(&home);
        if found.is_empty() {
            println!("no known credential stores under {}", home.display());
        }
        for f in &found {
            println!("{:<20} {}", f.store.label(), f.path.display());
        }
        return Ok(());
    }

    // Likewise a dry-run scan: it reads .env files but never the vault, so it
    // is safe to point at a directory you are not sure about.
    if let Command::ImportEnv {
        dir, dry_run: true, ..
    } = &args.command
    {
        let files = passman_import::dotenv::scan(dir)?;
        let (mut vars, mut secrets) = (0usize, 0usize);
        for f in &files {
            let text = std::fs::read_to_string(&f.path).unwrap_or_default();
            let parsed = passman_import::dotenv::parse(&text);
            let s = parsed
                .iter()
                .filter(|v| passman_import::dotenv::is_secret(&v.key, &v.value))
                .count();
            vars += parsed.len();
            secrets += s;
            println!("{:<56} {:>3} vars, {:>3} secret", f.relative.display(), parsed.len(), s);
        }
        println!(
            "\n{} file(s), {vars} variable(s), {secrets} credential(s) under {}",
            files.len(),
            dir.display()
        );
        return Ok(());
    }

    let path = match args.vault {
        Some(p) => p,
        None => Vault::default_path()?,
    };
    let passphrase = match &args.passphrase_env {
        Some(var) => {
            std::env::var(var).map_err(|_| format!("environment variable `{var}` is not set"))?
        }
        None => rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))?,
    };

    match args.command {
        Command::Generate { .. } => unreachable!("handled above"),

        Command::Init => {
            if path.exists() {
                return Err(format!("{} already exists", path.display()).into());
            }
            let vault = Vault::create(&path, &passphrase, KdfParams::default())?;
            println!("created {}", vault.path().display());
        }

        Command::List { query, json } => {
            let vault = Vault::open(&path, &passphrase)?;
            let needle = query.unwrap_or_default();
            let mut found = 0;
            for (collection, item) in vault.data().all_items() {
                if !item.matches(&needle) {
                    continue;
                }
                found += 1;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "id": item.id,
                            "collection": collection.label,
                            "label": item.label,
                            "kind": item.kind,
                            "subtitle": item.subtitle(),
                            "favorite": item.favorite,
                            "attributes": item.attributes,
                        })
                    );
                } else {
                    println!(
                        "{}  {:<28} {:<16} {}",
                        if item.favorite { "*" } else { " " },
                        item.label,
                        item.kind.label(),
                        item.subtitle()
                    );
                }
            }
            if found == 0 {
                eprintln!("no matching items");
                std::process::exit(1);
            }
        }

        Command::Get { query, field } => {
            let vault = Vault::open(&path, &passphrase)?;
            let needle = query.to_lowercase();
            let item = vault
                .data()
                .all_items()
                .map(|(_, i)| i)
                .find(|i| {
                    i.label.to_lowercase() == needle || i.id.to_string() == needle
                })
                .or_else(|| {
                    vault
                        .data()
                        .all_items()
                        .map(|(_, i)| i)
                        .find(|i| i.matches(&query))
                })
                .ok_or_else(|| format!("no item matching `{query}`"))?;

            match field {
                Some(name) => {
                    let value = item
                        .field_value(&name)
                        .ok_or_else(|| format!("item `{}` has no field `{name}`", item.label))?;
                    println!("{value}");
                }
                None => println!("{}", item.secret.expose()),
            }
        }

        Command::Edit {
            query,
            label,
            secret,
            generate,
            length,
            set,
            unset,
            favorite,
        } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let id = find_item(&vault, &query)?;

            // Read the new secret before taking the mutable borrow, so a
            // mistyped prompt cannot leave a half-applied edit behind.
            let new_secret = if secret {
                if generate {
                    let recipe = PasswordRecipe {
                        length,
                        ..Default::default()
                    };
                    let pw = generator::password(&recipe)?;
                    eprintln!("generated a {length}-character secret");
                    Some(pw.expose().to_owned())
                } else {
                    Some(rpassword::prompt_password("New secret: ")?)
                }
            } else {
                None
            };

            let mut fields = Vec::new();
            for pair in &set {
                let (name, value) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("--set wants NAME=VALUE, got `{pair}`"))?;
                if name.is_empty() {
                    return Err("--set needs a field name".into());
                }
                // Anything that looks like a credential is stored masked, the
                // same way the importers classify what they read.
                let kind = if passman_import::dotenv::is_secret(name, value) {
                    passman_core::model::FieldKind::Secret
                } else {
                    passman_core::model::FieldKind::Text
                };
                fields.push(Field::new(name, kind, value));
            }

            let item = vault
                .item_mut(id)
                .ok_or("the item vanished between finding and editing it")?;
            if let Some(label) = &label {
                item.label = label.clone();
            }
            if let Some(value) = new_secret {
                item.secret = passman_core::secret::SecretString::new(value);
            }
            for field in fields {
                item.set_field(field);
            }
            for name in &unset {
                item.fields.retain(|f| &f.name != name);
            }
            if let Some(favorite) = favorite {
                item.favorite = favorite;
            }
            item.touch();
            let label = item.label.clone();

            vault.save()?;
            println!("updated {label}");
        }

        Command::Rm { query, yes } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let id = find_item(&vault, &query)?;
            let label = vault
                .item(id)
                .map(|i| i.label.clone())
                .unwrap_or_else(|| query.clone());

            if !yes {
                eprint!("Delete `{label}`? This cannot be undone. [y/N] ");
                use std::io::Write as _;
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    eprintln!("left alone");
                    return Ok(());
                }
            }

            vault.remove_item(id).ok_or("could not remove the item")?;
            vault.save()?;
            println!("deleted {label}");
        }

        Command::Slots => {
            let vault = Vault::open(&path, &passphrase)?;
            for slot in vault.slots() {
                let detail = match &slot.factor {
                    passman_core::slots::SlotFactor::Passphrase { params, .. } => {
                        format!("argon2id m={}KiB t={} p={}", params.m_cost, params.t_cost, params.p_cost)
                    }
                    passman_core::slots::SlotFactor::Tpm2 { with_pin, pcrs, .. } => format!(
                        "TPM 2.0{}{}",
                        if *with_pin { " + PIN" } else { "" },
                        if pcrs.is_empty() { String::new() } else { format!(" PCRs {pcrs:?}") }
                    ),
                    passman_core::slots::SlotFactor::Fido2 { rp_id, user_verification, .. } => {
                        format!("FIDO2 rp={rp_id}{}", if *user_verification { " + UV" } else { "" })
                    }
                };
                println!("{}  {:<16} {}", slot.id, slot.label, detail);
            }
        }

        Command::Import {
            from,
            into,
            dry_run,
            replace,
        } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let before = vault.data().item_count();

            let summary = tokio::runtime::Runtime::new()?.block_on(
                passman_secret::import::import_from(&mut vault, &from, into.as_deref(), replace),
            )?;

            if dry_run {
                println!("would import {summary}");
                println!("(dry run; nothing written)");
            } else {
                vault.save()?;
                println!("imported {summary}");
                println!(
                    "vault now holds {} item(s), up from {before}",
                    vault.data().item_count()
                );
            }
        }

        Command::ImportPass { store, gpg, into } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let store = match store {
                Some(s) => s,
                None => passman_import::pass::default_store_dir()
                    .ok_or("could not determine the password-store directory")?,
            };
            let summary =
                passman_import::pass::import_store(&mut vault, &store, &gpg, into.as_deref())?;
            vault.save()?;
            println!("imported {summary} from {}", store.display());
        }

        Command::ImportKeepass {
            database,
            db_passphrase_env,
            keyfile,
            into,
        } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let db_pw = match &db_passphrase_env {
                Some(var) => std::env::var(var)
                    .map_err(|_| format!("environment variable `{var}` is not set"))?,
                None => rpassword::prompt_password(format!(
                    "Password for {}: ",
                    database.display()
                ))?,
            };
            let summary = passman_import::keepass::import_kdbx(
                &mut vault,
                &database,
                &db_pw,
                keyfile.as_deref(),
                into.as_deref(),
            )?;
            vault.save()?;
            println!("imported {summary} from {}", database.display());
        }

        Command::ImportCsv { file, into } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let summary = passman_import::csv::import_file(&mut vault, &file, into.as_deref())?;
            vault.save()?;
            println!("imported {summary} from {}", file.display());
            // The export is every credential you own, in the clear.
            eprintln!(
                "\nNow delete {} — it is a plaintext copy of every password it held.",
                file.display()
            );
        }

        Command::ImportEnv {
            dir, group_by, into, ..
        } => {
            let grouping = group_by.into();
            let mut vault = Vault::open(&path, &passphrase)?;
            let summary =
                passman_import::dotenv::import_dir(&mut vault, &dir, grouping, into.as_deref())?;
            vault.save()?;
            println!("imported {summary} from {}", dir.display());
            eprintln!(
                "\nThe .env files are untouched. Delete them only once the projects read \
                 their configuration from passman."
            );
        }

        Command::ImportSsh { dir, into } => {
            let dir = match dir.or_else(passman_import::ssh::default_dir) {
                Some(d) => d,
                None => return Err("no ~/.ssh; pass --dir".into()),
            };
            let mut vault = Vault::open(&path, &passphrase)?;
            let summary = passman_import::ssh::import_dir(&mut vault, &dir, into.as_deref())?;
            vault.save()?;
            println!("imported {summary} from {}", dir.display());
            for note in &summary.notes {
                eprintln!("\n{note}");
            }
            eprintln!(
                "\nYour key files are untouched. Point SSH_AUTH_SOCK at passman's agent \
                 and confirm `ssh-add -l` lists them before removing anything."
            );
        }

        Command::ImportCloud {
            home,
            sqlite,
            into,
            ..
        } => {
            let home = match home.or_else(passman_import::cloud::home) {
                Some(h) => h,
                None => return Err("cannot find your home directory".into()),
            };
            let mut vault = Vault::open(&path, &passphrase)?;
            let summary =
                passman_import::cloud::import_home(&mut vault, &home, &sqlite, into.as_deref())?;
            vault.save()?;
            println!("imported {summary} from {}", home.display());
            eprintln!(
                "\nThe source files still hold the same credentials in the clear. \
                 Rotate them, or remove them once the tools are reading from passman."
            );
        }

        Command::ImportTotp { file, into } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let summary = passman_import::totp::import_file(&mut vault, &file, into.as_deref())?;
            vault.save()?;
            println!("imported {summary} from {}", file.display());
            eprintln!("\nNow delete {} — it is a plaintext copy of every seed it held.", file.display());
        }

        Command::Passwd { new_passphrase_env } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let new = match &new_passphrase_env {
                Some(var) => std::env::var(var)
                    .map_err(|_| format!("environment variable `{var}` is not set"))?,
                None => {
                    let first = rpassword::prompt_password("New passphrase: ")?;
                    let again = rpassword::prompt_password("Again: ")?;
                    if first != again {
                        return Err("the two passphrases do not match".into());
                    }
                    first
                }
            };
            if new.is_empty() {
                return Err("an empty passphrase is not a passphrase".into());
            }
            vault.change_passphrase(&new, KdfParams::default())?;
            vault.save()?;
            println!("passphrase changed for {}", path.display());
            let others = vault.slots().len().saturating_sub(1);
            if others > 0 {
                eprintln!("{others} other unlock factor(s) still open this vault.");
            }
        }

        Command::Export {
            file,
            i_understand_this_is_plaintext,
        } => {
            if !i_understand_this_is_plaintext {
                return Err(
                    "refusing to write plaintext secrets without \
                     --i-understand-this-is-plaintext"
                        .into(),
                );
            }
            if file.exists() {
                return Err(format!("{} already exists", file.display()).into());
            }
            let vault = Vault::open(&path, &passphrase)?;
            let count = export_to(&vault, &file)?;
            println!("exported {count} item(s) to {}", file.display());
            eprintln!(
                "\n{} now holds every secret in the vault in the clear. Delete it \
                 once you have moved them.",
                file.display()
            );
        }

        Command::Add {
            label,
            username,
            url,
            generate,
            length,
        } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let recipe = PasswordRecipe {
                length,
                ..Default::default()
            };
            let secret = if generate {
                let pw = generator::password(&recipe)?;
                eprintln!("generated a {length}-character password");
                pw.expose().to_owned()
            } else {
                rpassword::prompt_password("Secret: ")?
            };

            let mut item = Item::new(ItemKind::Login, &label).with_secret(secret);
            if let Some(u) = username {
                item = item
                    .with_field(Field::text(field_names::USERNAME, &u))
                    .with_attribute("username", u);
            }
            if let Some(u) = url {
                item = item.with_field(Field::text(field_names::URL, u));
            }

            let id = vault.add_item_default(item);
            vault.save()?;
            println!("{id}");
        }
    }

    Ok(())
}

/// Resolve a label or id to exactly one item.
///
/// Exact matches first, so an item called `github` is reachable even when
/// three others merely mention it. An ambiguous substring is an error rather
/// than a guess: the commands using this delete and overwrite things.
fn find_item(vault: &Vault, query: &str) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    let needle = query.to_lowercase();

    let exact: Vec<_> = vault
        .data()
        .all_items()
        .map(|(_, i)| i)
        .filter(|i| i.label.to_lowercase() == needle || i.id.to_string() == needle)
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].id);
    }
    if exact.len() > 1 {
        return Err(format!(
            "`{query}` matches {} items exactly; use the id instead",
            exact.len()
        )
        .into());
    }

    let loose: Vec<_> = vault
        .data()
        .all_items()
        .map(|(_, i)| i)
        .filter(|i| i.matches(query))
        .collect();
    match loose.len() {
        0 => Err(format!("no item matching `{query}`").into()),
        1 => Ok(loose[0].id),
        _ => {
            // Printed rather than folded into the error, because `main` shows
            // errors through `Debug` and a multi-line one comes out with
            // literal `\n` in it.
            eprintln!("`{query}` matches {} items:", loose.len());
            for item in loose.iter().take(10) {
                eprintln!("  {}  {}", item.id, item.label);
            }
            if loose.len() > 10 {
                eprintln!("  … and {} more", loose.len() - 10);
            }
            Err("be more specific, or use one of those ids".into())
        }
    }
}

/// Write the whole vault out as JSON, secrets included.
///
/// JSON rather than CSV because CSV cannot represent an item with arbitrary
/// extra fields without either losing them or inventing a column per field —
/// and losing them silently is exactly the failure this command exists to
/// avoid. Created 0600 before anything is written to it.
fn export_to(vault: &Vault, path: &std::path::Path) -> Result<usize, Box<dyn std::error::Error>> {
    use std::io::Write as _;

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
            "fields": item.fields.iter().map(|f| serde_json::json!({
                "name": f.name,
                "kind": f.kind,
                "value": f.value.expose(),
            })).collect::<Vec<_>>(),
        }));
    }
    let count = items.len();

    let document = serde_json::json!({
        "format": "passman-export-v1",
        "items": items,
    });

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(&document)?)?;
    file.sync_all()?;
    Ok(count)
}

/// CLI spelling of [`passman_import::dotenv::Grouping`].
///
/// A separate type so the importer's API does not have to depend on clap.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum EnvGrouping {
    /// One item per .env file, every variable a field.
    File,
    /// One item per vendor within a file, inferred from the key prefix.
    Service,
    /// One item per variable.
    Variable,
}

impl From<EnvGrouping> for passman_import::dotenv::Grouping {
    fn from(g: EnvGrouping) -> Self {
        match g {
            EnvGrouping::File => Self::PerFile,
            EnvGrouping::Service => Self::PerService,
            EnvGrouping::Variable => Self::PerVariable,
        }
    }
}
