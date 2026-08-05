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

        Command::Import { from, into, dry_run } => {
            let mut vault = Vault::open(&path, &passphrase)?;
            let before = vault.data().item_count();

            let summary = tokio::runtime::Runtime::new()?.block_on(
                passman_secret::import::import_from(&mut vault, &from, into.as_deref()),
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
