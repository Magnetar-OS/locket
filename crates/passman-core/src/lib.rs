//! Vault format, cryptography and item model for passman.
//!
//! This crate is deliberately free of D-Bus, UI and async: it is the piece
//! that the daemon, the CLI and the COSMIC frontend all agree on, and the
//! piece worth auditing closely.
//!
//! ```no_run
//! use passman_core::{Vault, crypto::KdfParams, model::{Item, ItemKind}};
//!
//! let path = Vault::default_path()?;
//! let mut vault = Vault::create(&path, "correct horse battery staple", KdfParams::default())?;
//! vault.add_item_default(Item::new(ItemKind::Login, "GitHub").with_secret("hunter2"));
//! vault.save()?;
//! # Ok::<(), passman_core::Error>(())
//! ```

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod generator;
pub mod model;
pub mod secret;
pub mod slots;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
pub use model::{Collection, Field, FieldKind, Item, ItemKind, VaultData};
pub use secret::{SecretBytes, SecretString};
pub use totp::Totp;
pub use vault::Vault;
