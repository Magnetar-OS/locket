//! locket — a password and secrets manager for COSMIC.

mod app;
mod config;
mod daemon;
mod editor;
mod import;
mod preferences;
mod security;

use cosmic::app::Settings;
use cosmic::iced::Size;
use locket_core::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "locket=info".into()),
        )
        .init();

    let vault_path = match std::env::var_os("LOCKET_VAULT") {
        Some(p) => std::path::PathBuf::from(p),
        None => Vault::default_path()?,
    };

    let settings = Settings::default()
        .antialiasing(true)
        .client_decorations(true)
        .size(Size::new(1100.0, 760.0))
        .size_limits(
            cosmic::iced::Limits::NONE
                .min_width(560.0)
                .min_height(400.0),
        );

    // A second `locket` activates the window that is already open rather than
    // starting a second process: two windows would each hold their own vault
    // handle, so locking one would leave the other unlocked. Set
    // COSMIC_SINGLE_INSTANCE=0 to opt out — needed to run two vaults side by
    // side with LOCKET_VAULT, since the hand-off carries no arguments.
    cosmic::app::run_single_instance::<app::App>(settings, app::Flags { vault_path })?;
    Ok(())
}
