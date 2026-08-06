//! passman — a password and secrets manager for COSMIC.

mod app;
mod config;
mod daemon;
mod editor;
mod security;

use cosmic::app::Settings;
use cosmic::iced::Size;
use passman_core::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "passman=info".into()),
        )
        .init();

    let vault_path = match std::env::var_os("PASSMAN_VAULT") {
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

    cosmic::app::run::<app::App>(settings, app::Flags { vault_path })?;
    Ok(())
}
