//! locket — a password and secrets manager for COSMIC.

#![forbid(unsafe_code)]

mod app;
mod autotype;
mod config;
mod daemon;
mod editor;
mod i18n;
mod import;
mod labels;
mod preferences;
mod prompt;
mod security;

use cosmic::app::Settings;
use locket_core::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "locket=info".into()),
        )
        .init();

    // The languages the desktop asks for, in preference order. Done before any
    // widget is built, because `fl!` resolves against whatever is selected now.
    i18n::init(&i18n_embed::DesktopLanguageRequester::requested_languages());

    let vault_path = match std::env::var_os("LOCKET_VAULT") {
        Some(p) => std::path::PathBuf::from(p),
        None => Vault::default_path()?,
    };

    // `--prompt` is how the daemon starts us to answer an application's unlock
    // request. It opens no main window at all: the request gets the dialog it
    // needs and nothing else, and the full window is one button away for
    // anyone who wanted that instead.
    let prompt = std::env::args().skip(1).any(|arg| arg == "--prompt");

    let settings = Settings::default()
        .antialiasing(true)
        .client_decorations(true)
        .no_main_window(prompt)
        .size(app::WINDOW_SIZE)
        .size_limits(
            cosmic::iced::Limits::NONE
                .min_width(app::WINDOW_MIN_SIZE.width)
                .min_height(app::WINDOW_MIN_SIZE.height),
        );

    // A second `locket` activates the window that is already open rather than
    // starting a second process: two windows would each hold their own vault
    // handle, so locking one would leave the other unlocked. Set
    // COSMIC_SINGLE_INSTANCE=0 to opt out — needed to run two vaults side by
    // side with LOCKET_VAULT, since the hand-off carries no vault path.
    //
    // `--prompt` travels across that hand-off as an action, so a daemon that
    // starts us while a window is already open raises that instance's dialog
    // instead of pulling its window forward.
    cosmic::app::run_single_instance::<app::App>(settings, app::Flags::new(vault_path, prompt))?;
    Ok(())
}
