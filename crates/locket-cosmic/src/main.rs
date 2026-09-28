//! locket — a password and secrets manager for COSMIC.

#![forbid(unsafe_code)]

mod app;
mod autotype;
mod config;
mod confirm;
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
    // stderr, never stdout: a confirmation dialog answers on stdout, and a log
    // line there would be read as part of the answer.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "locket=info".into()),
        )
        .init();

    // The languages the desktop asks for, in preference order. Done before any
    // widget is built, because `fl!` resolves against whatever is selected now.
    i18n::init(&i18n_embed::DesktopLanguageRequester::requested_languages());

    let args: Vec<String> = std::env::args().skip(1).collect();

    // `--confirm-signing` / `--confirm-fill`: one question, answered on
    // stdout, in a process of its own. Decided before anything else so that no
    // path through the ordinary start — least of all the single-instance
    // hand-off, which exits 0 — can stand in for an answer.
    if let Some(question) = confirm::question_from_args(&args) {
        std::process::exit(ask(question));
    }

    let vault_path = match std::env::var_os("LOCKET_VAULT") {
        Some(p) => std::path::PathBuf::from(p),
        None => Vault::default_path()?,
    };

    // `--prompt` is how the daemon starts us to answer an application's unlock
    // request. It opens no main window at all: the request gets the dialog it
    // needs and nothing else, and the full window is one button away for
    // anyone who wanted that instead.
    let prompt = args.iter().any(|arg| arg == "--prompt");

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

/// Put one confirmation on screen and answer it on stdout. Returns the exit
/// code: 0 only after writing the allow line.
fn ask(question: Result<locket_secret::frontend::Question, String>) -> i32 {
    let question = match question {
        Ok(question) => question,
        Err(e) => {
            tracing::error!("{e}");
            return 2;
        }
    };

    // Other processes running as this user may not attach to this one: an
    // attached debugger could press "Allow" for them.
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        tracing::error!("refusing to ask: could not make the dialog non-dumpable ({e})");
        return 2;
    }

    let allowed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settings = Settings::default()
        .antialiasing(true)
        .client_decorations(true)
        .resizable(None)
        .size(confirm::SIZE);
    let flags = confirm::Flags {
        question,
        allowed: allowed.clone(),
    };
    if let Err(e) = cosmic::app::run::<confirm::Confirm>(settings, flags) {
        tracing::error!("the confirmation dialog failed: {e}");
        return 1;
    }
    if !allowed.load(std::sync::atomic::Ordering::SeqCst) {
        return 1;
    }
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(locket_secret::frontend::ALLOW.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("could not deliver the answer: {e}");
            1
        }
    }
}
