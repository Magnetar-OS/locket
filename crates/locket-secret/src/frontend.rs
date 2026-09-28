//! Starting locket's own windows from processes that have none.
//!
//! Two reasons to put something in front of the person at the keyboard:
//!
//! * **An unlock prompt.** An application asked for a secret while the vault
//!   was locked. The GUI is started with `--prompt`; the answer is the vault
//!   becoming unlocked, which the daemon observes on its own.
//! * **A confirmation.** One use of one secret needs a yes from a person: an
//!   SSH signature with a `confirm-each-use` key, or a password the browser
//!   extension wants to fill. See [`ask`].
//!
//! # Why a confirmation is its own process
//!
//! The answer to a confirmation must not be something another process can
//! send. It used to be: the daemon broadcast `ConfirmRequested(id, key)` on the
//! session bus with sequential ids, and took the answer from whichever bus
//! peer called `Manager1.AnswerConfirm(id, true)` first. Any process running as
//! the user could connect to `$SSH_AUTH_SOCK`, ask for a signature, and approve
//! it itself before the dialog was drawn — the exact attacker `confirm-each-use`
//! exists to stop.
//!
//! Now the asking process starts a dialog of its own (`locket --confirm-…`)
//! and reads the answer from that child's standard output, a pipe nobody else
//! holds. Nothing about the question is announced on the bus and there is no
//! method to answer it with. Only one output counts as a yes — [`ALLOW`] on
//! stdout *and* a clean exit — so a crash, a kill, a timeout, a frontend too
//! old to know the flag, or a single-instance hand-off that exits at once all
//! read as no.
//!
//! What this does not stop, stated so nobody has to discover it: a process
//! that can already control the dialog — `ptrace` it (the dialog makes itself
//! non-dumpable at startup, which refuses that to other same-user processes),
//! rewrite the user manager's environment before it starts (`LD_PRELOAD` via
//! `systemctl --user set-environment`, which would equally subvert the daemon
//! at its next start), or inject input into the compositor.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// How long a confirmation waits. An `ssh` client, or a browser tab, is holding
/// its request open on the other side of it; a use nobody has allowed after
/// half a minute is one nobody asked for.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);

/// What the dialog writes to standard output, and nothing else, to allow.
pub const ALLOW: &str = "allow\n";

/// The flag that asks the frontend about one signature.
pub const CONFIRM_SIGNING_FLAG: &str = "--confirm-signing";
/// The flag that asks the frontend about one browser fill.
pub const CONFIRM_FILL_FLAG: &str = "--confirm-fill";

/// One use of a secret that needs a person's yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Question {
    /// Sign with the SSH key known by this comment.
    Signing { key: String },
    /// Hand the password of the entry labelled `entry` to the browser, to type
    /// into a page on `site`.
    Fill { site: String, entry: String },
}

impl Question {
    /// The frontend's arguments for this question.
    fn args(&self) -> Vec<OsString> {
        match self {
            Question::Signing { key } => vec![CONFIRM_SIGNING_FLAG.into(), key.into()],
            Question::Fill { site, entry } => {
                vec![CONFIRM_FILL_FLAG.into(), site.into(), entry.into()]
            }
        }
    }
}

/// Ask the person at the keyboard, and wait for the answer.
///
/// Fails closed on every path that is not an explicit yes: no graphical
/// session, a frontend that cannot be started, no answer within `timeout`.
pub async fn ask(question: &Question, timeout: Duration) -> bool {
    // A request from an `ssh` in a script, on a machine with no screen, is
    // refused at once rather than made to wait out a dialog nobody can see.
    if !has_display() {
        tracing::info!("no graphical session to ask in; refusing {question:?}");
        return false;
    }
    let (command, name) = frontend_command(Mode::Confirm(question), launcher(), timeout);
    tracing::info!("asking through {name}: {question:?}");
    run_confirmation(command, timeout).await
}

/// Run a confirmation dialog and read its answer. See [`ask`].
async fn run_confirmation(command: std::process::Command, timeout: Duration) -> bool {
    let mut command = tokio::process::Command::from(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // A dialog nobody answered in time must not stay up to be answered
        // later, when nothing is waiting for it.
        .kill_on_drop(true);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!("could not start the confirmation dialog: {e}");
            return false;
        }
    };
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => is_allowed(output.status, &output.stdout),
        Ok(Err(e)) => {
            tracing::warn!("the confirmation dialog failed: {e}");
            false
        }
        Err(_) => {
            tracing::info!("confirmation timed out after {timeout:?}; refusing");
            false
        }
    }
}

/// Whether a finished dialog said yes: a clean exit *and* exactly [`ALLOW`].
fn is_allowed(status: std::process::ExitStatus, stdout: &[u8]) -> bool {
    status.success() && stdout == ALLOW.as_bytes()
}

/// Start the GUI so somebody can answer an unlock prompt.
///
/// The process is waited on from a thread of its own, so it never lingers as
/// a zombie; the answer is the vault becoming unlocked, not its exit.
pub fn spawn_prompt() -> std::io::Result<String> {
    let (mut command, name) = frontend_command(Mode::Prompt, launcher(), Duration::ZERO);
    let mut child = command.spawn()?;
    std::thread::Builder::new()
        .name("locket-frontend-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        })?;
    Ok(name)
}

/// Whether there is a graphical session to put a window in.
pub fn has_display() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

/// What the frontend is being started for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode<'a> {
    /// `--prompt`: the unlock dialog and no main window.
    Prompt,
    /// One confirmation dialog, answered on standard output.
    Confirm(&'a Question),
}

/// How the frontend is started.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Launcher {
    /// As a direct child: outside systemd, or where `systemd-run` is missing.
    Direct,
    /// As a transient user unit, through this `systemd-run`.
    SystemdRun(PathBuf),
}

/// `systemd-run` when this process is itself a systemd unit, which is exactly
/// when a child would inherit that unit's sandbox.
fn launcher() -> Launcher {
    if std::env::var_os("INVOCATION_ID").is_none() {
        return Launcher::Direct;
    }
    ["/usr/bin/systemd-run", "/bin/systemd-run"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .map_or(Launcher::Direct, Launcher::SystemdRun)
}

/// The command that starts the frontend, and the name to log it under.
///
/// The binary is resolved next to this executable before falling back to
/// `PATH`: the daemon runs as a systemd user unit, whose environment is not
/// the login shell's, so a `PATH` lookup is not something an unlock or a
/// confirmation should depend on.
///
/// Under systemd the frontend is started through `systemd-run --user` rather
/// than as a child. A child inherits the daemon unit's hardening — above all
/// `MemoryDenyWriteExecute`, which stops Mesa's shader JIT ("JIT session
/// error: Permission denied") — and lives in the daemon's cgroup. For a
/// confirmation, `--wait --pipe` keeps the dialog's standard output connected
/// to ours and propagates its exit status, and `RuntimeMaxSec` has systemd end
/// a dialog that outlives the wait.
///
/// Split out so the argument list is something a test can look at: the
/// difference between starting a dialog and starting the whole application is
/// one flag.
fn frontend_command(
    mode: Mode<'_>,
    launcher: Launcher,
    timeout: Duration,
) -> (std::process::Command, String) {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("locket")))
        .filter(|p| p.is_file());

    let candidate = match &sibling {
        Some(p) => p.as_os_str().to_owned(),
        None => OsString::from("locket"),
    };
    let mut command = match &launcher {
        Launcher::Direct => std::process::Command::new(&candidate),
        Launcher::SystemdRun(systemd_run) => {
            let mut command = std::process::Command::new(systemd_run);
            // `--setenv=NAME` with no value copies it from this environment:
            // the window needs the display, and the user manager may not have
            // been told about it.
            command.args([
                "--user",
                "--collect",
                "--quiet",
                "--setenv=WAYLAND_DISPLAY",
                "--setenv=DISPLAY",
                "--setenv=XDG_RUNTIME_DIR",
            ]);
            if let Mode::Confirm(_) = mode {
                command.args(["--wait", "--pipe"]);
                command.arg(format!("--property=RuntimeMaxSec={}", timeout.as_secs()));
            }
            command.arg("--");
            command.arg(&candidate);
            command
        }
    };
    match mode {
        Mode::Prompt => {
            command.arg("--prompt");
        }
        Mode::Confirm(question) => {
            command.args(question.args());
        }
    }
    (command, candidate.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &std::process::Command) -> Vec<String> {
        command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// An unlock request starts the frontend for the dialog, not for the
    /// application: `--prompt` is what keeps a request for one secret from
    /// opening the whole password manager.
    #[test]
    fn an_unlock_prompt_starts_the_frontend_with_prompt() {
        let (command, _) = frontend_command(Mode::Prompt, Launcher::Direct, Duration::ZERO);
        assert_eq!(args(&command), ["--prompt"]);
    }

    /// Under systemd the frontend must not be the daemon's child: it would
    /// inherit `MemoryDenyWriteExecute` and lose GPU shader compilation. The
    /// transient unit still gets `--prompt`, as the last argument.
    #[test]
    fn under_systemd_the_frontend_starts_outside_the_daemons_sandbox() {
        let (command, name) = frontend_command(
            Mode::Prompt,
            Launcher::SystemdRun("/usr/bin/systemd-run".into()),
            Duration::ZERO,
        );
        assert_eq!(command.get_program(), "/usr/bin/systemd-run");
        let args = args(&command);
        assert_eq!(args[0], "--user");
        let separator = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[separator + 1], name);
        assert_eq!(args.last().unwrap(), "--prompt");
        assert!(args.contains(&"--setenv=WAYLAND_DISPLAY".to_owned()));
        assert!(!args.contains(&"--wait".to_owned()));
    }

    /// A confirmation's answer comes back on the dialog's standard output, so
    /// under systemd the unit has to be waited for with its output piped back,
    /// and must not outlive the question.
    #[test]
    fn a_confirmation_under_systemd_is_waited_for_with_its_output() {
        let question = Question::Signing {
            key: "work laptop".into(),
        };
        let (command, name) = frontend_command(
            Mode::Confirm(&question),
            Launcher::SystemdRun("/usr/bin/systemd-run".into()),
            CONFIRM_TIMEOUT,
        );
        let args = args(&command);
        let separator = args.iter().position(|a| a == "--").unwrap();
        let (options, command) = args.split_at(separator);
        for wanted in ["--wait", "--pipe", "--property=RuntimeMaxSec=30"] {
            assert!(options.contains(&wanted.to_owned()), "{wanted} missing");
        }
        assert_eq!(command, ["--", &name, "--confirm-signing", "work laptop"]);
    }

    #[test]
    fn a_fill_confirmation_names_the_site_and_the_entry() {
        let question = Question::Fill {
            site: "github.com".into(),
            entry: "GitHub".into(),
        };
        let (command, _) =
            frontend_command(Mode::Confirm(&question), Launcher::Direct, CONFIRM_TIMEOUT);
        assert_eq!(args(&command), ["--confirm-fill", "github.com", "GitHub"]);
    }

    fn shell(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[tokio::test]
    async fn only_the_allow_line_and_a_clean_exit_is_a_yes() {
        let timeout = Duration::from_secs(10);
        assert!(run_confirmation(shell("printf 'allow\\n'"), timeout).await);
        // A frontend that exits cleanly without answering — too old to know
        // the flag, or a single-instance hand-off to a running window — has
        // not said yes.
        assert!(!run_confirmation(shell("exit 0"), timeout).await);
        assert!(!run_confirmation(shell("printf 'allow\\n'; exit 1"), timeout).await);
        // Logging to stdout around the answer is not the answer.
        assert!(!run_confirmation(shell("echo starting; printf 'allow\\n'"), timeout).await);
        assert!(
            !run_confirmation(std::process::Command::new("/nonexistent/locket"), timeout).await
        );
    }

    /// Silence is a no, and the dialog nobody answered does not stay up to be
    /// answered after the fact.
    #[tokio::test]
    async fn an_unanswered_dialog_is_refused_and_taken_down() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("still-running");
        let script = format!("sleep 5; touch '{}'", marker.display());
        let started = std::time::Instant::now();
        assert!(!run_confirmation(shell(&script), Duration::from_millis(300)).await);
        assert!(started.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_secs(6));
        assert!(!marker.exists(), "the timed-out dialog was left running");
    }
}
