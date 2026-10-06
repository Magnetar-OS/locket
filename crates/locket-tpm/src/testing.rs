//! A software TPM for tests.
//!
//! `swtpm` is the reference TPM 2.0 implementation behind a socket. Each
//! [`Swtpm`] is a fresh one — its own seeds, an empty dictionary-attack
//! counter, its state in a temporary directory — so tests neither share state
//! nor go anywhere near the chip in the machine running them. Behind the
//! `test-swtpm` feature, which nothing that ships enables.
//!
//! It listens on a pair of loopback TCP ports rather than a socket file
//! because that is the only address `tss-esapi` 7 can name for it.

use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::Tpm;

/// An `swtpm` that lives as long as this value.
pub struct Swtpm {
    child: Child,
    tcti: String,
    _dir: tempfile::TempDir,
}

impl Swtpm {
    /// Start a new, empty TPM.
    pub fn start() -> Self {
        let dir = tempfile::tempdir().expect("temporary directory for the TPM's state");
        // The ports are free when looked at and may not be a moment later,
        // with every test starting a TPM of its own; so look again.
        for _ in 0..20 {
            let Some(port) = free_port_pair() else {
                continue;
            };
            let mut child = Command::new("swtpm")
                .args(["socket", "--tpm2"])
                .arg("--tpmstate")
                .arg(format!("dir={}", dir.path().display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
                // tpm2-tss looks for the control channel one port up.
                .arg("--ctrl")
                .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
                .args(["--flags", "not-need-init,startup-clear"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("swtpm must be installed to run the TPM tests");

            if listening(&mut child, port) {
                return Self {
                    child,
                    tcti: format!("swtpm:host=127.0.0.1,port={port}"),
                    _dir: dir,
                };
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("swtpm could not be started on any pair of loopback ports");
    }

    /// The TCTI configuration naming this TPM, for a program of its own that
    /// reads it from the environment.
    pub fn tcti(&self) -> &str {
        &self.tcti
    }

    /// This TPM, to seal to and unseal with.
    pub fn tpm(&self) -> Tpm {
        Tpm::at(&self.tcti).expect("a valid TCTI configuration")
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loopback port that is free, with the one above it free too.
fn free_port_pair() -> Option<u16> {
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    let port = first.local_addr().ok()?.port();
    TcpListener::bind((Ipv4Addr::LOCALHOST, port.checked_add(1)?)).ok()?;
    Some(port)
}

/// Whether `child` came up listening on `port` and the one above it.
fn listening(child: &mut Child, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        // Gone already: it could not have the ports.
        if !matches!(child.try_wait(), Ok(None)) {
            return false;
        }
        let up = |port| TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok();
        if up(port + 1) && up(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}
