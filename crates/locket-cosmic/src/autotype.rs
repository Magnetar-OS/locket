//! Auto-type over the RemoteDesktop portal.
//!
//! The whole design is in `docs/autotype-wayland.md`, measured off a live
//! session. The short version: `xdg-desktop-portal-cosmic` implements
//! `NotifyKeyboardKeysym`, which types *characters* rather than physical
//! keys, so this works on any layout; there is no portal for a global
//! hotkey yet, so the trigger is a button in locket; and no portal names
//! the focused window, so the person clicking the target field during the
//! countdown *is* the targeting step.
//!
//! The sequence is `username → Tab → password`, with no Enter on the end:
//! submitting a form nobody has reviewed is a decision, not a keystroke.

use ashpd::desktop::remote_desktop::{
    DeviceType, KeyState, NotifyKeyboardKeysymOptions, RemoteDesktop, SelectDevicesOptions,
    StartOptions,
};
use ashpd::desktop::{PersistMode, Session};
use ashpd::enumflags2::BitFlags;
use locket_core::SecretString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// How long the person has to click the target field, after the portal has
/// granted access.
pub const COUNTDOWN_SECS: u64 = 3;

/// Between key events, so a slow client on the other end drops nothing.
const KEY_DELAY_MS: u64 = 8;

/// The X11 keysym for a character — the encoding the portal expects.
///
/// Printable ASCII and Latin-1 *are* their keysyms; everything else maps
/// through the Unicode range (`0x0100_0000 + codepoint`), per the keysym
/// registry. Control characters are refused, tab and return included: a
/// value containing one is data, and typing it would act on the form — Tab
/// moves the rest into another field, and Return submits a form nobody has
/// reviewed.
fn keysym_for(c: char) -> Option<i32> {
    let code = c as u32;
    match c {
        _ if (0x20..=0x7e).contains(&code) => Some(code as i32),
        _ if (0xa0..=0xff).contains(&code) => Some(code as i32),
        _ if code >= 0x100 => Some((0x0100_0000 + code) as i32),
        _ => None,
    }
}

/// Acquire keyboard access, wait out the countdown, and type.
///
/// The permission dialog is the compositor's, shown before the countdown
/// starts, so the person is never racing a timer while reading a consent
/// prompt. `PersistMode::Application` asks for the answer to be kept while
/// locket runs, but the portal only honours that through a restore token
/// passed to the next session, and none is kept here — so the compositor may
/// ask on every use.
///
/// `wanted` is cleared when the window locks; every key checks it first, so
/// nothing is typed from a vault that has since been locked.
pub async fn type_credentials(
    username: Option<String>,
    secret: SecretString,
    wanted: Arc<AtomicBool>,
) -> Result<(), String> {
    // Worked out before asking for access, so a value that cannot be typed
    // is refused without a permission dialog for nothing.
    let keys = keystrokes(username.as_deref(), secret.expose())?;
    let proxy = RemoteDesktop::new().await.map_err(portal_error)?;
    let session = proxy
        .create_session(Default::default())
        .await
        .map_err(portal_error)?;
    let typed = type_into(&proxy, &session, &keys, &wanted).await;
    // The session is what holds the keyboard. The portal only ends it on its
    // own when this process leaves the bus, so without this every auto-type
    // left one open for as long as locket ran.
    let closed = session.close().await;
    typed?;
    closed.map_err(|e| format!("typed, but could not end the input session: {e}"))
}

/// Ask for the keyboard, wait out the countdown, and press `keys`.
async fn type_into(
    proxy: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    keys: &[i32],
    wanted: &AtomicBool,
) -> Result<(), String> {
    proxy
        .select_devices(
            session,
            SelectDevicesOptions::default()
                .set_devices(BitFlags::from(DeviceType::Keyboard))
                .set_persist_mode(PersistMode::Application),
        )
        .await
        .map_err(portal_error)?;
    let devices = proxy
        .start(session, None, StartOptions::default())
        .await
        .map_err(portal_error)?
        .response()
        .map_err(|_| "input access was not granted".to_owned())?;
    if !devices.devices().contains(DeviceType::Keyboard) {
        return Err("the compositor did not grant keyboard access".into());
    }

    // Only now does the clock start: access is granted, the person's next
    // click decides where the text lands.
    tokio::time::sleep(std::time::Duration::from_secs(COUNTDOWN_SECS)).await;

    for &keysym in keys {
        press(proxy, session, keysym, wanted).await?;
    }
    Ok(())
}

/// Tab, between the username and the password.
const TAB: i32 = 0xff09;

/// Every key to press, worked out before the first one is: a value that
/// cannot be typed is refused whole rather than half-typed.
fn keystrokes(username: Option<&str>, secret: &str) -> Result<Vec<i32>, String> {
    let mut keys = Vec::new();
    // An empty username field is no username: typing nothing and then Tab
    // would land the password in the field after the one clicked.
    if let Some(username) = username.filter(|u| !u.is_empty()) {
        keys.extend(typed(username)?);
        keys.push(TAB);
    }
    keys.extend(typed(secret)?);
    Ok(keys)
}

fn typed(text: &str) -> Result<Vec<i32>, String> {
    text.chars()
        .map(|c| {
            keysym_for(c)
                .ok_or_else(|| format!("the value contains an untypeable character ({c:?})"))
        })
        .collect()
}

async fn press(
    proxy: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    keysym: i32,
    wanted: &AtomicBool,
) -> Result<(), String> {
    if !wanted.load(Ordering::SeqCst) {
        return Err("the vault was locked before typing finished".into());
    }
    proxy
        .notify_keyboard_keysym(
            session,
            keysym,
            KeyState::Pressed,
            NotifyKeyboardKeysymOptions::default(),
        )
        .await
        .map_err(portal_error)?;
    proxy
        .notify_keyboard_keysym(
            session,
            keysym,
            KeyState::Released,
            NotifyKeyboardKeysymOptions::default(),
        )
        .await
        .map_err(portal_error)?;
    tokio::time::sleep(std::time::Duration::from_millis(KEY_DELAY_MS)).await;
    Ok(())
}

fn portal_error(e: ashpd::Error) -> String {
    format!("the RemoteDesktop portal refused: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_latin1_are_their_own_keysyms() {
        assert_eq!(keysym_for('a'), Some(0x61));
        assert_eq!(keysym_for('A'), Some(0x41));
        assert_eq!(keysym_for('!'), Some(0x21));
        assert_eq!(keysym_for(' '), Some(0x20));
        assert_eq!(keysym_for('é'), Some(0xe9));
    }

    #[test]
    fn everything_else_goes_through_the_unicode_range() {
        assert_eq!(keysym_for('€'), Some(0x0100_0000 + 0x20ac));
        assert_eq!(keysym_for('λ'), Some(0x0100_0000 + 0x3bb));
        assert_eq!(keysym_for('🔑'), Some(0x0100_0000 + 0x1f511));
    }

    /// Tab and Enter act on the form: Tab moves the password into the next
    /// field, Enter submits a form nobody has looked at. Inside a value they
    /// are refused like every other control character.
    #[test]
    fn control_characters_in_a_value_are_refused_tab_and_return_included() {
        for c in ['\t', '\n', '\r', '\u{7}', '\u{1b}'] {
            assert_eq!(keysym_for(c), None, "{c:?} became a keystroke");
        }
        assert!(keystrokes(Some("ada"), "hunter2\n").is_err());
        assert!(keystrokes(Some("ada\t"), "hunter2").is_err());
    }

    /// An empty username field is not a username: typing nothing and then
    /// Tab would put the password into the field after the one clicked.
    #[test]
    fn an_empty_username_types_no_tab() {
        assert_eq!(keystrokes(Some(""), "pw"), Ok(vec![0x70, 0x77]));
        assert_eq!(keystrokes(None, "pw"), Ok(vec![0x70, 0x77]));
        assert_eq!(keystrokes(Some("a"), "pw"), Ok(vec![0x61, TAB, 0x70, 0x77]));
    }
}
