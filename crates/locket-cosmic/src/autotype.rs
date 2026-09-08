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

/// How long the person has to click the target field, after the portal has
/// granted access.
pub const COUNTDOWN_SECS: u64 = 3;

/// Between key events, so a slow client on the other end drops nothing.
const KEY_DELAY_MS: u64 = 8;

/// The X11 keysym for a character — the encoding the portal expects.
///
/// Printable ASCII and Latin-1 *are* their keysyms; everything else maps
/// through the Unicode range (`0x0100_0000 + codepoint`), per the keysym
/// registry. Control characters other than tab and return are refused: a
/// secret containing one is data, and typing it would do something.
fn keysym_for(c: char) -> Option<i32> {
    let code = c as u32;
    match c {
        '\t' => Some(0xff09),
        '\r' | '\n' => Some(0xff0d),
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
/// prompt. `PersistMode::Application` lets the compositor remember the
/// answer, so the dialog is a first-use cost rather than a per-use one.
pub async fn type_credentials(
    username: Option<String>,
    secret: SecretString,
) -> Result<(), String> {
    let proxy = RemoteDesktop::new().await.map_err(portal_error)?;
    let session = proxy
        .create_session(Default::default())
        .await
        .map_err(portal_error)?;
    proxy
        .select_devices(
            &session,
            SelectDevicesOptions::default()
                .set_devices(BitFlags::from(DeviceType::Keyboard))
                .set_persist_mode(PersistMode::Application),
        )
        .await
        .map_err(portal_error)?;
    let devices = proxy
        .start(&session, None, StartOptions::default())
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

    if let Some(username) = &username {
        type_text(&proxy, &session, username).await?;
        press(&proxy, &session, 0xff09).await?; // Tab
    }
    type_text(&proxy, &session, secret.expose()).await?;
    Ok(())
}

async fn type_text(
    proxy: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    text: &str,
) -> Result<(), String> {
    for c in text.chars() {
        let keysym = keysym_for(c)
            .ok_or_else(|| format!("the value contains an untypeable character ({c:?})"))?;
        press(proxy, session, keysym).await?;
    }
    Ok(())
}

async fn press(
    proxy: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    keysym: i32,
) -> Result<(), String> {
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

    #[test]
    fn tab_and_return_map_and_other_controls_are_refused() {
        assert_eq!(keysym_for('\t'), Some(0xff09));
        assert_eq!(keysym_for('\n'), Some(0xff0d));
        assert_eq!(
            keysym_for('\u{7}'),
            None,
            "a bell character became a keystroke"
        );
        assert_eq!(keysym_for('\u{1b}'), None, "escape became a keystroke");
    }
}
