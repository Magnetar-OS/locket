//! Desktop notifications, for daemon events that happen with no window on
//! screen to report them.

/// `org.freedesktop.Notifications`, the one call we make.
#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: Vec<&str>,
        hints: std::collections::HashMap<&str, zbus::zvariant::Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// Put one notification on the desktop.
///
/// Best effort: a session without a notification service still has the
/// journal line the caller wrote, so a failure here is logged and nothing
/// more. The text is the caller's; nothing read out of the vault belongs in it.
pub async fn send(connection: &zbus::Connection, summary: &str, body: &str) {
    let result = async {
        NotificationsProxy::new(connection)
            .await?
            .notify(
                "locket",
                0,
                "com.magnetaros.Locket",
                summary,
                body,
                Vec::new(),
                Default::default(),
                5_000,
            )
            .await
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("could not send a desktop notification: {e}");
    }
}
