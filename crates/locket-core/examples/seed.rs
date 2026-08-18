//! Create a vault populated with representative items, for development.
//!
//! ```sh
//! cargo run -p locket-core --example seed -- /tmp/dev.vault hunter2
//! ```

use locket_core::{
    Vault,
    crypto::KdfParams,
    model::{Collection, Field, FieldKind, Item, ItemKind, field_names},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: seed <vault-path> <passphrase>")?;
    let passphrase = args.next().ok_or("usage: seed <vault-path> <passphrase>")?;

    let _ = std::fs::remove_file(&path);
    let mut vault = Vault::create(&path, &passphrase, KdfParams::default())?;

    let mut github = Item::new(ItemKind::Login, "GitHub")
        .with_secret("g1thub-Sup3r-S3cret!")
        .with_field(Field::text(field_names::USERNAME, "idominikos"))
        .with_field(Field::new(
            field_names::URL,
            FieldKind::Url,
            "https://github.com",
        ))
        // RFC 6238's own test seed, so the code on screen is verifiable.
        .with_field(Field::new(
            field_names::TOTP,
            FieldKind::Totp,
            "otpauth://totp/GitHub:idominikos?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub",
        ))
        .with_attribute("service", "github.com")
        .with_attribute("username", "idominikos")
        .with_attribute("xdg:schema", "org.freedesktop.Secret.Generic");
    github.favorite = true;

    let items = vec![
        github,
        Item::new(ItemKind::Login, "Proton Mail")
            .with_secret("c0rrect-horse-battery-staple")
            .with_field(Field::text(field_names::USERNAME, "dominikos@myroomieapp.com"))
            .with_attribute("service", "proton.me"),
        Item::new(ItemKind::Note, "Recovery codes")
            .with_secret("4821-9930\n1102-8871\n7765-0912")
            .with_field(Field::new(
                field_names::NOTES,
                FieldKind::Note,
                "Backup codes for the GitHub account. Each one works once.",
            )),
        Item::new(ItemKind::SshKey, "workstation → build server")
            .with_field(Field::new(
                field_names::PRIVATE_KEY,
                FieldKind::PrivateKey,
                "-----BEGIN OPENSSH PRIVATE KEY-----\n(not a real key)\n-----END OPENSSH PRIVATE KEY-----",
            ))
            .with_field(Field::text(field_names::KEY_COMMENT, "idominikos@cachyos"))
            .with_attribute("host", "build.internal"),
        Item::new(ItemKind::ApiToken, "CI deploy token")
            .with_secret("tok-not-a-real-key-0000")
            .with_attribute("service", "ci.example.internal"),
        Item::new(ItemKind::OAuth, "Nextcloud desktop")
            .with_field(Field::text(field_names::CLIENT_ID, "nc-desktop"))
            .with_field(Field::secret(field_names::CLIENT_SECRET, "oauth-secret-value"))
            .with_field(Field::secret(field_names::REFRESH_TOKEN, "rt_abc123"))
            .with_attribute("service", "cloud.example.org"),
        Item::new(ItemKind::WifiNetwork, "Home Wi-Fi")
            .with_secret("a-long-wifi-passphrase")
            .with_attribute("xdg:schema", "org.gnome.NetworkManager.Connection")
            .with_attribute("ssid", "Kalamata-5G"),
        Item::new(ItemKind::Card, "Visa ••4242")
            .with_field(Field::secret("number", "4242424242424242"))
            .with_field(Field::text("expiry", "04/29"))
            .with_field(Field::secret("cvv", "123")),
    ];

    for item in items {
        vault.add_item_default(item);
    }

    // A second collection, to exercise multi-collection handling.
    let mut work = Collection::new("Work");
    work.items.push(
        Item::new(ItemKind::Login, "Jira")
            .with_secret("jira-password")
            .with_field(Field::text(field_names::USERNAME, "d.ioannou"))
            .with_attribute("service", "jira.corp"),
    );
    vault.add_collection(work);
    vault.save()?;

    println!(
        "seeded {} items across {} collections at {path}",
        vault.data().item_count(),
        vault.data().collections.len()
    );
    Ok(())
}
