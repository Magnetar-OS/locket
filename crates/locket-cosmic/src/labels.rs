//! Translated names for the model's enumerations.
//!
//! `locket-core` carries English labels for [`ItemKind`] and [`FieldKind`]
//! because the CLI and the importers need something to print. The GUI does not
//! reuse them: a catalogue lives here instead, so the core stays free of
//! `i18n-embed` and the desktop still speaks the user's language.

use std::sync::LazyLock;

use locket_core::model::{FieldKind, ItemKind};

use crate::fl;

/// One item of this kind.
pub fn kind(kind: ItemKind) -> String {
    match kind {
        ItemKind::Login => fl!("kind-login"),
        ItemKind::Note => fl!("kind-note"),
        ItemKind::Card => fl!("kind-card"),
        ItemKind::Identity => fl!("kind-identity"),
        ItemKind::SshKey => fl!("kind-ssh-key"),
        ItemKind::GpgKey => fl!("kind-gpg-key"),
        ItemKind::ApiToken => fl!("kind-api-token"),
        ItemKind::OAuth => fl!("kind-oauth"),
        ItemKind::Certificate => fl!("kind-certificate"),
        ItemKind::Environment => fl!("kind-environment"),
        ItemKind::WifiNetwork => fl!("kind-wifi"),
        ItemKind::Application => fl!("kind-application"),
    }
}

/// The category of items of this kind — its own string, not the singular with
/// an `s` stuck on the end.
pub fn kind_plural(kind: ItemKind) -> String {
    match kind {
        ItemKind::Login => fl!("kind-login-plural"),
        ItemKind::Note => fl!("kind-note-plural"),
        ItemKind::Card => fl!("kind-card-plural"),
        ItemKind::Identity => fl!("kind-identity-plural"),
        ItemKind::SshKey => fl!("kind-ssh-key-plural"),
        ItemKind::GpgKey => fl!("kind-gpg-key-plural"),
        ItemKind::ApiToken => fl!("kind-api-token-plural"),
        ItemKind::OAuth => fl!("kind-oauth-plural"),
        ItemKind::Certificate => fl!("kind-certificate-plural"),
        ItemKind::Environment => fl!("kind-environment-plural"),
        ItemKind::WifiNetwork => fl!("kind-wifi-plural"),
        ItemKind::Application => fl!("kind-application-plural"),
    }
}

pub fn field_kind(kind: FieldKind) -> String {
    match kind {
        FieldKind::Text => fl!("field-text"),
        FieldKind::Secret => fl!("field-secret"),
        FieldKind::Url => fl!("field-url"),
        FieldKind::Totp => fl!("field-totp"),
        FieldKind::Note => fl!("field-note"),
        FieldKind::Email => fl!("field-email"),
        FieldKind::Phone => fl!("field-phone"),
        FieldKind::Date => fl!("field-date"),
        FieldKind::PrivateKey => fl!("field-private-key"),
        FieldKind::PublicKey => fl!("field-public-key"),
    }
}

/// Every kind, in `ItemKind::ALL` order, for the editor's dropdown.
///
/// Built once: `dropdown` borrows the slice for the lifetime of the element it
/// returns, and rebuilding a translated list on every frame would allocate
/// twenty strings per redraw for a list that cannot change.
pub static ITEM_KINDS: LazyLock<Vec<String>> =
    LazyLock::new(|| ItemKind::ALL.iter().copied().map(kind).collect());

pub static FIELD_KINDS: LazyLock<Vec<String>> =
    LazyLock::new(|| FieldKind::ALL.iter().copied().map(field_kind).collect());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_translated_name_and_a_category_name() {
        // A missing arm would be a compile error; an empty catalogue entry
        // would not, and would show as a blank row in the sidebar.
        for k in ItemKind::ALL {
            assert!(!kind(*k).is_empty());
            assert!(!kind_plural(*k).is_empty());
        }
        for f in FieldKind::ALL {
            assert!(!field_kind(*f).is_empty());
        }
        assert_eq!(ITEM_KINDS.len(), ItemKind::ALL.len());
        assert_eq!(FIELD_KINDS.len(), FieldKind::ALL.len());
    }
}
