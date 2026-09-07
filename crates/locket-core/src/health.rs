//! The password health report: weak, reused, old, expiring.
//!
//! Everything here is computed offline from the decrypted vault — nothing
//! leaves the process. The optional Have I Been Pwned check is deliberately
//! *not* in this module or this crate: it is a network feature, and
//! locket-core does no I/O.
//!
//! What gets scored, and what does not:
//!
//! - Only the primary secret of an item is scored. Extra fields are not,
//!   because a `Secret`-kind field is as often an API answer or a seed as a
//!   password, and scoring those as if a person had chosen them is noise.
//! - Binary secrets are skipped: they are keys, not passwords, and zxcvbn
//!   scoring base64 tells you about base64.
//! - `Application` items are listed for reuse but not for weakness — their
//!   secrets were made by machines, and the application that made a weak one
//!   is not going to read our report.
//!
//! "Old" is measured from the item's `modified` timestamp, which is the
//! closest thing the vault records to "when this secret last changed". An
//! edit that only fixed a label resets it; the report is honest about being
//! an approximation, not a claim.

use std::collections::HashMap;

use uuid::Uuid;

use crate::model::{Item, ItemKind, Timestamp, VaultData};

/// A secret unchanged for this long counts as old.
pub const OLD_AFTER_SECS: u64 = 365 * 86_400;

/// An expiry within this window counts as expiring.
pub const EXPIRING_WITHIN_SECS: u64 = 30 * 86_400;

/// zxcvbn's 0–4 score, named. `Strong` is 4; anything at 2 or below is worth
/// flagging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    VeryWeak,
    Weak,
    Fair,
    Good,
    Strong,
}

impl Strength {
    fn from_score(score: u8) -> Self {
        match score {
            0 => Strength::VeryWeak,
            1 => Strength::Weak,
            2 => Strength::Fair,
            3 => Strength::Good,
            _ => Strength::Strong,
        }
    }

    /// Weak enough that the report should surface it.
    pub fn is_flagged(self) -> bool {
        self <= Strength::Fair
    }

    /// 0.0–1.0, for a meter. Linear in the score, which is what zxcvbn's
    /// own scale is: it is already the log-scaled answer.
    pub fn fraction(self) -> f32 {
        (self as u8 as f32) / 4.0
    }
}

/// Score one password, given the words an attacker would guess first —
/// the account name, the username, the site.
///
/// Public because a passphrase being *chosen* deserves the same estimate as
/// one already stored: the vault-creation screen scores what is being typed
/// with this, and the report below scores what was saved with it.
pub fn strength(password: &str, context: &[&str]) -> Strength {
    Strength::from_score(zxcvbn::zxcvbn(password, context).score().into())
}

/// One item's health, with everything the report lists it for.
#[derive(Debug, Clone)]
pub struct HealthEntry {
    pub id: Uuid,
    pub label: String,
    pub kind: ItemKind,
    /// `None` when the item was not scored: no secret, a binary secret, or
    /// an `Application` item.
    pub strength: Option<Strength>,
    /// How many *other* items hold the same secret.
    pub reused_with: usize,
    /// Days since the item last changed.
    pub age_days: u64,
    pub old: bool,
    pub expired: bool,
    pub expiring: bool,
}

impl HealthEntry {
    /// Whether the report has anything to say about this item.
    pub fn flagged(&self) -> bool {
        self.strength.is_some_and(Strength::is_flagged)
            || self.reused_with > 0
            || self.old
            || self.expired
            || self.expiring
    }
}

/// The whole report, with the counts a summary line wants.
#[derive(Debug, Clone, Default)]
pub struct HealthReport {
    /// Every item that has something worth saying, worst first.
    pub entries: Vec<HealthEntry>,
    /// How many items were considered at all.
    pub scanned: usize,
    pub weak: usize,
    pub reused: usize,
    pub old: usize,
    pub expired: usize,
    pub expiring: usize,
}

impl HealthReport {
    pub fn is_clean(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build the report for everything live in the vault. Trash is not audited:
/// a deleted credential's weakness is already dealt with.
pub fn report(data: &VaultData, at: Timestamp) -> HealthReport {
    let items: Vec<&Item> = data.all_items().map(|(_, item)| item).collect();

    // Reuse first: exact secret equality across items, empty and binary
    // secrets excluded (two portal keys being distinct blobs is expected;
    // two *identical* text passwords is the finding).
    let mut by_secret: HashMap<&str, usize> = HashMap::new();
    for item in &items {
        if !item.secret.is_empty() && !item.secret_is_binary() {
            *by_secret.entry(item.secret.expose()).or_default() += 1;
        }
    }

    let mut entries = Vec::new();
    let scanned = items.len();

    for item in items {
        let strength = score(item);
        let reused_with = if item.secret.is_empty() || item.secret_is_binary() {
            0
        } else {
            by_secret
                .get(item.secret.expose())
                .copied()
                .unwrap_or(1)
                .saturating_sub(1)
        };
        let age_secs = at.saturating_sub(item.modified);
        let old = !item.secret.is_empty() && age_secs >= OLD_AFTER_SECS;
        let expired = item.is_expired(at);
        let expiring = item.expires_within(at, EXPIRING_WITHIN_SECS);

        let entry = HealthEntry {
            id: item.id,
            label: item.label.clone(),
            kind: item.kind,
            strength,
            reused_with,
            age_days: age_secs / 86_400,
            old,
            expired,
            expiring,
        };
        if entry.flagged() {
            entries.push(entry);
        }
    }

    // Worst first: expired outranks weak outranks reused outranks old; the
    // tie-break is alphabetical so the order is stable across runs.
    entries.sort_by(|a, b| {
        severity(b)
            .cmp(&severity(a))
            .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
    });

    let weak = entries
        .iter()
        .filter(|e| e.strength.is_some_and(Strength::is_flagged))
        .count();
    let reused = entries.iter().filter(|e| e.reused_with > 0).count();
    let old = entries.iter().filter(|e| e.old).count();
    let expired = entries.iter().filter(|e| e.expired).count();
    let expiring = entries.iter().filter(|e| e.expiring).count();

    HealthReport {
        entries,
        scanned,
        weak,
        reused,
        old,
        expired,
        expiring,
    }
}

fn severity(e: &HealthEntry) -> u8 {
    if e.expired {
        4
    } else if e.strength.is_some_and(Strength::is_flagged) {
        3
    } else if e.reused_with > 0 {
        2
    } else if e.expiring {
        1
    } else {
        0
    }
}

/// Score one item's primary secret, or say why not with `None`.
fn score(item: &Item) -> Option<Strength> {
    if item.secret.is_empty() || item.secret_is_binary() || item.kind == ItemKind::Application {
        return None;
    }
    // The label and username are the guesses an attacker makes first, so a
    // password equal to either scores what it deserves.
    let username = item.field_value(crate::model::field_names::USERNAME);
    let inputs: Vec<&str> = [Some(item.label.as_str()), username]
        .into_iter()
        .flatten()
        .collect();
    Some(strength(item.secret.expose(), &inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, field_names, now};

    fn vault_of(items: Vec<Item>) -> VaultData {
        let mut data = VaultData::default();
        data.default_collection_mut().items = items;
        data
    }

    #[test]
    fn a_weak_password_is_flagged_and_a_generated_one_is_not() {
        let data = vault_of(vec![
            Item::new(ItemKind::Login, "Bad").with_secret("password1"),
            Item::new(ItemKind::Login, "Good").with_secret("kV9#mQ2$xL8@nR4!wT7z"),
        ]);
        let r = report(&data, now());
        assert_eq!(r.weak, 1);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].label, "Bad");
        assert!(r.entries[0].strength.unwrap().is_flagged());
    }

    #[test]
    fn a_password_equal_to_the_username_scores_very_weak() {
        let strong_looking = "ada.lovelace-1815";
        let data = vault_of(vec![
            Item::new(ItemKind::Login, "Site")
                .with_secret(strong_looking)
                .with_field(Field::text(field_names::USERNAME, strong_looking)),
        ]);
        let r = report(&data, now());
        assert_eq!(r.weak, 1, "a password equal to its username passed");
    }

    #[test]
    fn reuse_counts_the_other_holders_not_itself() {
        let data = vault_of(vec![
            Item::new(ItemKind::Login, "A").with_secret("shared-Secret-9!x"),
            Item::new(ItemKind::Login, "B").with_secret("shared-Secret-9!x"),
            Item::new(ItemKind::Login, "C").with_secret("unique-Secret-3$k9m"),
        ]);
        let r = report(&data, now());
        assert_eq!(r.reused, 2);
        for e in r.entries.iter().filter(|e| e.reused_with > 0) {
            assert_eq!(e.reused_with, 1, "{}", e.label);
        }
        assert!(!r.entries.iter().any(|e| e.label == "C" && e.reused_with > 0));
    }

    #[test]
    fn binary_and_application_secrets_are_not_scored() {
        let mut portal_key = Item::new(ItemKind::Application, "Portal key");
        portal_key.set_secret_bytes(&[0xff, 0xfe, 0x01]);
        let app_text = Item::new(ItemKind::Application, "App token").with_secret("weak");
        let data = vault_of(vec![portal_key, app_text]);
        let r = report(&data, now());
        assert_eq!(r.weak, 0, "machine-made secrets were scored as passwords");
    }

    #[test]
    fn two_identical_binary_secrets_are_not_reported_as_reuse() {
        let mut a = Item::new(ItemKind::Application, "A");
        a.set_secret_bytes(&[0xff, 0xfe]);
        let mut b = Item::new(ItemKind::Application, "B");
        b.set_secret_bytes(&[0xff, 0xfe]);
        let data = vault_of(vec![a, b]);
        let r = report(&data, now());
        assert_eq!(r.reused, 0);
    }

    #[test]
    fn age_and_expiry_are_reported() {
        let at = now();
        let mut old = Item::new(ItemKind::Login, "Old").with_secret("kV9#mQ2$xL8@nR4!wT7z");
        old.modified = at - OLD_AFTER_SECS - 86_400;
        let mut expired = Item::new(ItemKind::Certificate, "Cert");
        expired.expires = Some(at - 1);
        let mut expiring = Item::new(ItemKind::ApiToken, "Token").with_secret("uQ3&fZ8*pM5^dH2@jN6c");
        expiring.expires = Some(at + 86_400);

        let r = report(&vault_of(vec![old, expired, expiring]), at);
        assert_eq!(r.old, 1);
        assert_eq!(r.expired, 1);
        assert_eq!(r.expiring, 1);
        assert!(r.entries[0].expired, "expired must sort first");
        let old_entry = r.entries.iter().find(|e| e.label == "Old").unwrap();
        assert!(old_entry.age_days >= 366);
    }

    #[test]
    fn a_healthy_vault_reports_clean() {
        let data = vault_of(vec![
            Item::new(ItemKind::Login, "A").with_secret("kV9#mQ2$xL8@nR4!wT7z"),
            Item::new(ItemKind::Note, "No secret at all"),
        ]);
        let r = report(&data, now());
        assert!(r.is_clean(), "{:?}", r.entries);
        assert_eq!(r.scanned, 2);
    }

    #[test]
    fn the_shared_scorer_ranks_the_obvious_cases_in_order() {
        assert!(strength("password", &[]) < strength("kV9#mQ2$xL8@nR4!wT7z", &[]));
        assert_eq!(strength("", &[]), Strength::VeryWeak);
        // Context words are guessed first: a passphrase that *is* one scores
        // far worse than the same string with nothing to match against.
        assert!(strength("Locket2026", &["Locket2026"]).is_flagged());
        assert!(
            strength("Locket2026", &["Locket2026"]) < strength("Locket2026", &[]),
            "context words made no difference to the estimate"
        );
        // The meter fraction tracks the score and stays in range.
        assert_eq!(Strength::VeryWeak.fraction(), 0.0);
        assert_eq!(Strength::Strong.fraction(), 1.0);
    }

    #[test]
    fn trash_is_not_audited() {
        let mut data = vault_of(vec![Item::new(ItemKind::Login, "Weak").with_secret("hunter2")]);
        let id = data.collections[0].items[0].id;
        data.trash_item(id);
        let r = report(&data, now());
        assert!(r.is_clean(), "a trashed item was audited");
    }
}
