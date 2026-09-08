//! Timings for the operations a person waits on.
//!
//! Not a microbenchmark suite: these are the four things that decide whether
//! the application feels alive, measured end to end on a vault far larger
//! than a real one. Run it and paste the numbers into `docs/performance.md`
//! — a claim about responsiveness that nobody measured is a wish.
//!
//! ```sh
//! cargo run --release -p locket-core --example bench
//! ```
//!
//! Release matters: the debug build spends its time in Argon2 and serde, and
//! the numbers say nothing about what a user would see.

use std::time::Instant;

use locket_core::{
    Vault,
    crypto::KdfParams,
    model::{Field, Item, ItemKind, field_names},
};

const ITEMS: usize = 10_000;

fn fill(vault: &mut Vault) {
    for n in 0..ITEMS {
        let item = Item::new(
            ItemKind::Login,
            format!("Service {n:05} — example{}.test", n % 997),
        )
        .with_secret(format!("p4ssw0rd-{n:05}-#Xq"))
        .with_field(Field::text(field_names::USERNAME, format!("user{n:05}")))
        .with_field(Field::new(
            field_names::URL,
            locket_core::FieldKind::Url,
            format!("https://example{}.test/login", n % 997),
        ));
        vault.add_item_default(item);
    }
}

fn time<T>(label: &str, budget_ms: u128, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let ms = start.elapsed().as_millis();
    let verdict = if ms <= budget_ms { "ok" } else { "OVER BUDGET" };
    println!("{label:<44} {ms:>6} ms  (budget {budget_ms} ms, {verdict})");
    out
}

fn main() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("bench.vault");
    println!(
        "locket performance — {ITEMS} items, {}\n",
        std::env::consts::ARCH
    );

    // Creation runs the KDF once at the shipped cost. This is the number
    // behind "unlocking is supposed to take a moment".
    let mut vault = time("create + derive KEK (Argon2id 64 MiB, t=3)", 1_000, || {
        Vault::create(&path, "correct horse battery staple", KdfParams::default()).expect("create")
    });

    time("build 10k items in memory", 2_000, || fill(&mut vault));
    time("encrypt + write 10k items", 2_000, || {
        vault.save().expect("save")
    });
    drop(vault);

    let vault = time("open: KDF + decrypt + parse 10k items", 1_500, || {
        Vault::open(&path, "correct horse battery staple").expect("open")
    });

    // The two things that happen per keystroke in the list view.
    time("filter 10k items (one search keystroke)", 16, || {
        let hits = vault
            .data()
            .all_items()
            .filter(|(_, i)| i.matches("example42"))
            .count();
        assert!(hits > 0, "the fixture should match");
    });
    time("sort the filtered list", 16, || {
        // The list view's exact ordering: favourites first, then by label.
        let mut items: Vec<_> = vault.data().all_items().map(|(_, i)| i).collect();
        items.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        });
    });

    // The health report is the heaviest thing the UI ever asks for: zxcvbn
    // over every secret. It runs when the screen is opened, not per frame.
    #[cfg(feature = "health")]
    time("health report over 10k items (zxcvbn)", 10_000, || {
        let report = locket_core::health::report(vault.data(), locket_core::model::now());
        assert_eq!(report.scanned, ITEMS);
    });

    println!(
        "\nBudgets: per-keystroke work must fit one 60 Hz frame (16 ms). Unlock is\n\
         allowed to be slow — Argon2id is doing its job — but must stay under a\n\
         second and a half, because the window is showing a spinner for all of it."
    );
}
