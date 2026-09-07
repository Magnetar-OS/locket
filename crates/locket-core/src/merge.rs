//! Reconciling two copies of the same vault.
//!
//! The XChaCha20 nonce choice was made so a vault could ride a file
//! synchroniser between machines, and a file synchroniser's failure mode is a
//! fork: both sides edited since the last sync, and one copy — usually named
//! something like `default.sync-conflict-…​.vault` — holds edits the other
//! does not. This module folds the two back into one without losing either
//! side's work.
//!
//! # Rules
//!
//! Everything is matched by id and decided by timestamp; nothing depends on
//! which copy the person happened to open first, so merging A into B and B
//! into A produce the same set of items.
//!
//! - **Items live on both sides**: the newer `modified` wins. If their
//!   contents actually differ, the loser is kept as a revision in the
//!   winner's history — the merge never silently discards an edit, it files
//!   it. On a tie, the side being merged *into* wins, which only matters
//!   when the contents differ under equal timestamps (a fork the clocks
//!   cannot arbitrate; the loser still lands in history).
//! - **Live here, trashed there**: whichever event is newer wins. A deletion
//!   after the last edit propagates; an edit after the deletion resurrects.
//! - **Only on one side**: kept — as live or as trashed, wherever it was.
//! - **Collections**: matched by id; the newer side names them; collections
//!   only in the incoming copy are created. An item that moved collections
//!   follows its winning side's placement.
//! - **Settings** stay as the receiving vault has them: they carry no
//!   timestamp to arbitrate with, and a merge should never quietly change a
//!   retention window.
//!
//! Attachments ride with their item: the winning side's attachment list is
//! kept whole. History snapshots never carry attachments (see
//! [`crate::model::Revision`]), so an attachment added on the losing side of
//! a conflicted edit is the one thing a merge can drop — the report counts
//! that case so the UI can say so instead of leaving it to be noticed.

use uuid::Uuid;

use crate::model::{Item, Revision, TrashedItem, VaultData, now};

/// What a merge did, in numbers the UI can print.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Items that existed only in the incoming copy.
    pub added: usize,
    /// Items where the incoming copy's edit won; the local state went into
    /// the winner's history.
    pub updated: usize,
    /// Items the incoming copy had deleted more recently than we edited.
    pub trashed: usize,
    /// Items we held in the trash that the incoming copy edited after the
    /// deletion — brought back.
    pub restored: usize,
    /// Collections created because only the incoming copy had them.
    pub collections_added: usize,
    /// Conflicted edits where the losing side carried attachments the winner
    /// does not have; those attachments are gone, and the UI should say so.
    pub attachments_dropped: usize,
}

impl MergeReport {
    /// Whether the merge changed anything at all.
    pub fn changed(&self) -> bool {
        *self != Self::default()
    }
}

impl std::fmt::Display for MergeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} added, {} updated, {} deleted, {} restored, {} collections added",
            self.added, self.updated, self.trashed, self.restored, self.collections_added
        )
    }
}

/// Fold `other` into `data`. See the module docs for the rules.
pub fn merge(data: &mut VaultData, other: VaultData) -> MergeReport {
    let mut report = MergeReport::default();

    // Collections first, so every incoming item has somewhere to land.
    for c in &other.collections {
        match data.collection_mut(c.id) {
            Some(ours) => {
                if c.modified > ours.modified {
                    ours.label = c.label.clone();
                    ours.alias = c.alias.clone();
                    ours.modified = c.modified;
                }
            }
            None => {
                let mut created = c.clone();
                created.items = Vec::new();
                data.collections.push(created);
                report.collections_added += 1;
            }
        }
    }

    for (collection, theirs) in other
        .collections
        .iter()
        .flat_map(|c| c.items.iter().map(move |i| (c.id, i)))
    {
        merge_live_item(data, collection, theirs, &mut report);
    }

    for t in other.trash {
        merge_trashed_item(data, t, &mut report);
    }

    report
}

fn merge_live_item(
    data: &mut VaultData,
    their_collection: Uuid,
    theirs: &Item,
    report: &mut MergeReport,
) {
    // Live on both sides?
    if let Some((ours_collection, ours)) = data.find_item(theirs.id) {
        let ours_collection = ours_collection.id;
        if theirs.modified > ours.modified {
            // Their edit is newer: replace ours, filing our state in their
            // history, and follow their collection placement.
            let ours = data
                .remove_item(theirs.id)
                .expect("item was just found live");
            let mut winner = theirs.clone();
            absorb_loser(&mut winner, &ours, report);
            let target = resolve_collection(data, their_collection);
            data.collection_mut(target)
                .expect("collection resolved to an existing one")
                .items
                .push(winner);
            report.updated += 1;
        } else if Item::content_differs(ours, theirs) {
            // Ours is newer (or the fork tied): keep ours, file theirs.
            let id = theirs.id;
            if let Some(ours) = data
                .collection_mut(ours_collection)
                .and_then(|c| c.items.iter_mut().find(|i| i.id == id))
            {
                absorb_loser(ours, theirs, report);
            }
        }
        return;
    }

    // Live there, trashed here?
    if let Some(t) = data.trashed(theirs.id) {
        if theirs.modified > t.deleted {
            // Edited after we deleted it: the edit wins.
            data.purge_item(theirs.id);
            let target = resolve_collection(data, their_collection);
            data.collection_mut(target)
                .expect("collection resolved to an existing one")
                .items
                .push(theirs.clone());
            report.restored += 1;
        }
        // Otherwise our deletion is newer: it stays in the trash.
        return;
    }

    // Only on their side: bring it in where they had it.
    let target = resolve_collection(data, their_collection);
    data.collection_mut(target)
        .expect("collection resolved to an existing one")
        .items
        .push(theirs.clone());
    report.added += 1;
}

fn merge_trashed_item(data: &mut VaultData, t: TrashedItem, report: &mut MergeReport) {
    // Trashed there, live here?
    if data.find_item(t.item.id).is_some() {
        let ours_modified = data
            .find_item(t.item.id)
            .map(|(_, i)| i.modified)
            .expect("item was just found live");
        if t.deleted >= ours_modified {
            // Deleted after our last edit: the deletion propagates. Keep
            // *our* copy of the item in the trash — it is the newer-or-equal
            // content by the check above only when timestamps tie, so prefer
            // the trashed copy's own content, which the deleting side saw.
            data.trash_item(t.item.id);
            if let Some(entry) = data.trash.iter_mut().find(|e| e.item.id == t.item.id) {
                entry.deleted = t.deleted;
            }
            report.trashed += 1;
        }
        // Otherwise our edit is newer than their deletion: stays live.
        return;
    }

    match data.trash.iter_mut().find(|e| e.item.id == t.item.id) {
        // Trashed on both sides: keep one, under the newer deletion time so
        // the retention window counts from the later of the two deletes.
        Some(ours) => ours.deleted = ours.deleted.max(t.deleted),
        // Only their trash has it: carry it over, retention and all.
        None => data.trash.push(t),
    }
}

/// File the losing side of a conflicted edit into the winner's history.
fn absorb_loser(winner: &mut Item, loser: &Item, report: &mut MergeReport) {
    if !Item::content_differs(winner, loser) {
        return;
    }
    if loser
        .attachments
        .iter()
        .any(|a| winner.attachment(a.id).is_none())
    {
        report.attachments_dropped += 1;
    }
    winner.history.push(Revision {
        saved: now(),
        item: loser.snapshot(),
    });
    winner.trim_history();
}

/// The collection an incoming item should land in: where the winning side had
/// it if that collection exists here, the default collection otherwise.
fn resolve_collection(data: &mut VaultData, wanted: Uuid) -> Uuid {
    if data.collection(wanted).is_some() {
        wanted
    } else {
        data.default_collection_mut().id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Collection, ItemKind, VaultSettings};

    fn vault_with(label: &str, secret: &str) -> (VaultData, Uuid) {
        let mut data = VaultData::default();
        let item = Item::new(ItemKind::Login, label).with_secret(secret);
        let id = item.id;
        data.default_collection_mut().items.push(item);
        (data, id)
    }

    /// Two forks of one vault: cloning is what a file synchroniser does.
    fn fork(data: &VaultData) -> VaultData {
        data.clone()
    }

    #[test]
    fn an_item_only_on_one_side_is_kept() {
        let (mut a, _) = vault_with("Shared", "s");
        let mut b = fork(&a);

        let only_b = Item::new(ItemKind::Note, "Only in B").with_secret("b");
        let only_b_id = only_b.id;
        b.default_collection_mut().items.push(only_b);

        let report = merge(&mut a, b);
        assert_eq!(report.added, 1);
        assert!(a.find_item(only_b_id).is_some());
        assert_eq!(a.item_count(), 2);
    }

    #[test]
    fn the_newer_edit_wins_and_the_loser_lands_in_history() {
        let (base, id) = vault_with("Login", "original");
        let mut a = fork(&base);
        let mut b = fork(&base);

        // A edits first, B edits later: B's secret must win in either
        // direction of merge, with the other state kept as a revision.
        {
            let item = a.collection_mut(a.collections[0].id).unwrap().items.first_mut().unwrap();
            item.secret = "from A".into();
            item.modified = 1_000;
        }
        {
            let item = b.collection_mut(b.collections[0].id).unwrap().items.first_mut().unwrap();
            item.secret = "from B".into();
            item.modified = 2_000;
        }

        let mut a_into_b = fork(&b);
        merge(&mut a_into_b, fork(&a));
        let mut b_into_a = fork(&a);
        let report = merge(&mut b_into_a, fork(&b));

        for merged in [&a_into_b, &b_into_a] {
            let (_, item) = merged.find_item(id).expect("item survived the merge");
            assert_eq!(item.secret.expose(), "from B", "the newer edit lost");
            assert_eq!(item.history.len(), 1, "the losing edit was not filed");
            assert_eq!(item.history[0].item.secret.expose(), "from A");
        }
        assert_eq!(report.updated, 1);
    }

    #[test]
    fn merge_is_symmetric_in_what_survives() {
        let (base, _) = vault_with("Login", "original");
        let mut a = fork(&base);
        let mut b = fork(&base);

        let a_only = Item::new(ItemKind::Note, "A note").with_secret("a");
        a.default_collection_mut().items.push(a_only);
        let b_only = Item::new(ItemKind::Note, "B note").with_secret("b");
        b.default_collection_mut().items.push(b_only);

        let mut ab = fork(&a);
        merge(&mut ab, fork(&b));
        let mut ba = fork(&b);
        merge(&mut ba, fork(&a));

        let mut ab_ids: Vec<Uuid> = ab.all_items().map(|(_, i)| i.id).collect();
        let mut ba_ids: Vec<Uuid> = ba.all_items().map(|(_, i)| i.id).collect();
        ab_ids.sort();
        ba_ids.sort();
        assert_eq!(ab_ids, ba_ids, "merge produced different item sets by direction");
    }

    #[test]
    fn a_deletion_newer_than_the_last_edit_propagates() {
        let (base, id) = vault_with("Login", "s");
        let mut a = fork(&base);
        let mut b = fork(&base);

        // Pin A's edit clock well in the past, then delete on B "later".
        a.collections[0].items[0].modified = 1_000;
        b.collections[0].items[0].modified = 1_000;
        b.trash_item(id);
        b.trash[0].deleted = 2_000;

        let report = merge(&mut a, b);
        assert_eq!(report.trashed, 1);
        assert!(a.find_item(id).is_none(), "deleted item still live after merge");
        assert!(a.trashed(id).is_some(), "deletion did not land in the trash");
    }

    #[test]
    fn an_edit_newer_than_the_deletion_resurrects() {
        let (base, id) = vault_with("Login", "s");
        let mut a = fork(&base);
        let mut b = fork(&base);

        a.trash_item(id);
        a.trash[0].deleted = 1_000;
        {
            let item = &mut b.collections[0].items[0];
            item.secret = "edited after the delete".into();
            item.modified = 2_000;
        }

        let report = merge(&mut a, b);
        assert_eq!(report.restored, 1);
        let (_, item) = a.find_item(id).expect("edited item was not resurrected");
        assert_eq!(item.secret.expose(), "edited after the delete");
        assert!(a.trashed(id).is_none(), "restored item still in the trash");
    }

    #[test]
    fn trashed_on_both_sides_keeps_one_under_the_newer_deletion() {
        let (base, id) = vault_with("Login", "s");
        let mut a = fork(&base);
        let mut b = fork(&base);

        a.trash_item(id);
        a.trash[0].deleted = 1_000;
        b.trash_item(id);
        b.trash[0].deleted = 2_000;

        merge(&mut a, b);
        assert_eq!(a.trash.len(), 1, "both trash entries were kept");
        assert_eq!(a.trash[0].deleted, 2_000, "the newer deletion time lost");
    }

    #[test]
    fn a_collection_only_on_one_side_arrives_with_its_items() {
        let (base, _) = vault_with("Login", "s");
        let mut a = fork(&base);
        let mut b = fork(&base);

        let mut work = Collection::new("Work").with_alias("work");
        let moved = Item::new(ItemKind::Login, "Work login").with_secret("w");
        let moved_id = moved.id;
        work.items.push(moved);
        let work_id = work.id;
        b.collections.push(work);

        let report = merge(&mut a, b);
        assert_eq!(report.collections_added, 1);
        let (c, _) = a.find_item(moved_id).expect("item in the new collection");
        assert_eq!(c.id, work_id, "item did not land in its own collection");
        assert_eq!(c.label, "Work");
    }

    #[test]
    fn an_item_moved_between_collections_follows_the_newer_side() {
        let (base, id) = vault_with("Login", "s");
        let mut a = fork(&base);
        let mut b = fork(&base);
        a.collections[0].items[0].modified = 1_000;

        // B moves the item to a new collection and edits it later.
        let mut item = b.collections[0].items.remove(0);
        item.modified = 2_000;
        let mut work = Collection::new("Work");
        let work_id = work.id;
        work.items.push(item);
        b.collections.push(work);

        merge(&mut a, b);
        let (c, _) = a.find_item(id).expect("moved item survived");
        assert_eq!(c.id, work_id, "the winning side's placement was ignored");
    }

    #[test]
    fn identical_forks_merge_to_a_no_op() {
        let (a, _) = vault_with("Login", "s");
        let mut merged = fork(&a);
        let report = merge(&mut merged, fork(&a));
        assert!(!report.changed(), "identical copies reported changes: {report}");
        assert_eq!(merged.item_count(), 1);
        assert!(merged.all_items().all(|(_, i)| i.history.is_empty()));
    }

    #[test]
    fn settings_are_not_changed_by_a_merge() {
        let (mut a, _) = vault_with("Login", "s");
        a.settings.trash_retention_days = Some(7);
        let mut b = fork(&a);
        b.settings = VaultSettings {
            trash_retention_days: None,
        };

        merge(&mut a, b);
        assert_eq!(a.settings.trash_retention_days, Some(7));
    }

    #[test]
    fn a_losing_side_with_attachments_is_counted_as_dropped() {
        let (base, id) = vault_with("Login", "s");
        let mut a = fork(&base);
        let mut b = fork(&base);

        {
            let item = &mut a.collections[0].items[0];
            item.secret = "a's edit".into();
            item.add_attachment("codes.txt", "text/plain", b"12345".to_vec())
                .unwrap();
            item.modified = 1_000;
        }
        {
            let item = &mut b.collections[0].items[0];
            item.secret = "b's later edit".into();
            item.modified = 2_000;
        }

        let report = merge(&mut a, b);
        assert_eq!(report.updated, 1);
        assert_eq!(
            report.attachments_dropped, 1,
            "an attachment vanished without being counted"
        );
        let (_, item) = a.find_item(id).unwrap();
        assert!(item.attachments.is_empty(), "history snapshots must not carry attachments");
    }
}
