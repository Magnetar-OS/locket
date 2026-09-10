# Performance — measured

**Measured · September 2026 · `cargo run --release -p locket-core --example bench`**
**AMD Ryzen 7 9700X 8-Core Processor · rustc 1.98.1 (88d9e12ae 2026-08-18)**

A claim about responsiveness that nobody measured is a wish. These are the
four things a person actually waits on, timed end to end on a vault of
**10,000 items** — an order of magnitude past a real one, so the numbers are
a ceiling rather than a best case.

Reproduce with:

```sh
cargo run --release -p locket-core --example bench
```

## The numbers

Median of three runs on an otherwise idle machine. Under compile load every
figure roughly doubles, which is worth knowing before reading a single run
as a regression.

| Operation | Time | Budget | Why that budget |
|---|---:|---:|---|
| Create vault + derive KEK (Argon2id, 64 MiB, t=3) | 110 ms | 1000 ms | Deliberately slow; the window shows progress for it |
| Build 10k items in memory | 7 ms | 2000 ms | Import-shaped work |
| Encrypt + write 10k items | 17 ms | 2000 ms | Every save re-seals the whole body |
| Open: KDF + decrypt + parse 10k items | 129 ms | 1500 ms | The unlock a person watches |
| Filter 10k items (one search keystroke) | 1 ms | 16 ms | Must fit one 60 Hz frame |
| Sort the filtered list | 2 ms | 16 ms | Same frame as the filter |
| Health report over 10k items (zxcvbn) | 1605 ms | 10000 ms | Runs when the screen opens, never per frame |

## What the measurement changed

**The health report was blocking the UI thread.** At ten items it is
imperceptible; at ten thousand it is 1.6 seconds of frozen window every time
the Health screen is opened or an item is saved while it is up. It now runs
on a blocking worker with the vault data cloned into it (the clone is
milliseconds — see the "build" row for the shape of that cost), and the
screen fills in when it returns. The benchmark found this; nothing else
would have, because the author's own vault has nine items in it.

**Search and sort are not worth optimising.** Both are comfortably inside a
frame at 10k items, and both are linear — the naive implementations are the
right ones, and an index would be complexity bought with nothing.

**Unlock is the one slow operation, and it is slow on purpose.** 110 ms of
that is Argon2id refusing to be fast, which is the entire point of the
parameter. The number matters because it sets what "Stronger" costs: the
256 MiB preset in Settings is roughly four times this, still under half a
second, which is why it is offered at all.

## What is not measured here

Frame timing inside the compositor — dropped frames, scroll smoothness, the
cost of a redraw with 10,000 rows in the list. That needs a running session
and a profiler attached to the real window, not a headless timing harness,
and it is the open half of the roadmap's reactivity work.
