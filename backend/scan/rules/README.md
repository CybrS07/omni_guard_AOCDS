# YARA rules

Starter rules shipped with the app. Every `*.yar` / `*.yara` file here is compiled when the scan service starts.

Rules pulled by Git sync (Settings -> Updates) are stored in the data folder, NOT here, and are loaded in addition to
these. A synced file with the same name as a bundled file replaces the bundled one.

Each rule should carry this `meta:` block, which the dashboard shows:

    meta:
        description = "one sentence a normal person can read"
        severity    = "high"      // critical | high | medium | low
        author      = "you"

`omni_linux.yar` has 7 Linux rules (reverse shells, curl | sh, persistence, miners, Python shells, packed ELF, package install scripts).
