# TunnelR adapter

`tunnelr-adapter.js` connects Orkardch to **your existing TunnelR project** without
assuming what it is. It reads the real folder and describes what it finds.

## What it does

| Function | Purpose |
|---|---|
| `quickStatus(ctx)` | cheap check of the saved path (used by `--doctor`; no scanning) |
| `findCandidates(ctx, {cwd})` | bounded, read-only search: saved path, `TUNNELR_PATH`, cwd and parents, and folders under `~` and common project/storage folders matched by name, `package.json` name or Git remote |
| `inspect(ctx, dir)` | README summary, `package.json`/Python/Go/Rust markers, top-level files, dependency status, Git facts, launch options, flagged patterns, config-file names |
| `describe(ctx)` | cached summary used by the menu and by Mother's TunnelR lesson |
| `splitCommand(text)` | turns typed text into argv; refuses shell operators |
| `runForeground(ctx, {argv, cwd})` | runs with the terminal handed over; returns exit code or spawn error |
| `startBackground / status / stop / tailFile` | background run with log file, pid record, uptime, and stop |

## Guarantees (each covered by tests)

* Never writes inside the TunnelR folder; never changes Git history or the index (`GIT_OPTIONAL_LOCKS=0`).
* Never opens `.env`, `*.key`, `*.pem`, `id_rsa*`, or secret/credential/token-named files.
* Never runs anything without showing the exact command and getting a yes. No shell is used.
* Never installs dependencies. If some are missing it tells you which.
* Shows TunnelR's own output and exit codes unchanged (secrets Orkardch knows are redacted).
* Keeps its own pointer (`~/.config/orkardch/tunnelr.json`) apart from TunnelR's configuration.
* Verifies a recorded background process still matches before stopping it (guards against reused PIDs).

## Launch options it can discover

`npm run start|dev|serve` and `bin` entries from `package.json`; `main`; `main.py`, `app.py`,
`__main__.py`, `cli.py`, `tunnelr.py`; `run.sh`, `start.sh`, `tunnelr.sh`; `go run .`; `cargo run`.
Anything else: "Type my own command" (optionally remembered).

## What remains to be connected

The real TunnelR was **not available while this was built**, so these depend on what it actually is:

1. **Its real entry point.** If it is not one of the layouts above, choose "Type my own command" once
   and let Orkardch remember it.
2. **TunnelR-specific health.** "Status" currently means "is the process alive, and what did it print".
   If TunnelR exposes its own status command, API or log format, add a small reader in `adapter.js`
   (`status()` is the place) and an option in `index.js`.
3. **TunnelR-specific lessons.** Mother quotes the README and manifest. If TunnelR has a richer doc
   (a documentation folder), point `summarizeReadme` at it.
4. **Evidence from TunnelR.** There is no integration that turns TunnelR output into findings, because
   it is not known whether it produces any. Add a mapper like `network-intelligence-findings.js` if it does.

Manual setup you may need: `pkg install nodejs git`, `npm install` inside TunnelR, and
`termux-setup-storage` if it is stored in phone storage.
