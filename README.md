# Orkardch

**An all-in-one open-source-intelligence (OSINT) command center for your phone.** It runs in
[Termux](https://termux.dev) on Android, needs no paid services, and has **no npm dependencies**
(just Node.js 18+). You type `orkardch`, pick a number from a menu, and answer plain questions.

| | |
|---|---|
| **1** Image & File Forensics | what a file really is, its SHA-256 "fingerprint", hidden metadata (EXIF, PDF, Office) |
| **2** Public Web Intelligence | source-aware research with real links, retrieval times and archive lookups |
| **3** IP & Network Intelligence | IP/ASN/RDAP, DNS, certificate logs, subdomains, authorized connectivity checks |
| **4** Evidence Correlator | one case folder: provenance, connections, plain-word confidence, contradictions |
| **5** TunnelR | connects to *your own* TunnelR project, found and read from its real files |
| **6** Investigation Reports | JSON, Markdown, text, or a self-contained HTML report with a graph |
| **7** Settings | folders, timeouts, API keys (optional), offline mode, "what leaves this phone" |
| **M** Mother | a built-in teacher that explains every screen in very simple language |

Everything stays on your phone unless you use a tool that needs the internet, and
[Settings → "What leaves this phone"](PRIVACY.md) lists exactly what that is.

---

## Install (Termux)

```sh
pkg update
pkg install nodejs git unzip        # git and unzip are optional but handy
```

**From your GitHub repository** (see [GITHUB-UPLOAD.md](GITHUB-UPLOAD.md) for how to put the files there):

```sh
git clone <YOUR-REPOSITORY-URL> ~/orkardch
cd ~/orkardch
sh install-termux.sh
```

**Or straight from the ZIP:**

```sh
unzip Orkardch.zip -d ~/orkardch
cd ~/orkardch
sh install-termux.sh
```

The installer checks your Node.js version, installs the `orkardch` command into `$PREFIX/bin`
(the launcher works from any folder), and runs a self-check. It never deletes anything and never
edits your shell startup files. If you prefer to do it by hand:

```sh
node ~/orkardch/orkardch.js --install-launcher
```

> Not on Termux? It also runs on ordinary Linux. The launcher then goes to `~/.local/bin` and
> Orkardch prints the one `export PATH=...` line you may want to add yourself.

### First launch

```sh
orkardch
```

You will see the ORKARDCH banner, the version, a short status summary (system, network, modules,
open investigation), and the numbered menu. Type a number and press Enter. Type `?` at any
question and Mother explains where you are.

To prove the network features work **on your phone** (three tiny requests: DNS, HTTPS, RDAP):

```sh
orkardch --doctor --online
```

---

## Using it

### Moving around (nothing to memorise)

| Type | What happens |
|---|---|
| a number, or a word like `forensics`, `web`, `network` | choose that item |
| `0` or `back` | go back one step (at the main menu, `0` leaves) |
| `menu` | jump to the main menu |
| `?` or `help` | Mother explains the current question, your inputs so far, your last result and last error |
| `Ctrl+C` | cancels what you are doing (press twice at the main menu to leave) |
| `Ctrl+D` | leaves cleanly |

Invalid input, empty answers, network failures and Ctrl+C never crash Orkardch.

### 1. Image & File Forensics

Pick a file by typing its path, or type a folder and choose from a numbered list. You get:

* **File type from its contents**, not its name (a PNG renamed `.jpg` is called out).
* **SHA-256** by default. **SHA-1/MD5** only if you ask, and always labelled as weak legacy hashes.
  Files are read in small pieces, so huge files do not fill your RAM.
* **Phone filesystem times**, kept separate from **metadata inside the file**, with a reminder
  that timestamps can be changed and do not prove when a file was created.
* **Photos:** camera, lens, orientation, dates (with time zone only if recorded), exposure,
  software, dimensions, and GPS. Missing fields are never invented.
* **PDF:** title, author, producer, creation/modification dates, version, page count, encryption.
* **Word/Excel/PowerPoint and OpenDocument:** title, author, last saved by, dates, application,
  and whether a macro part exists (reported only, never read or run).
* **Compare** two files, **export** as text or JSON, **save a fingerprint** and **re-check** it later.

Before showing GPS coordinates it warns you and asks. Exports leave out GPS, your folder path, and
author/serial details unless you say yes. Your original file is never modified.

### 2. Public Web Intelligence

Ask *"What do you want to research?"* and type words, a website, or a web address.

* Sources: Wikipedia, GDELT (news), DuckDuckGo (best effort), and Brave Search *if* you add your
  own free key. A source that is blocked, rate-limited or missing a key is reported, never faked.
* Every result keeps its **real URL**, **publisher**, **dates labelled by what they mean**
  (published vs. first seen vs. retrieved), a **short extractive summary** (the site's own description
  or first paragraph, labelled as such), and short **excerpts**. Pages that cannot be opened keep
  their link and the reason.
* Screens separate **Observed by Orkardch**, **Claimed by the source**, and **Things to be careful about**.
* Open one or several pages, **de-duplicate**, **compare** two results, look at **old versions**
  in the Internet Archive, **record a claim** from a source, **export** lists, **save** to an
  investigation, and **re-run** a saved search later (it tells you what is new).

### 3. IP & Network Intelligence

IP address, domain/hostname, DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, PTR), certificates
and subdomains from public certificate-transparency logs, AS numbers, and connectivity checks.

* Inputs are validated first. Private, loopback, link-local, reserved and malformed addresses are
  explained and **no lookup is made**.
* Registry data comes from RDAP, routing from Team Cymru (over DNS), and an *optional* approximate
  location from RIPEstat (asked first, with the reminder that IP location is approximate and often
  describes a provider, VPN or data centre, never a person's home).
* A **missing record**, a **missing domain (NXDOMAIN)** and a **failed lookup** are shown as three
  different things. In Termux, where the phone has no local DNS resolver, Orkardch automatically
  falls back to DNS-over-HTTPS and says so.
* **Active checks** (TCP latency, HTTP/HTTPS status and timing, live TLS certificate) connect to the
  target, so they only run after you confirm you own it or may test it. They are limited to one host
  and one port, at most five tries, and never scan, probe for weaknesses, or follow redirects.
  There is no exploit, credential or stealth functionality of any kind.

### 4. Evidence Correlator

Create an investigation, then save results from other tools into it (or add evidence by hand, or
import a JSON file such as [sample-evidence.json](sample-evidence.json)).

Each finding records an ID, type, value, **where it came from**, first/last seen, supporting and
contradicting evidence, verification status, and notes. Notes and verification never change the
original evidence. Orkardch then:

* finds **connections**, marked **exact**, **structural** (built from known fields, like a DNS record
  belonging to its domain) or **fuzzy** (only similar: never treated as the same person or company);
* rates confidence in five plain categories: *Confirmed by direct observation*, *Supported by multiple
  independent sources*, *Plausible but unverified*, *Conflicting evidence*, *Unknown*. There are no
  invented percentages. Sites repeating one report count as **one** source until you mark them
  independent;
* shows **contradictions** (dates, names, ownership, claims, file details) with both sides and their
  sources, and never picks a winner;
* draws a **text relationship graph** (the HTML report has a tappable one).

Deleting an investigation needs you to type `DELETE`.

### 5. TunnelR

See [TunnelR integration](#tunnelr-integration) below.

### 6. Investigation Reports

Choose an investigation and a format (Markdown, standalone HTML with graph, text, JSON, or all).
Each report has: title, created/exported timestamps, search methods used, findings, source
references, provenance, contradictions, limitations, confidence assessments, and recommended next
verification steps. Reports are **self-contained and work offline**; the HTML one blocks all
external loads. Orkardch asks before including GPS, personal metadata or local paths, and
API keys are never included.

### 7. Settings

Output folder, cache time, request timeout, parallel requests, which tools are on, optional API key,
colours/box characters, report format, DNS mode, active checks, search sources, **offline mode**
(blocks every network request), clear cache, reset, and **What leaves this phone**.

### M. Mother — Teach Me Everything

> "Hi! I'm Mother. I'll help you understand Orkardch. You don't need to memorize commands. Pick
> something you want to learn, and I'll explain it one small step at a time."

Seven lessons (forensics, web, network, evidence, TunnelR, reports, settings), each with:
**[1]** what the tool does, **[2]** how to use it, **[3]** an example, **[4]** what results mean,
**[5]** fixing an error, **[6]** back to the main menu. Plus *How Orkardch works* and a *glossary*.
Mother is entirely local: lessons are stored in the project and **nothing is sent to any AI service**.
Outside the lessons, press `?` at any question for help about exactly that question, your last
result and your last error. The TunnelR lesson is built from your real TunnelR files, not invented.

---

## Command-line options

```
orkardch                       start the interactive menu
orkardch --doctor              check the installation (uses no network)
orkardch --doctor --online     also run three tiny live lookups
orkardch --install-launcher    install the "orkardch" command
orkardch --uninstall-launcher  remove the command (project and data stay)
orkardch --offline             start with all network access disabled
orkardch --no-color --ascii    plain-text display
orkardch --version | --help
```

## Where things are stored

| What | Where |
|---|---|
| Settings (may hold your optional API key; mode 600) | `~/.config/orkardch/config.json` |
| TunnelR pointer and saved command (Orkardch's own, not TunnelR's) | `~/.config/orkardch/tunnelr.json` |
| Investigations, saved fingerprints, cache, logs | `~/.local/share/orkardch/` |
| Exports and reports (changeable in Settings) | `~/orkardch-output/` |

Overrides: `ORKARDCH_CONFIG_DIR`, `ORKARDCH_DATA_DIR`, `ORKARDCH_OUTPUT_DIR`, `TUNNELR_PATH`,
`NO_COLOR`, `FORCE_COLOR`, `COLUMNS`. Logs are structured JSON lines with secrets removed.

## Dependencies

None to install. Required: **Node.js 18+**. Optional: `git` (TunnelR Git details, updating),
`unzip` (to unpack the ZIP), the Termux:API app (`termux-open` to open a report), and a free
[Brave Search API](https://brave.com/search/api/) key (an extra search source). Orkardch is fully
useful without any key.

## TunnelR integration

TunnelR is **your** project, so Orkardch never assumes what it is. The adapter
([tunnelr-adapter.js](tunnelr-adapter.js), details in
[TUNNELR-ADAPTER.md](TUNNELR-ADAPTER.md)):

1. **Finds it** (read-only): the saved path, `TUNNELR_PATH`, your current folders, and common places
   under your home folder, matching folder names, `package.json` names or Git remotes. You confirm
   or type the path. At most ~500 directory entries are examined.
2. **Reads it**: README, `package.json`/Python/Go/Rust markers, top-level files, dependency
   status, and Git branch/last commit/uncommitted counts (using `GIT_OPTIONAL_LOCKS=0`, so Git state
   is not touched). It never opens `.env`, key or secret-looking files.
3. **Explains it** from those facts (menu → "What is TunnelR?", and Mother's lesson), including
   how it can be started (`npm run start`, `bin` entries, `main.py`, shell scripts, ...).
4. **Flags things worth reviewing** (starts programs, opens listening ports, changes routing,
   asks for root, ...). These are prompts to look closer, not verdicts.
5. **Launches only after you confirm the exact command**, in front (you see its output; Ctrl+C
   stops it) or in the background (logged, with status, last output and stop). Programs run
   directly, never through a shell. Exit codes and errors are shown unchanged.
6. **Keeps separate**: Orkardch stores only a pointer (and an optional saved command) in its own
   settings. It never writes inside the TunnelR folder, never changes its Git history, never
   runs `npm install` for you.

If the folder cannot be found, Orkardch says so and shows how to connect it; nothing is invented.
Manual setup you may need: `pkg install nodejs` (and `git`), `npm install` inside TunnelR if it
has dependencies, `termux-setup-storage` if it lives in phone storage.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Android would not let Orkardch read..." | run `termux-setup-storage`, tap Allow, use `~/storage/shared/...` |
| DNS says the resolver was unreachable (`ECONNREFUSED`) | normal in Termux; Orkardch switches to DNS-over-HTTPS automatically (Settings → Network → DNS mode) |
| Title box looks broken | Settings → Colors → "Box characters: off", or start with `--ascii` |
| `orkardch: command not found` | run `node ~/orkardch/orkardch.js --install-launcher`, then open a new session |
| "crt.sh is often slow" | wait a minute and try again, or use a more specific domain |
| "showed a bot check" | Orkardch will not get around it; use other sources or add a Brave key |
| Everything says "Offline mode is ON" | Settings → Offline mode, or start without `--offline` |
| Something else | press `?` (Mother explains the last error); `orkardch --doctor`; the log is `~/.local/share/orkardch/logs/orkardch.log` |

## Privacy and security notes

* Nothing leaves the phone from forensics, the correlator, reports, or Mother.
* Online tools send only what you typed (and the lookups it implies) to the services listed in
  [PRIVACY.md](PRIVACY.md). **Offline mode** blocks all of it, including DNS.
* API keys are never hard-coded, are stored with owner-only permissions, are hidden when typed, and
  are redacted from logs, reports and TunnelR output.
* Evidence, settings and cache are written atomically; destructive actions need explicit confirmation.
* No exploits, credential attacks, stealth scanning or destructive activity are implemented.
  Active checks need your confirmation each time you test a new target.
* Use Orkardch lawfully. Public data can still be sensitive; collect and share only what you need.

## Known limitations

* **The network features were built and tested against mocks and local servers.** The build
  environment had no internet access, so live lookups were not exercised there. Run
  `orkardch --doctor --online` on your phone to confirm DNS, HTTPS and RDAP work for you. Providers
  can change their formats; a failure is reported per source and never papered over.
* **The real TunnelR was not available during the build.** The adapter was tested on a synthetic
  fixture project. If TunnelR is unusual, use "Type my own command" when launching.
* Photos: HEIC/HEIF metadata is not read; MakerNotes are not decoded; only the first EXIF block is used.
* PDF: metadata inside compressed object streams is not unpacked (Orkardch says when it finds none).
  Files over 24 MB are scanned only at the start and end.
* ZIP64 archives and encrypted Office parts are not read.
* Web pages: simple HTML extraction. Pages that need JavaScript, logins or paywalls may yield little.
  Only single pages are fetched; there is no crawling.
* Public-suffix handling for "same website" detection is approximate (no public-suffix list).
* Orkardch does not search social networks for usernames. Usernames enter the correlator by hand or
  import, and matches are labelled as hints.
* Screens narrower than 28 columns are not supported. Box characters depend on your Termux font.
* Tested on Linux with Node 22. Windows and macOS were not tested.

## Testing

```sh
npm test            # same as: node --test
node --test tests-forensics.test.js     # a single file
```

130 tests cover: hashing (known vectors, empty and 160 MB files, streaming, no modification), EXIF/PDF/
Office parsing (including damaged, truncated and malicious files), IP/DNS/RDAP/CT parsing with mocks,
local-server connectivity and TLS checks, offline mode making zero requests, timeouts, retries,
caching, rate limiting, secret redaction, evidence analysis (exact vs fuzzy, contradictions,
independence rules), report safety (withholding, XSS-safe self-contained HTML), the TunnelR adapter,
Mother's coverage of every prompt, menu navigation, and the real program run as a separate process.
No test needs the internet.

## Update and uninstall

**Update** (Git clone, no local changes): `sh update.sh` (fast-forward only; never discards work).
From a new ZIP: extract to a *new* folder and run `sh install-termux.sh` there. Settings and
investigations live outside the project folder and carry over.

**Uninstall:** `orkardch --uninstall-launcher` removes only the command (and only if Orkardch created
it). Your project folder, settings, investigations and exports are not touched. To remove everything
yourself, delete `~/orkardch`, `~/.config/orkardch`, `~/.local/share/orkardch` and `~/orkardch-output`.

## Project layout

**Everything is in one flat folder, with no sub-folders.** (That is what lets you send the files
around as a single list.) A file's name starts with the part of the program it belongs to:

```
orkardch.js                    the program you start (node orkardch.js, or just: orkardch)
cli-*.js                       banner, menus, prompts, launcher, self-check
core-*.js                      settings, network client (offline gate, cache, limits), logger, context
file-forensics-*.js            tool 1: types, hashes, EXIF, PDF, Office, comparison, export
web-intelligence-*.js          tool 2: search providers, pages, archive, sources, export
network-intelligence-*.js      tool 3: IP, DNS, RDAP, certificates, active checks
evidence-correlator-*.js       tool 4: confidence, connections, contradictions, graph
tunnelr-*.js                   tool 5: the TunnelR adapter and its menu
reports-*.js                   tool 6: report model and the four formats
settings-index.js              tool 7: settings and privacy
mother-*.js                    Mother: lessons, error and result explainers, context help
storage-*.js  security-*.js    atomic files, investigations, secret redaction   utils-*.js: small helpers
tests-*.js                     the 130 tests (tests-helpers-*.js are shared test helpers)
install-termux.sh  update.sh   install and update helpers
*.md                           this guide and the other documents
sample-evidence.json           fictional evidence to practise with
package.json  package-lock.json  .gitignore
```

More: [ARCHITECTURE.md](ARCHITECTURE.md) · [PRIVACY.md](PRIVACY.md) ·
[TUNNELR-ADAPTER.md](TUNNELR-ADAPTER.md) · [GITHUB-UPLOAD.md](GITHUB-UPLOAD.md) ·
[VERIFICATION.md](VERIFICATION.md)

*License: none chosen yet. Add a `LICENSE` file before sharing the project publicly.*
