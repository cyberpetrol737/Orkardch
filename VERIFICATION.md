# What was verified, and where

Orkardch was built and tested in a **Linux container (Node.js 22) with no internet access**, not on
an Android phone and not with your real TunnelR. This page says exactly what that does and does not
prove, so you know what to confirm on your phone.

## Automated tests (`npm test`): 130 tests, all passing, no internet needed

| Area | What is proven |
|---|---|
| Hashing | known SHA-256/SHA-1/MD5 vectors; empty file; a 160 MB file hashed in a stream with bounded memory; source files never modified; cancel works |
| File forensics | type from contents (renamed files, ZIP/Office/ODF refinement); EXIF (little and big endian, GPS, orientation, dates and time zones); PNG chunks; PDF info, XMP, encryption; Office/ODF properties; truncated, corrupt, junk and decompression-bomb inputs; export withholds GPS, paths and personal details by default |
| Network engine | IP classification (private, loopback, reserved, mapped, IPv6, malformed); DNS found/missing/NXDOMAIN/failed kept distinct; Termux-style resolver failure falling back to DNS-over-HTTPS; RDAP, Team Cymru and certificate-log parsing; local-server TCP/HTTP checks; a live TLS handshake with a self-signed certificate; active checks refused without authorization |
| Offline mode | zero `fetch` calls, zero DNS queries, and no TLS/TCP/HTTP connections in every network-facing module; friendly messages in the UI |
| Network layer | timeouts, bounded retries, per-host rate limiting, cache hit/expiry/clear/bypass, size limits, secret redaction in logs |
| Web intelligence | provider parsers (Wikipedia, GDELT, DuckDuckGo, Brave); bot protection, rate limits and missing keys reported per source; real URLs, publishers and dates retained and labelled; failed pages keep URL and reason; de-duplication; archive captures; comparison; exports |
| Evidence correlator | record validation; evidence immutability; import; guarded delete; archive integrity hash; exact vs structural vs fuzzy links with cautions; contradictions with both sides; repeated claims **not** counted as independent until shown; derived copies; text graph widths |
| Reports | four formats; required sections; sensitive withholding; secret redaction; XSS-safe, self-contained HTML with a blocking CSP |
| TunnelR adapter | not-found handling; discovery by name/package/Git remote; read-only inspection (file snapshot proves nothing changed); `.env` and key files never read; command splitting refuses shell operators; nothing launches without confirmation; foreground exit codes; background start/monitor/stop; immediate failures shown unchanged |
| Mother | every lesson covers the nine teaching points; every prompt in the app has context help (a test scans the source for step ids); every result kind has an explainer; errors explained; TunnelR lesson contains only inspected facts |
| Navigation and robustness | the real program run as a separate process: banner, menu, invalid/empty/hostile input, end of input, Ctrl+C, aliases, `--doctor`, `--offline`, ASCII/narrow screens, damaged settings, closed pipes; launcher install/uninstall from any folder |
| Real terminal | the program inside a pseudo-terminal: colours, raw-mode Ctrl+C, and handing the terminal to a child process (TunnelR fixture) and back |

Measured here: about 95 ms and 56 MB to reach the menu (bare Node.js is 41 MB); 96 MB peak while hashing
a 160 MB file; no module code is loaded until it is opened.

## Acceptance checklist

| # | Criterion | Status |
|---|---|---|
| 1 | `orkardch` launches | verified on Linux (launcher tests, real-process tests). **Confirm on your phone:** `sh install-termux.sh` |
| 2 | Banner and menu appear | verified, including ASCII fallback and 28-column screens |
| 3 | Navigation without memorising commands | verified |
| 4 | Mother explains every module simply | verified (all 7 lessons, every prompt) |
| 5 | Hashing works on real files | verified; output cross-checked against the system `sha256sum` |
| 6 | Metadata for supported formats; missing metadata handled | verified on synthetic files built by the tests. Not tried on your own photos and documents |
| 7 | Web results keep real source URLs | verified against mocked providers. **Live results need your phone:** `orkardch --doctor --online` |
| 8 | IP and DNS results come from real lookups | **not verifiable here** (no internet). The code calls the real resolver and services; parsing and fallbacks are tested with realistic mock answers. Run `orkardch --doctor --online` on your phone |
| 9 | Correlation keeps provenance and finds contradictions | verified |
| 10 | Reports export | verified (JSON, Markdown, text, HTML) |
| 11 | Offline mode prevents unintended external requests | verified for every module |
| 12 | TunnelR integration reflects the actual project | **cannot be verified here:** your TunnelR was not available. The adapter reads the real folder at run time and was tested on a synthetic fixture. See [TUNNELR-ADAPTER.md](TUNNELR-ADAPTER.md) for what remains to be connected |
| 13 | Tests pass | 130/130 |
| 14 | Works without paid API keys | verified (no key is needed anywhere) |
| 15 | README matches the implementation | reviewed against the code at packaging time |

## Not tested at all

Android itself (Termux's Node.js build, Android storage permissions, the Termux font and terminal),
macOS and Windows, real-world files and websites, real RDAP/crt.sh/GDELT/DuckDuckGo/Brave/Wikipedia
responses, and the real TunnelR. None of these should block you, and `orkardch --doctor --online`
checks the network side in about a second. If anything misbehaves, press `?` for Mother, then check
the log at `~/.local/share/orkardch/logs/orkardch.log`.
