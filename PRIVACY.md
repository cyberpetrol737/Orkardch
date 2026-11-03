# What leaves your phone

Orkardch has **no accounts, no telemetry, no analytics and no background services**. It contacts
a network service only when you use a tool that needs one, and only with what that tool needs.
The same list is available in the app: **Settings → What leaves this phone**.

| Tool | Stays on the phone | Sent over the network, and to whom |
|---|---|---|
| Image & File Forensics | everything (files are only read) | nothing |
| Public Web Intelligence | investigations, cache | your search words → Wikipedia (`en.wikipedia.org`), GDELT (`api.gdeltproject.org`), DuckDuckGo (`html.duckduckgo.com`), and Brave (`api.search.brave.com`, only if you added a key, which is sent as that service's token header). Opening a result → that page's own website (and any site it redirects to). Old versions → the page address to `web.archive.org` |
| IP & Network Intelligence | investigations, cache | the IP/domain/AS you typed → `rdap.org` (which forwards to the registry that owns the data), DNS lookups (see below), `crt.sh` for certificate logs, `stat.ripe.net` only if you say yes to a location lookup. Active checks → connect straight to the target after you confirm |
| Evidence Correlator, Reports | everything | nothing |
| TunnelR | pointer in Orkardch's settings, logs of background runs | nothing from Orkardch. What TunnelR itself sends is up to TunnelR |
| Mother | all lessons | nothing. No question, input or result is ever sent to an AI service |

**DNS.** Lookups go to the DNS resolver your phone uses (or servers you set in Settings). Routing
lookups for an IP ask names under `cymru.com` (Team Cymru). If the phone's resolver cannot be reached
(common in Termux), Orkardch asks a DNS-over-HTTPS provider instead: `cloudflare-dns.com` or
`dns.google` (your choice in Settings). Those providers then see the names you look up.

**`orkardch --doctor --online`** sends three small requests: DNS for `example.com`, one HTTPS request
to Wikipedia, and one RDAP lookup for `example.com`.

**Offline mode** (Settings, or `--offline`) stops every request listed above, including DNS,
TLS/TCP checks and HTTP checks. Local tools keep working. Orkardch cannot control another program
you start, such as TunnelR.

## What is stored on the phone

| Data | Location | Notes |
|---|---|---|
| Settings, optional API key | `~/.config/orkardch/config.json` | owner-only (mode 600); key hidden when typed, masked on screen |
| Investigations and saved fingerprints | `~/.local/share/orkardch/` | local only; delete from the menu (needs `DELETE`) |
| Cache of network answers | `~/.local/share/orkardch/cache/` | expires (default 60 minutes), clearable in Settings, can be turned off |
| Log | `~/.local/share/orkardch/logs/orkardch.log` | structured lines; API keys and tokens are redacted; no page contents or investigation data |
| Exports and reports | `~/orkardch-output/` (changeable) | created only when you export; sensitive details withheld unless you say yes |

## Redaction

API keys, bearer tokens, `api_key=`/`password=`/`token=` style values and credentials in URLs are
removed from logs, reports, and TunnelR output that Orkardch displays or saves.
