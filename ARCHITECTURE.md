# Architecture

Orkardch is a plain Node.js (>= 18) program with **no runtime dependencies**, built for a phone:
modest memory, no background services, nothing loaded until needed.

```
orkardch.js               tiny entry point
cli-main.js               argument parsing, banner, main menu, module opening
cli-ui.js                 colours, box drawing (Unicode or ASCII), tables that become cards on narrow screens
cli-prompt.js             line reader (piped input, Ctrl+C, Ctrl+D) and the Asker: text/confirm/select/menu
cli-registry.js           the module list; code is require()d only when a module is opened
cli-launcher.js           installs/removes the "orkardch" command (marker-protected)
cli-doctor.js             installation self-check, optional live lookups
core-*.js                 config (validated), net client, cache, logger, session, context
<tool>-index.js           the menu of each tool, exporting { id, title, run(ctx) }
<tool>-*.js               that tool's engine (parsers, lookups, analysis, renderers)
mother-*.js               lessons, error and result explainers, context help
storage-*.js              atomic JSON writes, investigation store, saved fingerprints
security-redact.js        secret redaction used by logs and reports
```

The project is one flat folder: a file name is the old folder name plus the file name
(`network-intelligence-dns.js`, `tunnelr-adapter.js`, `mother-index.js`). Tools are
`file-forensics`, `web-intelligence`, `network-intelligence`, `evidence-correlator`, `tunnelr`,
`reports` and `settings`. Files are loaded with plain `require('./name')`.

## The context (`ctx`)

Every module receives one object: `config`, `ui`, `ask`, `session`, `net`, `dns`, `store`, `paths`,
`log` and `services` (the Node built-ins `fetch`, `dns`, `tls`, `net`, `http`, `https`,
`child_process`, and a clock). Because built-ins arrive through `ctx.services`, tests replace them with
fakes, so **no test touches the internet**.

## Safety layers for the network

1. `ctx.requireOnline()` gives flows a friendly "Offline mode is ON" message before they ask questions.
2. `NetClient.get()` refuses in offline mode, rate-limits per host, enforces timeouts, limits body
   size, retries a bounded number of times, and caches successes.
3. DNS, RDAP, certificate, TLS, TCP and HTTP helpers each check the same offline gate. Active checks
   additionally require `authorized: true` (the UI asks the person) and the `activeChecks` setting.

## Navigation

Prompts throw `NavSignal('back' | 'menu' | 'exit')`. `Asker.menu()` catches `back`, shows errors from
items without crashing, and returns `'left'` when it closes, so a submenu never closes its parent.
`?` at any prompt calls Mother's `contextHelp`, using what modules recorded in `ctx.session`
(module, step id, inputs, options, last result, last error).

## The evidence model

An investigation is one JSON file. A finding has:

`id, type, value, statementType (observation | claim | inference), subject, attribute, source
{module, provider, url, file, publisher, retrievedAt, description, importNote}, firstObserved,
lastObserved, supporting, contradicting, verification, independence, sensitive, notes, data`

* Original fields are write-once. Notes, verification and independence are the only things that change,
  and they are stored beside the evidence, never over it.
* Confidence is **computed fresh** by `evidence-correlator-analysis.js` and never stored:
  * `confirmed_direct`: an observation made by Orkardch itself (file, DNS, RDAP, page fetch). It
    confirms what the source returned, not that the real-world statement is true.
  * `multi_independent`: at least two different origins, none derived from another, and the person has
    marked at least two as independent.
  * `plausible`: a single claim, repeats without shown independence, or inferences.
  * `conflicting`: part of a contradiction, or disputed by the person.
  * `unknown`: no provenance.
  * "Origin" = same website (approximate registrable domain) or same publisher. Copies marked
    `derived` count as the origin they copied.
* Relationships are `exact` (identical values), `structural` (from known fields) or `fuzzy`
  (similar only, always with a caution).
* Contradictions group findings by `subject + attribute`. Dates compare by calendar day; names ignore
  Inc/Ltd/etc. Observations made hours apart are labelled `changed-between-observations`, near-identical
  names `possible-variant`, anything else `conflict`. Both sides and sources are always shown.

## Adding a module

1. Create `<name>-index.js` exporting `{ id, title, run(ctx) }` (put its engine in `<name>-*.js`).
2. Add an entry to `MODULES` in `cli-registry.js` (its `dir` is `<name>`) and a `modules.<cfg>` flag in `core-config.js`.
3. Use `ctx.ask.menu/text/confirm/select` with a `step` id; add that step to `STEP_HELP` in
   `mother-index.js` (a test fails if any step has no help).
4. Record `ctx.session.setResult(kind, data)` and add an explainer in `mother-explain.js`.
5. Return findings with a `source` so they can be saved to investigations.

## Decisions worth knowing

* **Zero dependencies**: nothing to install or audit on a phone; EXIF, ZIP, PDF and OOXML readers are
  small purpose-built parsers with bounds checks and size caps.
* **Streaming**: files are hashed in 256 KB chunks; ZIP/PDF/image readers read headers and metadata
  blocks only.
* **Atomic writes**: temp file + rename for settings, investigations, caches and exports.
* **Honesty over polish**: every failure is reported with its reason and nothing is fabricated.
