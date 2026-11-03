'use strict';
const crypto = require('crypto');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

/*
 * Mother's lessons. Everything is stored locally; nothing is sent anywhere.
 * Each lesson covers: what it does, input, where information comes from, how to run it,
 * a normal result, common errors, what results cannot prove, saving/exporting, and going back.
 * Examples use harmless sample data and say so.
 */
const LESSONS = [
  {
    id: 'forensics', title: 'Image and file forensics', module: 'forensics',
    what: [
      'This tool looks at a file on your phone, like a photo or a PDF.',
      'It tells you what the file really is, makes a "fingerprint" of it, and shows little hidden notes inside it, such as which camera took a photo.',
      'It only looks. Your original file is never changed.',
    ],
    input: [
      'A file on your phone. You can type its path (its address), or type a folder name and pick from a numbered list.',
      'Tip: your phone\'s Downloads and Pictures are inside ~/storage/shared. Run termux-setup-storage once so Termux is allowed to see them.',
    ],
    source: [
      'Everything is worked out on your phone. Nothing is sent over the internet.',
      'There are three kinds of information: the file\'s own bytes (its real type and fingerprint), hidden notes written inside the file (metadata), and dates kept by your phone\'s filesystem.',
    ],
    howTo: [
      '1. From the main menu, choose [1] Image & File Forensics.',
      '2. Choose "Inspect a file" and pick your file.',
      '3. Say whether you also want the older SHA-1 and MD5 fingerprints. Most people say no.',
      '4. If the file has GPS coordinates, Orkardch asks before showing them. They tell where a photo was probably taken.',
      '5. Read the result. Then you can save findings, export a report, or save the fingerprint to re-check later.',
    ],
    normal: [
      'A normal result shows the type, size, a SHA-256 fingerprint, a few phone dates, and sometimes camera, software, dates or author inside the file.',
      'Many files have no hidden notes at all. Websites and chat apps often remove them. That is normal.',
    ],
    errors: [
      { when: '"I could not find..."', meaning: 'The path is wrong or the file moved.', fix: 'Check the spelling, or type the folder and pick from the list.' },
      { when: '"Android would not let Orkardch read..."', meaning: 'Termux does not have permission for that folder.', fix: 'Run termux-setup-storage and tap Allow, or copy the file into the Termux home folder.' },
      { when: '"HEIC/HEIF metadata is not supported"', meaning: 'iPhone-style photos hide their notes in a format this version cannot read yet.', fix: 'Convert a copy to JPEG and inspect that.' },
      { when: '"No embedded metadata was found"', meaning: 'The file has no hidden notes, or they were removed.', fix: 'Nothing is wrong. Not having notes proves nothing by itself.' },
    ],
    cannot: [
      'Dates and notes inside a file can be edited by anyone, so they are claims, not proof.',
      'Your phone\'s dates change when a file is copied or downloaded, so they do not show when it was first made.',
      'A fingerprint can show two files are identical. It cannot tell you who made a file or whether its contents are true.',
    ],
    save: [
      'After a result, choose "Export this report" for a text or JSON file. Orkardch asks before including GPS, your folder path, or author names.',
      'Choose "Save findings to an investigation" to keep the result with its source, ready for the Evidence Correlator.',
    ],
    back: 'Type 0 to go back one step, or the word "menu" to jump to the main menu.',
    example() {
      const a = sha('hello');
      const b = sha('hello!');
      return {
        intro: 'A hash is like a digital fingerprint for a file. If the file\'s contents change, its fingerprint will usually change too. Here is a harmless live example using two tiny pieces of text:',
        lines: [`The text "hello" has the fingerprint:`, `  ${a}`, 'Now add one exclamation mark: "hello!"', `  ${b}`, 'One tiny change gave a completely different fingerprint. That is why fingerprints are good at noticing that a file changed.'],
      };
    },
  },
  {
    id: 'web', title: 'Public web intelligence', module: 'web',
    what: [
      'This tool researches a topic using public sources, like Wikipedia and news sites.',
      'For every result it keeps the real link and the time it looked, so you can check later. If a page cannot be opened, it keeps the link and tells you why. It never makes up results.',
    ],
    input: [
      'Words ("solar panel recycling"), a website name (example.com), or a full web address.',
      'You will be asked one thing: "What do you want to research?"',
    ],
    source: [
      'Public search sources: Wikipedia, GDELT (news), DuckDuckGo (best effort) and Brave Search if you add your own free key.',
      'Opening a result contacts that website. Old versions come from the Internet Archive (archive.org). Your search words are sent to the sources; nothing else about you is.',
    ],
    howTo: [
      '1. Choose [2] Public Web Intelligence, then "Research something".',
      '2. Type what you want to learn about.',
      '3. Look at the "Where the results came from" list. Some sources may fail; that is okay.',
      '4. Open a result to see what the page says, who published it, and when. Open several at once if you like.',
      '5. Compare two results, see old versions, or record a claim from a source.',
    ],
    normal: [
      'A normal result is a short numbered list. Each has a title, a publisher, a date (or "date unknown"), and whether the page was opened.',
      'It is normal for one source to fail or be blocked, and for some pages to have no date.',
    ],
    errors: [
      { when: '"showed a bot check"', meaning: 'A search site thought you were a robot and asked for a puzzle.', fix: 'Orkardch does not try to get around that. Use the other sources, wait, or add a Brave Search key.' },
      { when: '"too many requests"', meaning: 'A source asked you to slow down.', fix: 'Wait a minute and try again.' },
      { when: '"Offline mode is on"', meaning: 'You switched off network access.', fix: 'Turn offline mode off in Settings.' },
      { when: '"could not open"', meaning: 'The page is gone, needs a login, or refused the request.', fix: 'The link is still saved. Try the archive for an old copy.' },
    ],
    cannot: [
      'One person saying something is a clue. Two independent sources agreeing can be stronger evidence. But we still need to check where the information came from.',
      'A search result is a pointer, not a fact. A page claiming a date does not prove the date.',
      'If many websites repeat one original story, that is still one source.',
    ],
    save: [
      'Choose "Save sources to an investigation" to keep them. Choose "Export this list" for a Markdown, text or JSON file.',
      'Saved searches can be re-run later, and Orkardch will tell you what is new.',
    ],
    back: 'Type 0 to go back, or "menu" for the main menu.',
    example() {
      return {
        intro: 'Here is a made-up example (sample data, not a real search) showing how Orkardch keeps claims apart from facts:',
        lines: [
          'Observed by Orkardch:  the page https://news.example/story was opened on 2026-01-05 at 10:00 UTC.',
          'Claimed by the source: the page says it was published on 2025-12-30.',
          'Careful: the date is what the page says about itself. Orkardch did not confirm it.',
          'That is the difference between what I saw and what a page says.',
        ],
      };
    },
  },
  {
    id: 'network', title: 'IP and network intelligence', module: 'network',
    what: [
      'This tool answers questions like: Who runs this IP address? What does this website\'s DNS say? Which certificates were issued for this domain?',
      'It uses public records. Checks that connect straight to a machine only run after you say you own it or have permission.',
    ],
    input: [
      'An IP address (like 192.0.2.1), a domain (like example.com), or an AS number (like AS64500).',
      'For connectivity checks: a host or web address you own.',
    ],
    source: [
      'DNS answers come from your phone\'s resolver (or a public DNS-over-HTTPS service if the phone\'s resolver is not reachable).',
      'Ownership records come from RDAP, the registries\' public lookup. Routing facts come from Team Cymru over DNS. Certificates come from public logs (crt.sh). Each result shows its source and the time.',
    ],
    howTo: [
      '1. Choose [3] IP & Network Intelligence and pick what you have: an IP, a domain, DNS records, certificates, an AS number.',
      '2. Type it in. Orkardch checks it is valid before asking anyone.',
      '3. Read the plain-English notes under each result.',
      '4. For anything that connects to the target, you will be asked to confirm that you own it or may test it.',
    ],
    normal: [
      'DNS is like the internet\'s address book. It helps a computer find the server for a website. A normal answer is one or more records, such as an A record (an IPv4 address).',
      '"No record" for a type is common. For example, many domains have no AAAA record. That is different from "lookup failed", which means the question could not be answered.',
    ],
    errors: [
      { when: '"not a valid IP address"', meaning: 'The numbers do not form a real address.', fix: 'IPv4 has four numbers from 0 to 255, like 192.0.2.1.' },
      { when: '"does not exist in DNS (NXDOMAIN)"', meaning: 'That name is not registered or is misspelled.', fix: 'Check the spelling.' },
      { when: '"lookup FAILED"', meaning: 'The question could not be answered at all (network down, resolver unreachable, timeout).', fix: 'Check your connection. Orkardch tries a DNS-over-HTTPS service automatically if your resolver cannot be reached.' },
      { when: '"crt.sh is often slow"', meaning: 'The certificate log site is busy.', fix: 'Wait a minute and try again.' },
      { when: '"only runs them after you confirm"', meaning: 'This check connects to the target, so you must say you own it.', fix: 'Say yes only for things you own or may test.' },
    ],
    cannot: [
      'An IP address does not tell you a person\'s name or home. Its location is only approximate and often points to an internet provider, VPN, company or data centre.',
      'Registry data says who an address was assigned to, not who is using it now.',
      'Certificate logs list certificates that were issued. They are not a complete list of a domain\'s sites, and some names may no longer exist.',
      'Not finding a record does not prove it does not exist.',
    ],
    save: ['Every result has a "Save these findings to an investigation" option. Findings keep their source and the time they were observed.'],
    back: 'Type 0 to go back, or "menu" for the main menu.',
    example() {
      return {
        intro: 'DNS is like the internet\'s address book. Here is a sample (made-up numbers from a range reserved for examples, not a real lookup):',
        lines: [
          'Question: what is the address of example.com?',
          'Answer (A record): 192.0.2.10',
          'Another question: who handles email? (MX record) "10 mail.example.com" - the lower number is tried first.',
          'The numbers 192.0.2.x are set aside for examples, so they never belong to a real person.',
        ],
      };
    },
  },
  {
    id: 'correlator', title: 'Evidence correlation', module: 'correlator',
    what: [
      'Think of this as your case folder. It keeps every finding from every tool in one place, with where it came from.',
      'It finds connections, rates how much to trust each finding in plain words, and points out where sources disagree. It never edits your evidence.',
    ],
    input: [
      'Findings saved from other tools, evidence you type in by hand, or a JSON file you import.',
      'For best results, give claims a "subject" and a "property" (like "Acme Corp" and "founding year") so disagreements can be noticed.',
    ],
    source: [
      'Everything is stored on your phone in your investigation files. Each finding records its module, source link or file, and the time it was seen.',
    ],
    howTo: [
      '1. Choose [4] Evidence Correlator and start a new investigation.',
      '2. Save results from the other tools into it, or add evidence by hand.',
      '3. Choose "Find connections, confidence and contradictions".',
      '4. Open a finding to see its source, add a note, or say whether its source is independent.',
    ],
    normal: [
      'You will see counts in five groups: Confirmed by direct observation, Supported by multiple independent sources, Plausible but unverified, Conflicting evidence, and Unknown. Most claims start as "plausible but unverified". That is honest, not bad.',
      'Connections are "exact" (identical values), "structural" (built from known fields, like a DNS record belonging to a domain), or "fuzzy" (only similar).',
    ],
    errors: [
      { when: '"needs the word DELETE"', meaning: 'Deleting is permanent, so Orkardch wants an exact confirmation.', fix: 'Type DELETE in capitals, or cancel.' },
      { when: '"not valid JSON"', meaning: 'The import file has a typo, such as a missing comma or quote.', fix: 'Open it in a text editor. sample-evidence.json shows the right shape.' },
      { when: '"No record of where this came from"', meaning: 'A finding has no source, so it is rated Unknown.', fix: 'Add a link or a description of the source.' },
    ],
    cannot: [
      'Confidence words are not percentages. They come from fixed, visible rules and are not scientific measurements.',
      'Many websites repeating one report count as ONE source unless you mark them independent.',
      'A fuzzy match, like two similar usernames, is a hint. It does not show two accounts belong to one person.',
      'No contradictions found only means no two findings share a subject and property with different values.',
    ],
    save: ['Use "Back up or archive" for a full private copy, or [6] Investigation Reports for something you can read and share.'],
    back: 'Type 0 to go back, or "menu" for the main menu.',
    example() {
      return {
        intro: 'One person saying something is a clue. Two independent sources agreeing can be stronger evidence. But we still need to check where the information came from. A made-up example:',
        lines: [
          'Claim: "Acme Corp was founded in 2010."',
          'Site A says it. Site B says it too. Site B just copied Site A.',
          'That is ONE source repeated, not two. Orkardch rates it "plausible but unverified" until you mark them independent.',
          'If Site C says 2012, Orkardch shows both sides and does not pick one for you.',
        ],
      };
    },
  },
  {
    id: 'reports', title: 'Investigation reports', module: 'reports',
    what: [
      'This turns an investigation into a report you can read later with no internet.',
      'It includes a summary, how you searched, each finding with its source, contradictions, limits, and what to check next.',
    ],
    input: ['An investigation (the open one is offered first) and a format: Markdown, a web page with a graph, plain text, or JSON.'],
    source: ['Only your own saved investigation. Nothing is looked up and nothing is sent anywhere.'],
    howTo: [
      '1. Choose [6] Investigation Reports.',
      '2. Pick the investigation and a format.',
      '3. If it holds GPS positions, author names or folder paths, answer the questions about what to include. The safe answer is the default.',
      '4. Orkardch prints where the file was saved.',
    ],
    normal: ['One or more files in your output folder (Settings shows where). The web-page version opens in any browser, offline, and includes a tappable graph.'],
    errors: [
      { when: 'The report seems nearly empty', meaning: 'The investigation has few findings.', fix: 'Save results from other tools first.' },
      { when: '"[withheld: ...]" appears', meaning: 'A sensitive detail was left out on purpose.', fix: 'Run the report again and say yes to include it, only if you are sure.' },
    ],
    cannot: ['A report shows what you collected. It cannot make weak evidence strong. Read its Limitations section before sharing it.'],
    save: ['The report itself is the file. Share it only if you mean to. API keys are never put in reports.'],
    back: 'Type 0 to go back, or "menu" for the main menu.',
    example() {
      return { intro: 'A tiny sample of the Limitations section (sample text):', lines: ['- A search result or web page is a claim by its author, not a verified fact.', '- Confidence labels are plain categories, not probabilities.', '- Not finding something does not prove it does not exist.'] };
    },
  },
  {
    id: 'settings', title: 'Settings and privacy', module: 'settings',
    what: [
      'Here you choose where files are saved, how long answers are remembered (the cache), how long to wait for websites, which tools are on, and optional API keys.',
      'There is also Offline mode, which stops every network request. File forensics, the case folder and reports still work.',
    ],
    input: ['Numbers, on/off choices, or a folder path, one setting at a time. Press Enter to keep the current value.'],
    source: ['Settings are saved on your phone in ~/.config/orkardch/config.json. The file is readable only by you.'],
    howTo: [
      '1. Choose [7] Settings.',
      '2. Pick a setting and type the new value.',
      '3. Choose "What leaves this phone" any time to see exactly which services each tool talks to.',
    ],
    normal: ['A list of settings with their current values. Changes apply right away and are saved.'],
    errors: [
      { when: '"Cannot write there"', meaning: 'The output folder is not writable.', fix: 'Choose a folder in the Termux home, or run termux-setup-storage first for phone storage.' },
      { when: '"Please enter a number from..."', meaning: 'The value is outside the allowed range.', fix: 'Use a number in the range shown.' },
    ],
    cannot: ['Offline mode stops Orkardch\'s own requests. It cannot control what another program, like TunnelR, does.'],
    save: ['Settings save themselves. "Reset to defaults" restores the starting values and does not touch your investigations.'],
    back: 'Type 0 to go back, or "menu" for the main menu.',
    example() {
      return { intro: 'Offline mode in one sentence:', lines: ['Turn it on, and lookups say "Offline mode is on" instead of contacting anyone, while your local files and investigations keep working.'] };
    },
  },
];

const BASICS = [
  'Orkardch works by menus. Type the number you see, then press Enter.',
  'Type 0 (or "back") to go back one step. Type "menu" to jump to the main menu. At the main menu, 0 leaves Orkardch.',
  'Type ? at any question and I will explain where you are and what your options are.',
  'Ctrl+C cancels what you are doing. It will not break anything. Press it twice at the main menu to leave.',
  'Nothing is sent anywhere unless you use a tool that needs the internet. [7] Settings > "What leaves this phone" lists everything.',
];

const GLOSSARY = [
  ['Hash (fingerprint)', 'A short code made from a file\'s contents. Change the file even a tiny bit and the code changes. SHA-256 is the strong one; SHA-1 and MD5 are old and weak.'],
  ['Metadata', 'Hidden notes inside a file, like the camera model of a photo or the author of a document.'],
  ['EXIF', 'The kind of metadata photos carry: camera, date, settings, sometimes GPS.'],
  ['GPS coordinates', 'Two numbers (latitude and longitude) that say where on Earth. In a photo they show where it was probably taken.'],
  ['IP address', 'A number that identifies a device or server on a network, like 192.0.2.1.'],
  ['DNS', 'The internet\'s address book. It turns names like example.com into addresses.'],
  ['A / AAAA record', 'The address of a server. A is the older IPv4 style, AAAA is the newer IPv6 style.'],
  ['MX record', 'Which mail servers accept email for a domain.'],
  ['NS record', 'Which servers hold the official DNS records for a domain.'],
  ['TXT record', 'A note in DNS. Often used to prove ownership or publish email rules.'],
  ['PTR record', 'The reverse of an A record: the name registered for an address.'],
  ['ASN / AS number', 'A number for a network run by one organisation, such as an internet provider.'],
  ['RDAP', 'The public lookup where registries say who a domain, IP block or AS number was assigned to.'],
  ['Certificate', 'A digital ID card a website shows to prove it is who it says. Browsers check it before showing the lock.'],
  ['Certificate transparency', 'Public logs of certificates that were issued. Useful to see which names a domain has used.'],
  ['Subdomain', 'A name under a domain, like mail.example.com.'],
  ['Provenance', 'Where a piece of information came from, so you can check it.'],
  ['Observation / claim / inference', 'Observation: something a tool or you saw directly. Claim: something a source says. Inference: a conclusion drawn from other evidence.'],
  ['Independent sources', 'Sources that each found something out on their own, not by copying each other.'],
  ['Cache', 'A small saved copy of an earlier answer, so Orkardch does not have to ask again right away.'],
  ['API key', 'A password-like code that some services give you. Orkardch never needs one to work.'],
  ['Offline mode', 'A switch that stops all of Orkardch\'s network requests.'],
];

module.exports = { LESSONS, BASICS, GLOSSARY };
