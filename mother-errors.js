'use strict';

/** Plain-English explanations for errors. Matched against code, kind and message text. */
const RULES = [
  { re: /FILE_NOT_FOUND|ENOENT/i, title: 'File or folder not found', meaning: 'The path does not point to anything. It may be misspelled, or the file was moved.', fix: ['Check the spelling.', 'Type the folder path and pick the file from the numbered list.', 'Phone storage is under ~/storage/shared (run termux-setup-storage first).'] },
  { re: /PERMISSION_DENIED|EACCES|EPERM/i, title: 'Permission denied', meaning: 'Android or the file\'s permissions do not let Termux read or write there.', fix: ['Run termux-setup-storage and tap Allow.', 'Or copy the file into the Termux home folder first.', 'For the output folder, pick one inside the Termux home.'] },
  { re: /IS_DIRECTORY|EISDIR|NOT_A_FILE/i, title: 'That is a folder, not a file', meaning: 'This step needs a single file.', fix: ['Open the folder and pick a file inside it.'] },
  { re: /MALFORMED|BAD_IP/i, title: 'Not a valid IP address', meaning: 'The text does not form a real IP address.', fix: ['IPv4 is four numbers from 0 to 255 separated by dots, like 192.0.2.1.', 'IPv6 looks like 2001:db8::1.'] },
  { re: /OFFLINE_MODE|offline-mode/i, title: 'Offline mode is on', meaning: 'You switched off network access, so Orkardch did not contact anyone.', fix: ['Open [7] Settings and turn Offline mode off.', 'If you started with --offline, restart without it.'] },
  { re: /rate-limited|HTTP_429|too many requests/i, title: 'Slow down (rate limit)', meaning: 'The service says too many requests came too fast.', fix: ['Wait a minute and try again.', 'Orkardch already spaces requests and caches answers.'] },
  { re: /BLOCKED|bot-protection|bot check/i, title: 'Blocked by bot protection', meaning: 'The site showed a "prove you are human" check. Orkardch does not get around those.', fix: ['Use the other search sources.', 'Try again later.', 'Add a free Brave Search key in Settings for a more reliable source.'] },
  { re: /HTTP_404|not found \(moved|404/i, title: 'Page not found', meaning: 'The address no longer leads anywhere.', fix: ['The link is still saved.', 'Try "See old versions" to look in the Internet Archive.'] },
  { re: /HTTP_403|refused access|HTTP_401|needs a login/i, title: 'Access refused', meaning: 'The site would not let Orkardch in. It may need a login or block automated visits. Orkardch does not bypass logins.', fix: ['Open it in your own browser if you have access.', 'Look for an archived copy.'] },
  { re: /HTTP_5\d\d|server problem|502|503|504/i, title: 'The server had a problem', meaning: 'The other side is down or overloaded. This is not your fault.', fix: ['Wait a bit and try again.'] },
  { re: /TIMEOUT|ETIMEDOUT|ETIMEOUT|did not answer in time|timed out/i, title: 'No answer in time', meaning: 'The other side did not reply before the time limit. The network may be slow or blocking it.', fix: ['Check your connection.', 'Try again.', 'You can raise the timeout in Settings.'] },
  { re: /ENOTFOUND|EAI_AGAIN|kind.?dns|name could not be found/i, title: 'Name could not be found', meaning: 'DNS could not turn that name into an address. The name may be misspelled, or your DNS is not working.', fix: ['Check the spelling.', 'Check that you are online.'] },
  { re: /ECONNREFUSED/i, title: 'Connection refused', meaning: 'Nothing accepted the connection. For DNS in Termux this often means the phone has no local resolver, which Orkardch works around with DNS-over-HTTPS.', fix: ['For a website: the port may be closed or a firewall is blocking it.', 'For DNS: leave DNS mode on "auto" in Settings.'] },
  { re: /CERT_HAS_EXPIRED/i, title: 'Certificate expired', meaning: 'The site\'s digital ID card is out of date.', fix: ['If it is your site, renew the certificate.', 'Check your phone\'s date and time are right.'] },
  { re: /SELF_SIGNED|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER|ALTNAME|CERT_NOT_YET_VALID|kind.?tls|Secure connection problem/i, title: 'Secure connection problem', meaning: 'The site\'s certificate could not be trusted: it may be self-signed, for another name, incomplete, or your phone\'s clock may be wrong.', fix: ['Check your phone\'s date and time.', 'If it is your own site, check its certificate setup.'] },
  { re: /ESERVFAIL|EREFUSED|DOH_STATUS/i, title: 'The DNS server reported a failure', meaning: 'The question reached DNS, but the answer was an error. The domain\'s own name servers may be broken.', fix: ['Try again later.', 'A "lookup failed" is different from "no record".'] },
  { re: /EJSON|BAD_JSON|not valid JSON|CT_BAD_JSON/i, title: 'Not valid JSON', meaning: 'The text is not in the exact format JSON needs, for example a comma or quote is missing.', fix: ['Open the file in a text editor and look near the place mentioned.', 'sample-evidence.json shows a working file.'] },
  { re: /BAD_RECORD|BAD_IMPORT/i, title: 'An evidence record was rejected', meaning: 'A record is missing a required part, such as "type" or "value".', fix: ['Each record needs a type and a value.', 'See sample-evidence.json.'] },
  { re: /NOT_CONFIRMED/i, title: 'Not confirmed, so nothing changed', meaning: 'A risky action needs a clear yes. It was not given.', fix: ['Try again and type the confirmation word exactly.'] },
  { re: /NOT_AUTHORIZED|ACTIVE_CHECKS_OFF/i, title: 'Active check not allowed', meaning: 'Checks that connect to a target need your confirmation that you own it or may test it, and the setting must be on.', fix: ['Answer yes only for systems you own or have permission to test.', 'Check Settings > Network preferences > Active checks.'] },
  { re: /TUNNELR_UNREADABLE/i, title: 'TunnelR folder could not be read', meaning: 'Orkardch could not open the folder it was pointed to.', fix: ['Check the path.', 'Run termux-setup-storage if it is in phone storage.', 'Use "Choose a different TunnelR folder".'] },
  { re: /SIGNAL_SIG/i, title: 'TunnelR was ended by a signal', meaning: 'The operating system or something else told it to stop (SIGINT is what Ctrl+C sends). If you did not expect this, check the program\'s own output and the Android battery settings for Termux.', fix: ['Read TunnelR\'s own messages above.', 'Android may stop background programs to save battery: allow Termux to run in the background.'] },
  { re: /EXIT_\d+|SPAWN_FAILED/i, title: 'TunnelR stopped with an error', meaning: 'TunnelR ran and then quit with a non-zero code, or could not start. Orkardch shows its messages unchanged.', fix: ['Read TunnelR\'s own messages above or in the log.', 'Check that its dependencies are installed (see "How to run it").'] },
  { re: /CORRUPT/i, title: 'An investigation file looks damaged', meaning: 'The file could not be read as an investigation. Your other investigations are fine.', fix: ['Restore a backup if you made one (Back up or archive).'] },
  { re: /NO_PARSE|GDELT_TEXT/i, title: 'A search source answered oddly', meaning: 'The answer was not in the expected shape. The service may have changed or complained about the search.', fix: ['Try other words, or wait a few seconds.', 'The other sources still work.'] },
  { re: /FETCH_FAILED/i, title: 'The page could not be opened', meaning: 'Orkardch kept the link and noted the reason, but did not analyse the page.', fix: ['Try again later, or look for an archived copy.'] },
];

function explainError(err) {
  if (!err) return null;
  const hay = `${err.code || ''} ${err.kind || ''} ${err.message || ''}`;
  const hit = RULES.find((r) => r.re.test(hay));
  if (hit) return { title: hit.title, meaning: hit.meaning, fix: hit.fix };
  return {
    title: 'Something did not work',
    meaning: `Orkardch reported: "${String(err.message || err.code || 'unknown problem').slice(0, 160)}".`,
    fix: ['Try again.', 'Type "back" and re-enter the information.', 'If it keeps happening, check ~/.local/share/orkardch/logs/orkardch.log (secrets are removed from it).'],
  };
}

module.exports = { explainError, RULES };
