'use strict';
// Real-terminal tests: the program runs inside a pseudo-terminal (via Python's pty module), so raw
// mode, line editing, colours and genuine Ctrl+C keypresses are exercised, not just piped input.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { spawnSync } = require('child_process');

const BIN = path.join(__dirname, 'orkardch.js');
const HAVE = (() => { try { return spawnSync('python3', ['-c', 'import pty, termios']).status === 0 && process.platform !== 'win32'; } catch { return false; } })();

const PRELUDE = `
import os, pty, sys, time, select, re, tempfile, json, struct, fcntl, termios
BIN = os.environ['ORK_BIN']
home = tempfile.mkdtemp()
env = dict(os.environ, HOME=home, TERM='xterm-256color', LANG='C.UTF-8', COLUMNS='50')
def start(cols=50):
    env['COLUMNS'] = str(cols)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir('/tmp'); os.execvpe(sys.executable and 'node', ['node', BIN], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 30, cols, 0, 0))
    return pid, fd
class Term:
    def __init__(self, pid, fd): self.pid, self.fd, self.buf = pid, fd, b''
    def pump(self, wait=0.7):
        end = time.time() + wait
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try: d = os.read(self.fd, 65536)
                except OSError: return
                if not d: return
                self.buf += d
    def send(self, s, wait=0.7):
        os.write(self.fd, s.encode()); self.pump(wait)
    def status(self):
        for _ in range(6):
            try:
                p, st = os.waitpid(self.pid, os.WNOHANG)
                if p: return st
            except ChildProcessError: return 0
            time.sleep(0.5)
        return -1
    def text(self): return re.sub(rb'\\x1b\\[[0-9;?]*[A-Za-z]', b'', self.buf).decode('utf8', 'replace')
def report(checks):
    for k, v in checks.items(): print(('PASS ' if v else 'FAIL ') + k)
`;

function runPty(body) {
  const r = spawnSync('python3', ['-c', PRELUDE + body], { env: { ...process.env, ORK_BIN: BIN }, encoding: 'utf8', timeout: 60000 });
  const lines = r.stdout.split('\n').filter((l) => /^(PASS|FAIL) /.test(l));
  return { lines, stdout: r.stdout, stderr: r.stderr, status: r.status };
}

test('interactive terminal: colours, line editing, invalid input, real Ctrl+C keypresses, Mother, Settings, clean exit', { skip: !HAVE && 'python3 pty is not available' }, () => {
  const r = runPty(`
t = Term(*start())
t.pump(1.2)
for k in ['banana\\r', '\\x03', 'm\\r', '1\\r', '3\\r', '\\x03', '?\\r', '0\\r', '7\\r', '9\\r', '9\\r', '0\\r']: t.send(k)
t.send('\\x03', 0.4); t.send('\\x03', 1.0)
st = t.status(); tx = t.text()
report({
  'banner': 'OPEN-SOURCE INTELLIGENCE' in tx, 'colour codes in a real terminal': b'\\x1b[3' in t.buf,
  'invalid input handled': "I didn't understand" in tx, 'first Ctrl+C only warns': 'Press Ctrl+C again' in tx,
  'Mother opened': "Hi! I'm Mother" in tx, 'example shown': 'A hash is like a digital fingerprint' in tx,
  'Ctrl+C inside a menu cancels': '(cancelled)' in tx, 'context help': 'Let me help with where you are' in tx or 'Mother:' in tx,
  'settings shown': 'Offline mode:' in tx, 'goodbye': 'Goodbye' in tx, 'exits by itself with code 0': os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0,
})
`);
  const failed = r.lines.filter((l) => l.startsWith('FAIL'));
  assert.ok(r.lines.length >= 10, `no results from the pty script: ${r.stdout}\n${r.stderr}`);
  assert.deepEqual(failed, [], r.stdout);
});

test('TunnelR hand-over in a real terminal: the child owns the keyboard and Ctrl+C, Orkardch gets the terminal back', { skip: !HAVE && 'python3 pty is not available' }, () => {
  const r = runPty(`
proj = os.path.join(home, 'TunnelR'); os.makedirs(proj)
open(os.path.join(proj, 'package.json'), 'w').write(json.dumps({"name": "fixture-tunnel", "scripts": {"start": "node run.js"}}))
open(os.path.join(proj, 'README.md'), 'w').write('# Fixture\\n\\nSynthetic fixture used only by tests.\\n')
open(os.path.join(proj, 'run.js'), 'w').write("""
console.log('FIXTURE-CHILD started');
process.stdin.setEncoding('utf8');
process.stdin.on('data', d => console.log('CHILD-GOT-INPUT:' + d.trim()));
process.on('SIGINT', () => { console.log('FIXTURE-CHILD got SIGINT'); process.exit(7); });
setInterval(() => {}, 1000);
""")
env['NO_COLOR'] = '1'
t = Term(*start(60))
t.pump(1.2)
for k in ['5\\r', 'y\\r', '3\\r', '1\\r']: t.send(k)
t.send('y\\r', 1.5); t.send('hello-child\\r'); t.send('\\x03', 1.5); t.send('0\\r'); t.send('0\\r')
st = t.status(); tx = t.text()
report({
  'folder found and confirmed': 'Connected to' in tx, 'confirmation shown before running': 'Please confirm' in tx and 'Run it now?' in tx,
  'child output visible': 'FIXTURE-CHILD started' in tx, 'keyboard input reached the child': 'CHILD-GOT-INPUT:hello-child' in tx,
  'Ctrl+C reached the child, not Orkardch': 'FIXTURE-CHILD got SIGINT' in tx,
  'a Ctrl+C stop is described as normal, not as an error': 'normal way to stop it' in tx or 'exit code 7' in tx,
  'Orkardch took the terminal back': 'TunnelR output ends' in tx and tx.count('Goodbye') == 1, 'exits by itself with code 0': os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0,
})
`);
  const failed = r.lines.filter((l) => l.startsWith('FAIL'));
  assert.ok(r.lines.length >= 8, `no results from the pty script: ${r.stdout}\n${r.stderr}`);
  assert.deepEqual(failed, [], r.stdout);
});
