/**
 * Diagnostic: what does an IMAP server advertise, and what does it say to a
 * plain LOGIN attempt? Run: npx tsx scripts/imap-probe.ts <host> [user] [pass]
 */
import tls from 'node:tls';

const host = process.argv[2] || 'outlook.office365.com';
const port = 993;
const user = process.argv[3];
const pass = process.argv[4];

const sock = tls.connect({ host, port, servername: host }, () => {
  console.log(`connected to ${host}:${port}`);
});

let buf = '';
let step = 0;
sock.setEncoding('utf8');
sock.on('data', (d) => {
  buf += d;
  process.stdout.write(d);
  if (step === 0 && /\* OK/i.test(buf)) {
    step = 1;
    sock.write('a1 CAPABILITY\r\n');
  } else if (step === 1 && /a1 (OK|NO|BAD)/i.test(buf)) {
    step = 2;
    if (user && pass) {
      sock.write(`a2 LOGIN "${user}" "${pass}"\r\n`);
    } else {
      sock.write('a2 LOGOUT\r\n');
    }
  } else if (step === 2 && /a2 (OK|NO|BAD)/i.test(buf)) {
    sock.end();
  }
});
sock.on('error', (e) => console.error('socket error:', e.message));
sock.on('end', () => console.log('\n--- connection closed ---'));
