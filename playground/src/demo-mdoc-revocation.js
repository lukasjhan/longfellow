// Demo: PRIVACY-PRESERVING REVOCATION on top of a REAL ISO 18013-5 mdoc ZK
// presentation (two MAC-linked circuits: MdocSignature + MdocHash).
//
// The issuer embeds a per-credential `revocation_id` as a normal mdoc attribute;
// its valueDigests entry (= SHA of the item) is the hidden 256-bit `rev_id`. A
// revocation authority (CRA) signs the open gaps `epoch ‖ l ‖ r` between adjacent
// revoked ids; the hash circuit proves `l < rev_id < r` in ZK — so the verifier
// learns neither rev_id nor which credential it is (unlinkability preserved).
// Constant-size proof regardless of the list size. Properties:
//   [2] not revoked            -> ACCEPT
//   [3] revoked (on the list)  -> REJECT  (no signed gap brackets rev_id)
//   [4] span not CRA-signed    -> REJECT  (forged revocation status)
//   [5] stale span (old epoch) -> REJECT  (freshness / epoch pin)
//   [6] tampered MAC link      -> REJECT  (both circuits, cross-linked)
//
// Run:  node src/demo-mdoc-revocation.js   (after build:native)

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/mdoc_revoc_split');
const GEN = path.join(ROOT, 'tools/gen-mdoc.mjs');
const MDOC = path.join(ROOT, 'fixtures/mdoc.bin');
const ISSUER = path.join(ROOT, 'fixtures/mdoc-issuer.json');
const TR = path.join(ROOT, 'fixtures/mdoc-transcript.bin');
const NOW = '2026-06-01T00:00:00Z';
const ATTR_ID = 'age_over_18';
const ATTR_HEX = 'f5'; // CBOR true
const EPOCH = '7';     // verifier's current revocation-list epoch
const line = () => console.log('─'.repeat(70));

function sh(cmd, args, env = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', process.env.DEBUG === '1' ? 'inherit' : 'pipe'],
    env: { ...process.env, ...env },
  });
}

// Run the mdoc revocation prover; return {accept, out}. A revoked / bad-sig /
// stale credential makes the witness unsatisfiable, so proving itself fails
// (nonzero exit) — the strongest form of rejection.
function runRevoc(env = {}) {
  try {
    const out = sh(BIN, [MDOC, ISSUER, TR, NOW, ATTR_ID, ATTR_HEX, EPOCH], env);
    return { accept: /ACCEPT \(real mdoc NOT revoked|PASS/.test(out), out };
  } catch (e) {
    return { accept: false, out: (e.stdout || '').toString() };
  }
}

function main() {
  if (!fs.existsSync(BIN)) {
    console.error('mdoc_revoc_split not found — run: pnpm run build:native');
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE — real mdoc with a per-credential `revocation_id` attribute');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN]); console.log('  issued + presented a real mdoc → fixtures/'); }
    catch { console.log('  (gen failed; using committed fixture)'); }
  } else {
    console.log('  using committed fixture (no node_modules for gen)');
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [2] NOT revoked → must ACCEPT (rev_id falls in a CRA-signed gap)');
  line();
  const ok = runRevoc();
  console.log(`  → ${ok.accept ? 'ACCEPT ✅ (not revoked, proven in ZK on a real mdoc)' : 'REJECT ❌'}`);
  if (!ok.accept) throw new Error('a non-revoked mdoc must ACCEPT');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] REVOKED → must REJECT (rev_id is on the list; no gap brackets it)');
  line();
  const rev = runRevoc({ REVOKED: '1' });
  console.log(`  → ${rev.accept ? 'ACCEPT ❌ (revocation broken!)' : 'REJECT ✅ (cannot prove non-membership)'}`);
  if (rev.accept) throw new Error('SOUNDNESS: a revoked mdoc was accepted!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [4] FORGED status → span signed by a non-CRA key → must REJECT');
  line();
  const bad = runRevoc({ BADSIG: '1' });
  console.log(`  → ${bad.accept ? 'ACCEPT ❌ (forgery accepted!)' : 'REJECT ✅ (span must be CRA-signed)'}`);
  if (bad.accept) throw new Error('SOUNDNESS: a non-CRA-signed span was accepted!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [5] STALE → span from a previous epoch → must REJECT (freshness)');
  line();
  const stale = runRevoc({ STALE: '1' });
  console.log(`  → ${stale.accept ? 'ACCEPT ❌ (stale status accepted!)' : 'REJECT ✅ (epoch pinned to current)'}`);
  if (stale.accept) throw new Error('SOUNDNESS: a stale-epoch span was accepted!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [6] TAMPER → flip 1 bit of the cross-circuit MAC → both must REJECT');
  line();
  const tam = runRevoc({ TAMPER: '1' });
  const tamPass = /PASS/.test(tam.out);
  console.log(`  → ${tamPass ? 'REJECT ✅ (MAC link is load-bearing)' : 'FAIL ❌'}`);
  if (!tamPass) throw new Error('SOUNDNESS: MAC tampering was not detected!');

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ privacy-preserving revocation on a REAL mdoc — signed-span non-membership');
  console.log('     rev_id = valueDigests entry of `revocation_id`; prove l < rev_id < r in ZK.');
  console.log('     constant-size proof regardless of list size; rev_id never revealed.');
  console.log('═'.repeat(70) + '\n');
}

main();
