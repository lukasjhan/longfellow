// Demo: PRIVACY-PRESERVING REVOCATION on top of a full SD-JWT-VC ZK proof.
//
// The issuer embeds a per-credential `revocation_id` (an _sd claim, never
// disclosed). Its _sd digest is the 256-bit `rev_id`. A revocation authority
// (CRA) sorts the revoked ids and signs the open gaps `epoch ‖ l ‖ r` between
// adjacent revoked ids. To prove non-revocation the holder presents a CRA-signed
// span with `l < rev_id < r` — in zero knowledge, so the verifier learns neither
// rev_id nor which credential it is (unlinkability is preserved). Properties:
//   [2] not revoked            -> ACCEPT
//   [3] revoked (on the list)  -> REJECT  (no signed gap brackets rev_id)
//   [4] span not CRA-signed    -> REJECT  (forged revocation status)
//   [5] stale span (old epoch) -> REJECT  (freshness / epoch pin)
//   [6] tampered MAC link      -> REJECT  (both circuits, cross-linked)
//
// Run:  node src/demo-revocation.js   (after build:native)

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/sdjwt_revoc_split');
const GEN = path.join(ROOT, 'tools/gen-sdjwt.mjs');
const FIX = path.join(ROOT, 'fixtures/sdjwt.txt');
const JWK = path.join(ROOT, 'fixtures/issuer-jwk.json');
const CLAIMS = 'age_over_18';
const VCT = 'https://credentials.example/pid';
const NONCE = '1234567890';
const AUD = 'https://verifier.example';
const EPOCH = '7'; // verifier's current revocation-list epoch
const line = () => console.log('─'.repeat(70));

function sh(cmd, args, env = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', process.env.DEBUG === '1' ? 'inherit' : 'pipe'],
    env: { ...process.env, ...env },
  });
}

// Run the revocation prover; return {ok, accept, out}. A revoked / bad-sig / stale
// credential makes the witness unsatisfiable, so proving itself fails (nonzero
// exit) — that is the strongest form of rejection.
function runRevoc(env = {}) {
  try {
    const out = sh(BIN, [FIX, JWK, '1700000000', CLAIMS, VCT, NONCE, AUD, EPOCH], env);
    return { ok: true, accept: /ACCEPT|PASS/.test(out), out };
  } catch (e) {
    return { ok: false, accept: false, out: (e.stdout || '').toString() };
  }
}

function main() {
  if (!fs.existsSync(BIN)) {
    console.error('sdjwt_revoc_split not found — run: pnpm run build:native');
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE — SD-JWT-VC with a per-credential `revocation_id` (in _sd)');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN]); console.log('  issued fresh credential → fixtures/'); }
    catch { console.log('  (gen failed; using committed fixture)'); }
  } else {
    console.log('  using committed fixture (no node_modules for gen)');
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [2] NOT revoked → must ACCEPT (rev_id falls in a CRA-signed gap)');
  line();
  const ok = runRevoc();
  console.log(`  → ${ok.accept ? 'ACCEPT ✅ (not revoked, proven in ZK)' : 'REJECT ❌'}`);
  if (!ok.accept) throw new Error('a non-revoked credential must ACCEPT');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] REVOKED → must REJECT (rev_id is on the list; no gap brackets it)');
  line();
  const rev = runRevoc({ REVOKED: '1' });
  console.log(`  → ${rev.accept ? 'ACCEPT ❌ (revocation broken!)' : 'REJECT ✅ (cannot prove non-membership)'}`);
  if (rev.accept) throw new Error('SOUNDNESS: a revoked credential was accepted!');

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
  console.log('  ✅ privacy-preserving revocation on SD-JWT-VC — signed-span non-membership');
  console.log('     rev_id = _sd digest of `revocation_id`; prove l < rev_id < r in ZK.');
  console.log('     constant-size proof regardless of list size; rev_id never revealed.');
  console.log('═'.repeat(70) + '\n');
}

main();
