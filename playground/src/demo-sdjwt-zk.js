// M5 demo: full SD-JWT-VC selective-disclosure ZERO-KNOWLEDGE proof,
// Approach C (membership over the signed `_sd` set). Unlike the substring
// jwt_cli, this proves a BOOLEAN claim (age_over_18=true) and checks expiry.
//
//   1) issue   : generate a real ES256 SD-JWT-VC (if deps available) or reuse
//                the committed fixture
//   2) present+verify : native sdjwt_full builds the circuit, ZK-proves
//                "issuer-signed + not expired + age_over_18 ∈ _sd = true",
//                then verifies. (prove+verify in one process.)
//   3) expired : same with now > exp → REJECT (soundness)
//
// Run:  pnpm run demo:sdjwt-zk   (after build:native)

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/sdjwt_full');
const FIX = path.join(ROOT, 'fixtures/sdjwt.txt');
const JWK = path.join(ROOT, 'fixtures/issuer-jwk.json');
const line = () => console.log('─'.repeat(70));

function sh(cmd, args, opts = {}) {
  const debug = process.env.DEBUG === '1';
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', debug ? 'inherit' : 'pipe'],
    ...opts,
  });
}

function runFull(now) {
  try {
    const out = sh(BIN, [FIX, JWK, String(now)]);
    return { ok: /ACCEPT/.test(out), out };
  } catch (e) {
    return { ok: false, out: (e.stdout || '').toString() };
  }
}

function main() {
  if (!fs.existsSync(BIN)) {
    console.error(`sdjwt_full not found — run: pnpm run build:native`);
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE — real ES256 SD-JWT-VC (with _sd disclosures)');
  line();
  // Try to (re)issue a fresh token; fall back to the committed fixture.
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try {
      sh('node', [path.join(ROOT, 'tools/gen-sdjwt.mjs')]);
      console.log('  issued fresh SD-JWT-VC → fixtures/');
    } catch {
      console.log('  (gen failed; using committed fixture)');
    }
  } else {
    console.log('  using committed fixture (no node_modules for gen)');
  }
  const compact = fs.readFileSync(FIX, 'utf8').trim();
  const segs = compact.split('~');
  console.log('  token:', compact.length, 'chars,', Math.max(0, segs.length - 2), 'disclosures + Key Binding');

  console.log('\n' + '─'.repeat(70));
  console.log('  [2] PRESENT + VERIFY — ZK prove 3 attrs (given_name+age_over_18+height) ∈ _sd, not expired');
  line();
  const v1 = runFull(1700000000); // now < exp
  process.stdout.write(v1.out.split('\n').filter((l) => /circuit:|proof:|result:/.test(l)).map((l) => '  ' + l.trim()).join('\n') + '\n');
  if (!v1.ok) throw new Error('expected ACCEPT');
  console.log('  → ACCEPT ✅  (boolean claim disclosed in ZK; signature & other claims hidden)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] EXPIRED — now > exp → REJECT (soundness)');
  line();
  const v2 = runFull(9999999999);
  console.log(`  → ${v2.ok ? 'ACCEPT ❌(unexpected)' : 'REJECT ✅'}`);
  if (v2.ok) throw new Error('expired credential was accepted!');

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ full SD-JWT-VC selective-disclosure ZK — mdoc parity & beyond');
  console.log('     issuer sig + Key Binding + sd_hash 바인딩 + exp + 3-attr _sd');
  console.log('     membership (mixed types incl. boolean/number), one ZK proof.');
  console.log('     sd_hash 바인딩: 회로가 SHA(presented)==KB의 sd_hash 를 검증해');
  console.log('     "공개한 disclosure ⊆ 홀더가 서명한 제시 묶음" 을 강제.');
  console.log('═'.repeat(70) + '\n');
}

main();
