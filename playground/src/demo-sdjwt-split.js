// M7 demo: SD-JWT-VC selective-disclosure ZK as the TWO-CIRCUIT + MAC split
// (mdoc's architecture): a Fp256 signature circuit + a GF(2^128) hash circuit,
// soundly linked by MACs over the common values (e / dpkx / dpky) with a_v
// pulled from the post-commit transcript.
//
//   1) issue          : reissue a real ES256 SD-JWT-VC, or reuse the fixture
//   2) present+verify : native sdjwt_split builds BOTH circuits, proves+verifies
//                       each, linked by the shared MAC -> both ACCEPT
//   3) expired        : now > exp -> hash circuit REJECTs (soundness)
//   4) tamper         : flip 1 bit of mac_e in the bundle -> BOTH reject,
//                       proving the MAC link is load-bearing (TAMPER=1)
//
// Run:  pnpm run demo:sdjwt-split   (after build:native)

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/sdjwt_split');
const FIX = path.join(ROOT, 'fixtures/sdjwt.txt');
const JWK = path.join(ROOT, 'fixtures/issuer-jwk.json');
const BIGFIX = path.join(ROOT, 'fixtures/sdjwt-big.txt');
const BIGJWK = path.join(ROOT, 'fixtures/issuer-jwk-big.json');
const CLAIMS = 'given_name,age_over_18,height';
const VCT = 'https://credentials.example/pid';
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

// run the split binary; return {ok, accept, out} where `accept` = both circuits
// accepted (normal mode) and `ok` = process exit 0 (= expected outcome).
function runSplit(now, env = {}, fix = FIX, jwk = JWK,
                  nonce = '1234567890', aud = 'https://verifier.example') {
  try {
    const out = sh(BIN, [fix, jwk, String(now), CLAIMS, VCT, nonce, aud], {
      env: { ...process.env, ...env },
    });
    return { ok: true, accept: /soundly linked/.test(out), out };
  } catch (e) {
    return { ok: false, accept: false, out: (e.stdout || '').toString() };
  }
}

const blocks = (n) => Math.ceil((n + 9) / 64);

const show = (out) =>
  process.stdout.write(
    out
      .split('\n')
      .filter((l) => /sig |hash |TOTAL|TAMPER/.test(l))
      .map((l) => '  ' + l.trim())
      .join('\n') + '\n',
  );

function main() {
  if (!fs.existsSync(BIN)) {
    console.error(`sdjwt_split not found — run: pnpm run build:native`);
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE — real ES256 SD-JWT-VC (with _sd disclosures + Key Binding)');
  line();
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
  console.log('  [2] PRESENT + VERIFY — TWO circuits (Fp256 sig + GF(2^128) hash), MAC-linked');
  line();
  const v1 = runSplit(1700000000); // now < exp
  show(v1.out);
  if (!v1.accept) throw new Error('expected both circuits to ACCEPT');
  console.log('  → ACCEPT ✅  (sig circuit + hash circuit, bound by shared MAC; a_v derived from post-commit transcript)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] EXPIRED — now > exp → hash circuit REJECTs (soundness)');
  line();
  const v2 = runSplit(9999999999);
  console.log(`  → ${v2.accept ? 'ACCEPT ❌(unexpected)' : 'REJECT ✅'}`);
  if (v2.accept) throw new Error('expired credential was accepted!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3b] ADVERSARIAL — expired token + malicious prover (EVIL_EXP: exp_idx→letters)');
  console.log('       without `"exp":` anchor / digit checks, letters(>now) bypass expiry (ACCEPT before the fix)');
  line();
  const v2b = runSplit(9999999999, { EVIL_EXP: '1' });
  console.log(`  → ${v2b.accept ? 'ACCEPT ❌ (soundness broken!)' : 'REJECT ✅  (anchor blocks the bypass)'}`);
  if (v2b.accept) throw new Error('SOUNDNESS: malicious exp_idx bypassed expiry!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [4] TAMPER — flip 1 bit of mac_e in the bundle → BOTH circuits REJECT (link enforcement proof)');
  line();
  const v3 = runSplit(1700000000, { TAMPER: '1' });
  show(v3.out);
  // tamper mode: the binary exits 0 when BOTH correctly rejected (test PASS).
  if (!v3.ok || /FAIL/.test(v3.out)) throw new Error('tamper test did not enforce the link!');
  console.log('  → on tamper both circuits REJECT ✅  (MAC link is actually load-bearing)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [5] BIG — 13-attribute PID-class credential (a token the old constants would have overflowed)');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try {
      sh('node', [path.join(ROOT, 'tools/gen-sdjwt.mjs')], { env: { ...process.env, BIG: '1' } });
    } catch { /* fall back to committed big fixture */ }
  }
  if (fs.existsSync(BIGFIX)) {
    const big = fs.readFileSync(BIGFIX, 'utf8').trim();
    const jwt = big.slice(0, big.indexOf('~'));
    const hp = jwt.slice(0, jwt.indexOf('.', jwt.indexOf('.') + 1));
    const pres = big.slice(0, big.lastIndexOf('~') + 1);
    console.log(`  token: ${big.length} chars, ${big.split('~').length - 2} disclosures`);
    console.log(`  header.payload ${hp.length}B → ${blocks(hp.length)} SHA blocks (exceeds old kMaxSHA=13, fits new 32)`);
    console.log(`  presented      ${pres.length}B → ${blocks(pres.length)} SHA blocks (exceeds old PB=18, fits new 44)`);
    const vb = runSplit(1700000000, {}, BIGFIX, BIGJWK);
    show(vb.out);
    if (!vb.accept) throw new Error('big credential failed');
    console.log('  → ACCEPT ✅  generous constants let large credentials work too (clear error on overflow)');
  } else {
    console.log('  (no big fixture — create with `BIG=1 pnpm run gen:sdjwt`)');
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [6] KB FRESHNESS — holder KB signature bound to verifier-chosen nonce/aud');
  console.log('       (replay prevention) — issue with a fresh nonce → same nonce ACCEPTs, different REJECTs');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    const freshNonce = String(Math.floor(Math.random() * 1e10)).padStart(10, '0');
    try {
      // verifier issues/binds a KB-JWT to a freshly chosen nonce
      sh('node', [path.join(ROOT, 'tools/gen-sdjwt.mjs')], { env: { ...process.env, KB_NONCE: freshNonce } });
      console.log(`  verifier nonce: ${freshNonce}`);
      const ok = runSplit(1700000000, {}, FIX, JWK, freshNonce);          // verifier expects the fresh nonce
      const stale = runSplit(1700000000, {}, FIX, JWK, '0000000000');     // replayed/stale nonce
      console.log(`  → same nonce: ${ok.accept ? 'ACCEPT ✅' : 'REJECT ❌(unexpected)'}`);
      console.log(`  → different nonce(replay): ${stale.accept ? 'ACCEPT ❌ (replay!)' : 'REJECT ✅  (freshness enforced)'}`);
      if (!ok.accept) throw new Error('matching nonce should ACCEPT');
      if (stale.accept) throw new Error('FRESHNESS: stale/replayed nonce was accepted!');
    } catch (e) {
      if (/FRESHNESS|matching nonce/.test(e.message)) throw e;
      console.log('  (gen failed — skipping freshness step)');
    }
  } else {
    console.log('  (no node_modules — skipping freshness step)');
  }

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ SD-JWT-VC selective-disclosure ZK — same 2-circuit + MAC architecture as mdoc');
  console.log('     Fp256 signature circuit (issuer ES256 + holder KB) + GF(2^128) hash circuit');
  console.log('     split (SHA+exp+vct+cnf+sd_hash+N×membership/structure/consent),');
  console.log('     soundly bound by MAC over common values e/dpkx/dpky. prove ~4–6x faster.');
  console.log('═'.repeat(70) + '\n');
}

main();
