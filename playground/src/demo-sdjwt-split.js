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
function runSplit(now, env = {}, fix = FIX, jwk = JWK) {
  try {
    const out = sh(BIN, [fix, jwk, String(now), CLAIMS, VCT], {
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
  console.log('  → ACCEPT ✅  (sig 회로 + 해시 회로, 공유 MAC로 결속; a_v는 commit 후 트랜스크립트에서 유도)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] EXPIRED — now > exp → 해시 회로 REJECT (soundness)');
  line();
  const v2 = runSplit(9999999999);
  console.log(`  → ${v2.accept ? 'ACCEPT ❌(unexpected)' : 'REJECT ✅'}`);
  if (v2.accept) throw new Error('expired credential was accepted!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3b] ADVERSARIAL — 만료 토큰 + 악성 prover (EVIL_EXP: exp_idx→letters)');
  console.log('       `"exp":` 앵커·자릿수 검증이 없으면 letters(>now)로 만료 우회 (수정 전엔 ACCEPT)');
  line();
  const v2b = runSplit(9999999999, { EVIL_EXP: '1' });
  console.log(`  → ${v2b.accept ? 'ACCEPT ❌ (soundness broken!)' : 'REJECT ✅  (앵커가 우회를 차단)'}`);
  if (v2b.accept) throw new Error('SOUNDNESS: malicious exp_idx bypassed expiry!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [4] TAMPER — 번들의 mac_e 1비트 변조 → 양 회로 모두 REJECT (링크 강제 증명)');
  line();
  const v3 = runSplit(1700000000, { TAMPER: '1' });
  show(v3.out);
  // tamper mode: the binary exits 0 when BOTH correctly rejected (test PASS).
  if (!v3.ok || /FAIL/.test(v3.out)) throw new Error('tamper test did not enforce the link!');
  console.log('  → 변조 시 양 회로 REJECT ✅  (MAC 링크가 실제로 load-bearing)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [5] BIG — 13속성 PID급 크레덴셜 (옛 상수면 초과로 깨졌을 토큰)');
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
    console.log(`  header.payload ${hp.length}B → ${blocks(hp.length)} SHA블록 (옛 kMaxSHA=13 초과, 새 32 OK)`);
    console.log(`  presented      ${pres.length}B → ${blocks(pres.length)} SHA블록 (옛 PB=18 초과, 새 40 OK)`);
    const vb = runSplit(1700000000, {}, BIGFIX, BIGJWK);
    show(vb.out);
    if (!vb.accept) throw new Error('big credential failed');
    console.log('  → ACCEPT ✅  넉넉한 상수 덕에 큰 크레덴셜도 동작 (초과 시엔 명확한 에러)');
  } else {
    console.log('  (big fixture 없음 — `BIG=1 pnpm run gen:sdjwt` 로 생성)');
  }

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ SD-JWT-VC 선택공개 ZK — mdoc과 동일한 2회로 + MAC 아키텍처');
  console.log('     Fp256 서명 회로(발급자 ES256 + 홀더 KB) + GF(2^128) 해시 회로');
  console.log('     (SHA+exp+vct+cnf+sd_hash+N×멤버십/구조/consent)를 분리해');
  console.log('     공통값 e/dpkx/dpky의 MAC로 건전하게 결속. prove ~4–6배 단축.');
  console.log('═'.repeat(70) + '\n');
}

main();
