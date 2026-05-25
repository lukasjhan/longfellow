// SCENARIO: anonymous, double-vote-resistant voting with a BLIND nullifier.
//
// A voter holds a real mdoc (issued blind: the issuer committed C=SHA(secret‖blind)
// and never learned the secret). At a polling station the voter proves, in ONE
// zero-knowledge proof:
//   * age_over_18 == true            (eligible: adult)
//   * resident_city == "김포시"       (eligible: lives in this district)
//   * a DI nullifier scoped to THIS election = SHA(secret ‖ SHA(election_id))
// revealing nothing else (name, DOB, signature, the secret all stay hidden).
//
// The election commission (EC) keeps a set of seen nullifiers:
//   * first vote  → nullifier is new  → ACCEPT, register it, vote counted
//   * second vote → same nullifier    → REJECT (one person, one vote)
// Different elections use a different scope, so the voter is unlinkable across
// them; and because issuance was blind, not even the EC/issuer can compute the
// voter's nullifier for another scope.
//
// The wallet only answers a presentation request that is SIGNED by a TRUSTED
// requester (the EC). A third party trying to harvest the nullifier is rejected
// by the wallet before any proof is produced.
//
// Run:  node src/scenario-voting.js   (after build:native + gen-mdoc-blind)

import { execFileSync } from 'node:child_process';
import { SignJWT, jwtVerify, generateKeyPair, exportJWK, importJWK } from 'jose';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/mdoc_null_blind');
const GEN = path.join(ROOT, 'tools/gen-mdoc-blind.mjs');
const MDOC = path.join(ROOT, 'fixtures/mdoc-blind.bin');
const ISSUER = path.join(ROOT, 'fixtures/mdoc-blind-issuer.json');
const TR = path.join(ROOT, 'fixtures/mdoc-blind-transcript.bin');
const SECRET = path.join(ROOT, 'fixtures/mdoc-holder-secret.txt');
const NOW = '2026-06-01T00:00:00Z';

const line = (c = '─') => console.log(c.repeat(72));
const cborText = (s) => {                         // CBOR tstr for short strings
  const b = Buffer.from(s, 'utf8');
  if (b.length >= 24) throw new Error('cborText: only short strings here');
  return (0x60 + b.length).toString(16).padStart(2, '0') + b.toString('hex');
};
const CBOR_TRUE = 'f5';

function sh(cmd, args, env = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', process.env.DEBUG === '1' ? 'inherit' : 'pipe'],
    env: { ...process.env, ...env },
  });
}

// The wallet's ZK presentation: prove the requested attrs + the scoped nullifier.
// Returns { accept, nullifier }. (The binary does present AND verify internally.)
function zkPresent(attrs, electionId) {
  const ids = attrs.map((a) => a.id).join(',');
  const hexes = attrs.map((a) => a.hex).join(',');
  try {
    const out = sh(BIN, [MDOC, ISSUER, TR, NOW, ids, hexes, electionId],
                   { HOLDER_SECRET: SECRET });
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { accept: /ACCEPT \(real mdoc/.test(out), nullifier: m && m[1] };
  } catch (e) {
    const out = (e.stdout || '').toString();
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { accept: false, nullifier: m && m[1] };
  }
}

async function main() {
  if (!fs.existsSync(BIN)) { console.error('build first: pnpm run build:native'); process.exit(1); }

  // ===== keys =====
  // Election commission (the only requester the wallet trusts) and an unrelated
  // third party (a data broker) that will try to harvest the nullifier.
  const ec = await generateKeyPair('ES256', { extractable: true });
  const broker = await generateKeyPair('ES256', { extractable: true });
  const ecPubJwk = await exportJWK(ec.publicKey);
  ecPubJwk.kid = 'gimpo-ec-2026';
  // The wallet's trust list of authorized requesters (issuer -> public key).
  const TRUST = { 'gimpo-election-commission': ecPubJwk };

  // ===== the wallet: answer ONLY signed, authorized presentation requests =====
  async function walletHandleRequest(requestJwt) {
    // 1) the request must be signed by a trusted requester (RP authentication)
    let body;
    for (const [iss, jwk] of Object.entries(TRUST)) {
      try {
        const key = await importJWK(jwk, 'ES256');
        const { payload } = await jwtVerify(requestJwt, key, { issuer: iss });
        body = payload; break;
      } catch { /* try next trusted key */ }
    }
    if (!body) {
      return { ok: false, reason: '요청 서명이 신뢰된 선관위 키로 검증되지 않음 → 거부 (proof 미생성)' };
    }
    // 2) map the request to the attributes + nullifier scope, then ZK present
    const attrs = body.require.map((r) =>
      r.claim === 'age_over_18' ? { id: 'age_over_18', hex: CBOR_TRUE }
                                : { id: r.claim, hex: cborText(r.equals) });
    const res = zkPresent(attrs, body.nullifier_context);
    return { ok: true, body, ...res };
  }

  // ===== the election commission verifier state =====
  const seen = new Set();   // nullifiers already used in THIS election
  function ecCountVote(res, who) {
    if (!res.accept) return `❌ 증명 거부 (자격 미달/위조) — ${who}`;
    if (seen.has(res.nullifier)) return `❌ 이미 투표한 nullifier → 재투표 거부 — ${who}`;
    seen.add(res.nullifier);
    return `✅ 투표 완료 (nullifier 등록) — ${who}`;
  }

  const ELECTION = 'kr-2026-local-election:gimpo';   // the DI scope for this poll
  const districtRequire = [
    { claim: 'age_over_18' },                        // must be an adult
    { claim: 'resident_city', equals: '김포시' },     // must live in 김포시
  ];

  console.log('\n');
  line('═');
  console.log('  익명·1인1표 투표 시나리오 — BLIND nullifier on a real mdoc');
  line('═');

  // [1] ISSUE
  line();
  console.log('  [1] 발급 — 월렛에 mdoc 저장 (성인, 김포시 거주, 가명 커밋먼트 C)');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN]); console.log('  발급 완료 → fixtures/mdoc-blind.bin (발급자는 secret을 모름)'); }
    catch { console.log('  (gen 실패; 기존 fixture 사용)'); }
  } else console.log('  기존 fixture 사용');

  // [2] EC signs a presentation request; the wallet verifies it
  line();
  console.log('  [2] 선관위(EC)가 서명한 제시요청 → 월렛이 서명·권한 검증');
  line();
  const ecRequest = await new SignJWT({
    purpose: '2026 지방선거 투표소 본인확인',
    district: '김포시',
    require: districtRequire,
    nullifier_context: ELECTION,           // the DI scope = this election
    nonce: 'poll-nonce-' + Date.now(),
  }).setProtectedHeader({ alg: 'ES256', kid: ecPubJwk.kid })
    .setIssuer('gimpo-election-commission')
    .setAudience('wallet')
    .setExpirationTime('5m')
    .sign(ec.privateKey);
  console.log('  EC request JWT 서명됨 (iss=gimpo-election-commission)');

  // [3] FIRST VOTE
  line();
  console.log('  [3] 첫 투표 — 월렛이 ZK 제출 (성인 + 김포 거주 + 선거 scope nullifier)');
  line();
  const v1 = await walletHandleRequest(ecRequest);
  console.log(`  요청검증: ${v1.ok ? 'OK (신뢰된 선관위)' : '거부'}`);
  console.log(`  ZK 증명 : ${v1.accept ? 'ACCEPT (성인✅ 김포거주✅)' : 'REJECT'}`);
  console.log(`  nullifier: ${v1.nullifier}`);
  console.log('  선관위:', ecCountVote(v1, '유권자(첫 방문)'));
  if (!v1.accept || !seen.has(v1.nullifier)) throw new Error('first vote should be counted');

  // [4] DOUBLE VOTE — same person comes back
  line();
  console.log('  [4] 재투표 시도 — 같은 사람이 다시 옴 (같은 secret → 같은 nullifier)');
  line();
  const v2 = await walletHandleRequest(ecRequest);
  console.log(`  nullifier: ${v2.nullifier}  ${v2.nullifier === v1.nullifier ? '(첫 투표와 동일)' : '(다름?!)'}`);
  console.log('  선관위:', ecCountVote(v2, '유권자(재방문)'));
  if (v2.nullifier !== v1.nullifier) throw new Error('same voter must yield same nullifier');

  // [5] ADDRESS FORGERY — same voter tries to vote as a Seoul resident
  line();
  console.log('  [5] 주소 위조 시도 — 김포 자격증명으로 "서울시" 거주를 주장');
  line();
  const forged = zkPresent(
    [{ id: 'age_over_18', hex: CBOR_TRUE }, { id: 'resident_city', hex: cborText('서울시') }],
    'kr-2026-local-election:seoul');
  console.log(`  ZK 증명 : ${forged.accept ? 'ACCEPT ❌ (주소 위조 성공?!)' : 'REJECT ✅ (자격증명은 김포시 — 값 불일치)'}`);
  if (forged.accept) throw new Error('SOUNDNESS: forged address accepted!');

  // [6] THIRD-PARTY HARVEST — a data broker tries to learn the nullifier
  line();
  console.log('  [6] 제3자(데이터브로커)가 nullifier를 캐내려 요청 — 자기 키로 서명');
  line();
  const brokerRequest = await new SignJWT({
    purpose: '경품 이벤트 본인확인(사칭)',
    require: districtRequire,
    nullifier_context: ELECTION,            // tries to reuse the election scope
    nonce: 'evil',
  }).setProtectedHeader({ alg: 'ES256', kid: 'data-broker' })
    .setIssuer('totally-not-the-ec')
    .setAudience('wallet')
    .setExpirationTime('5m')
    .sign(broker.privateKey);
  const harvest = await walletHandleRequest(brokerRequest);
  console.log(`  월렛: ${harvest.ok ? 'OK ❌' : harvest.reason}`);
  if (harvest.ok) throw new Error('PRIVACY: wallet answered an untrusted requester!');
  console.log('  → 월렛이 요청 서명을 선관위 키로 검증 실패 → proof 자체를 만들지 않음.');
  console.log('     (설령 만들었어도 선거 scope nullifier는 blind라 발급자/제3자가 계산 불가)');

  // summary
  console.log('\n');
  line('═');
  console.log('  결과: 익명성·1인1표·자격(성인/거주지)·요청권한 모두 충족');
  console.log(`   • 첫 투표 ACCEPT, 재투표 REJECT (nullifier ${v1.nullifier.slice(0, 16)}…)`);
  console.log('   • 주소 위조 REJECT (자격증명 값에 결속)');
  console.log('   • 제3자 요청 REJECT (월렛이 선관위 서명만 응답)');
  console.log('   • 발급자도 secret 모름 → 다른 scope로도 역추적 불가 (blind issuance)');
  line('═');
  console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
