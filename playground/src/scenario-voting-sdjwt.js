// SCENARIO (SD-JWT-VC): anonymous, double-vote-resistant voting with a BLIND
// nullifier — the SD-JWT-VC counterpart of scenario-voting.js (which uses mdoc).
//
// A voter holds a real SD-JWT-VC issued BLIND (the issuer committed
// C=SHA(secret‖blind) and never learned the secret). At the poll the wallet
// presents ONE ZK proof that:
//   * age_over_18 == true            (eligible: adult)           — disclosed, authentic
//   * resident_city == "Seoul"       (eligible: lives here)       — disclosed, authentic
//   * a DI nullifier scoped to THIS election = SHA(secret ‖ SHA(election_id))
//   * the holder Key Binding is bound to the EC's nonce + aud     (in-circuit)
// while the signature, salt, secret, and other claims stay hidden.
//
// SD-JWT vs mdoc differences highlighted here:
//   * selective disclosure REVEALS the claim values (the verifier reads "Seoul"
//     and applies policy); the ZK only guarantees they are issuer-authentic
//     (∈ _sd). So a wrong district is rejected by the verifier's POLICY on an
//     authentic value (the holder cannot disclose a city it was not issued).
//   * Key Binding nonce/aud are checked IN-CIRCUIT, so the proof is bound to the
//     EC's challenge (mdoc binds via the session transcript instead).
//
// The wallet only answers a presentation request SIGNED by a TRUSTED requester
// (the EC); a third party is rejected before any proof is produced.
//
// Run:  node src/scenario-voting-sdjwt.js   (after build:native)

import { execFileSync } from 'node:child_process';
import { SignJWT, jwtVerify, generateKeyPair, exportJWK, importJWK } from 'jose';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/sdjwt_null_blind');
const GEN = path.join(ROOT, 'tools/gen-sdjwt-blind.mjs');
const FIX = path.join(ROOT, 'fixtures/sdjwt-blind.txt');
const JWK = path.join(ROOT, 'fixtures/issuer-jwk-blind.json');
const SECRET = path.join(ROOT, 'fixtures/holder-secret.txt');
const NOW = '1700000000';
const VCT = 'https://credentials.example/pid';

const line = (c = '─') => console.log(c.repeat(72));

function sh(cmd, args, env = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', process.env.DEBUG === '1' ? 'inherit' : 'pipe'],
    env: { ...process.env, ...env },
  });
}

// The wallet's ZK presentation. Returns { accept, nullifier, disclosed:{name:value} }.
function zkPresent(claims, electionId, nonce, aud) {
  const parse = (out) => {
    const disclosed = {};
    for (const m of out.matchAll(/disclosed: (\S+) = (.+)/g))
      disclosed[m[1]] = m[2].trim().replace(/^"|"$/g, '');     // strip JSON quotes
    const nm = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { accept: /soundly linked/.test(out), nullifier: nm && nm[1], disclosed };
  };
  try {
    return parse(sh(BIN, [FIX, JWK, NOW, claims.join(','), VCT, nonce, aud, electionId],
                    { HOLDER_SECRET: SECRET }));
  } catch (e) { return parse((e.stdout || '').toString()); }
}

async function main() {
  if (!fs.existsSync(BIN)) { console.error('build first: pnpm run build:native'); process.exit(1); }

  // ===== keys: election commission (trusted) + a data broker (untrusted) =====
  const ec = await generateKeyPair('ES256', { extractable: true });
  const broker = await generateKeyPair('ES256', { extractable: true });
  const ecPubJwk = await exportJWK(ec.publicKey); ecPubJwk.kid = 'seoul-ec-2026';
  const TRUST = { 'seoul-election-commission': ecPubJwk };   // wallet's trusted requesters

  // EC challenge: the KB-JWT is bound to THIS nonce+aud (verified in-circuit).
  const EC_NONCE = 'poll-' + Math.random().toString(36).slice(2, 10);
  const EC_AUD = 'https://ec.seoul.go.kr/poll-2026';
  const ELECTION = 'kr-2026-local-election:seoul';           // the DI nullifier scope
  const CLAIMS = ['age_over_18', 'resident_city'];

  // ===== wallet: answer ONLY signed, authorized requests =====
  async function walletHandleRequest(requestJwt) {
    let body;
    for (const [iss, jwk] of Object.entries(TRUST)) {
      try {
        const { payload } = await jwtVerify(requestJwt, await importJWK(jwk, 'ES256'), { issuer: iss });
        body = payload; break;
      } catch { /* not this trusted key */ }
    }
    if (!body) return { ok: false, reason: '요청 서명이 신뢰된 선관위 키로 검증 안 됨 → 거부 (proof 미생성)' };
    const claims = body.require.map((r) => r.claim);
    const res = zkPresent(claims, body.nullifier_context, body.nonce, body.kb_aud);
    return { ok: true, body, ...res };
  }

  // ===== EC verifier: ZK valid + authentic-value policy + nullifier dedup =====
  const seen = new Set();
  function ecCountVote(res, requiredCity, who) {
    if (!res.ok) return `❌ ${res.reason} — ${who}`;
    if (!res.accept) return `❌ ZK 증명 거부 (서명/KB/nullifier 불만족) — ${who}`;
    if (res.disclosed.age_over_18 !== 'true') return `❌ 성인 아님 → 거부 — ${who}`;
    if (res.disclosed.resident_city !== requiredCity)
      return `❌ 거주지 불일치 (공개값 ${res.disclosed.resident_city} ≠ 요구 ${requiredCity}) → 거부 — ${who}`;
    if (seen.has(res.nullifier)) return `❌ 이미 투표한 nullifier → 재투표 거부 — ${who}`;
    seen.add(res.nullifier);
    return `✅ 투표 완료 (성인✅ ${requiredCity}거주✅ nullifier 등록) — ${who}`;
  }

  // `kb_aud` is the audience the KB-JWT must bind to (verified in-circuit); it is a
  // CUSTOM field, distinct from the request JWT's own standard `aud` ('wallet').
  const signReq = (key, iss, kid, extra) => new SignJWT({
    purpose: '2026 지방선거 투표소 본인확인',
    require: CLAIMS.map((c) => ({ claim: c })),
    nullifier_context: ELECTION, nonce: EC_NONCE, kb_aud: EC_AUD, ...extra,
  }).setProtectedHeader({ alg: 'ES256', kid }).setIssuer(iss).setAudience('wallet')
    .setExpirationTime('5m').sign(key);

  console.log('\n'); line('═');
  console.log('  익명·1인1표 투표 시나리오 (SD-JWT-VC) — BLIND nullifier');
  line('═');

  // [1] ISSUE — KB bound to the EC nonce/aud; resident_city=Seoul; blind commitment
  line();
  console.log('  [1] 발급 — SD-JWT-VC (성인, Seoul 거주, 가명 커밋먼트 C); KB는 선관위 nonce/aud에 결속');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN], { KB_NONCE: EC_NONCE, KB_AUD: EC_AUD }); console.log('  발급 완료 → fixtures/sdjwt-blind.txt (발급자는 secret 모름)'); }
    catch (e) { console.log('  (gen 실패; 기존 fixture)', e.message); }
  } else console.log('  기존 fixture 사용');

  // [2] EC signs a request → wallet verifies
  line();
  console.log('  [2] 선관위(EC)가 서명한 제시요청 → 월렛이 서명·권한 검증');
  line();
  const ecRequest = await signReq(ec.privateKey, 'seoul-election-commission', ecPubJwk.kid);
  console.log(`  EC request 서명됨 (iss=seoul-election-commission, nonce=${EC_NONCE})`);

  // [3] FIRST VOTE
  line();
  console.log('  [3] 첫 투표 — 월렛 ZK 제출 (성인 + Seoul 거주 + 선거 scope nullifier + KB nonce/aud)');
  line();
  const v1 = await walletHandleRequest(ecRequest);
  console.log(`  요청검증: ${v1.ok ? 'OK (신뢰된 선관위)' : '거부'}`);
  console.log(`  공개값  : age_over_18=${v1.disclosed.age_over_18}, resident_city=${v1.disclosed.resident_city} (둘 다 _sd 멤버십으로 진본)`);
  console.log(`  ZK 증명 : ${v1.accept ? 'ACCEPT (KB가 EC nonce/aud에 결속)' : 'REJECT'}`);
  console.log(`  nullifier: ${v1.nullifier}`);
  console.log('  선관위:', ecCountVote(v1, 'Seoul', '유권자(첫 방문)'));
  if (!v1.accept || !seen.has(v1.nullifier)) throw new Error('first vote should be counted');

  // [4] DOUBLE VOTE
  line();
  console.log('  [4] 재투표 시도 — 같은 사람 (같은 secret → 같은 nullifier)');
  line();
  const v2 = await walletHandleRequest(ecRequest);
  console.log(`  nullifier: ${v2.nullifier}  ${v2.nullifier === v1.nullifier ? '(첫 투표와 동일)' : '(다름?!)'}`);
  console.log('  선관위:', ecCountVote(v2, 'Seoul', '유권자(재방문)'));
  if (v2.nullifier !== v1.nullifier) throw new Error('same voter must yield same nullifier');

  // [5] WRONG DISTRICT — a Busan poll requires Busan; the holder can only prove Seoul
  line();
  console.log('  [5] 타 지역 투표 시도 — Busan 선관위가 Busan 거주를 요구');
  line();
  const v5 = await walletHandleRequest(ecRequest);   // holder still discloses authentic Seoul
  console.log(`  공개값  : resident_city=${v5.disclosed.resident_city} (진본, 위조 불가)`);
  console.log('  Busan 선관위:', ecCountVote({ ...v5 }, 'Busan', '유권자'));
  console.log('  → 자격증명에 없는 도시는 공개조차 불가 → 거주지 위조 불가');

  // [6] THIRD-PARTY HARVEST
  line();
  console.log('  [6] 제3자(데이터브로커)가 nullifier를 캐내려 요청 — 자기 키로 서명');
  line();
  const brokerReq = await signReq(broker.privateKey, 'totally-not-the-ec', 'data-broker');
  const harvest = await walletHandleRequest(brokerReq);
  console.log(`  월렛: ${harvest.ok ? 'OK ❌' : harvest.reason}`);
  if (harvest.ok) throw new Error('PRIVACY: wallet answered an untrusted requester!');
  console.log('  → 월렛이 요청 서명을 선관위 키로 검증 실패 → proof 미생성.');
  console.log('     (KB도 EC nonce/aud에 결속되어, 다른 nonce면 회로가 REJECT — 이중 방어)');

  console.log('\n'); line('═');
  console.log('  결과: 익명성·1인1표·자격(성인/거주지)·요청권한·KB결속 모두 충족');
  console.log(`   • 첫 투표 ACCEPT, 재투표 REJECT (nullifier ${v1.nullifier.slice(0, 16)}…)`);
  console.log('   • 거주지는 _sd 멤버십으로 진본 → 타 지역 위조 불가 (정책 거부)');
  console.log('   • 제3자 요청 REJECT (월렛 RP 인증) + KB nonce/aud 회로 결속');
  console.log('   • 발급자도 secret 모름 → 다른 scope로도 역추적 불가 (blind issuance)');
  line('═'); console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
