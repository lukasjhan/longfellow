// SCENARIO (SD-JWT-VC, ASSERT style): anonymous one-person-one-vote, but the
// eligibility VALUES are NOT disclosed — they are ASSERTED.
//
// Difference from scenario-voting-sdjwt.js (which DISCLOSES the values): here the
// election commission states the REQUIRED values in its request
//   require: [{age_over_18 == true}, {resident_city == "Seoul"}]
// and the wallet proves the holder's credential matches them WITHOUT revealing
// the actual values. The SD-JWT circuit already asserts "holder disclosure suffix
// == public pattern"; feeding the pattern from the verifier's required value (the
// `name=value` claim syntax of sdjwt_null_blind) turns disclose into assert — NO
// circuit change (same compiled circuit/cache).
//
// Key property (vs disclose): on a MISMATCH the proof is unsatisfiable, so the
// verifier learns nothing about the holder's actual value — e.g. a Seoul resident
// at a Busan poll is rejected WITHOUT the EC ever learning the real city.
//
// Run:  node src/scenario-voting-sdjwt-assert.js   (after build:native)

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

// ASSERT present: each requirement {claim, equals} → `claim=<json(equals)>`.
// Returns { accept, nullifier, asserted:[...] }; the actual values are NEVER returned.
function zkAssert(requirements, electionId, nonce, aud) {
  const claims = requirements.map((r) => `${r.claim}=${JSON.stringify(r.equals)}`).join(',');
  const parse = (out) => {
    const nm = out.match(/nullifier\s*: ([0-9a-f]+)/);
    const asserted = [...out.matchAll(/asserted: (\S+) == (.+)/g)].map((m) => `${m[1]}==${m[2].trim()}`);
    return { accept: /soundly linked/.test(out), nullifier: nm && nm[1], asserted };
  };
  try {
    return parse(sh(BIN, [FIX, JWK, NOW, claims, VCT, nonce, aud, electionId], { HOLDER_SECRET: SECRET }));
  } catch (e) { return parse((e.stdout || '').toString()); }
}

async function main() {
  if (!fs.existsSync(BIN)) { console.error('build first: pnpm run build:native'); process.exit(1); }

  const ec = await generateKeyPair('ES256', { extractable: true });
  const broker = await generateKeyPair('ES256', { extractable: true });
  const ecPubJwk = await exportJWK(ec.publicKey); ecPubJwk.kid = 'seoul-ec-2026';
  const TRUST = { 'seoul-election-commission': ecPubJwk };

  const EC_NONCE = 'poll-' + Math.random().toString(36).slice(2, 10);
  const EC_AUD = 'https://ec.seoul.go.kr/poll-2026';
  const ELECTION = 'kr-2026-local-election:seoul';
  // The EC's REQUIRED values (asserted, not disclosed).
  const REQUIRE_SEOUL = [{ claim: 'age_over_18', equals: true }, { claim: 'resident_city', equals: 'Seoul' }];
  const REQUIRE_BUSAN = [{ claim: 'age_over_18', equals: true }, { claim: 'resident_city', equals: 'Busan' }];

  async function walletHandleRequest(requestJwt) {
    let body;
    for (const [iss, jwk] of Object.entries(TRUST)) {
      try { const { payload } = await jwtVerify(requestJwt, await importJWK(jwk, 'ES256'), { issuer: iss }); body = payload; break; }
      catch { /* not this key */ }
    }
    if (!body) return { ok: false, reason: '요청 서명이 신뢰된 선관위 키로 검증 안 됨 → 거부 (proof 미생성)' };
    const res = zkAssert(body.require, body.nullifier_context, body.nonce, body.kb_aud);
    return { ok: true, body, ...res };
  }

  // ASSERT verifier: the policy is IN the proof, so the EC only needs ACCEPT/REJECT
  // + nullifier dedup. No disclosed value is read (none is revealed).
  const seen = new Set();
  function ecCountVote(res, who) {
    if (!res.ok) return `❌ ${res.reason} — ${who}`;
    if (!res.accept) return `❌ 요구조건 불충족 (자격/거주지/KB/nullifier 중 하나) — 실제값은 비공개 — ${who}`;
    if (seen.has(res.nullifier)) return `❌ 이미 투표한 nullifier → 재투표 거부 — ${who}`;
    seen.add(res.nullifier);
    return `✅ 투표 완료 (요구값 단언 성공, 실제값 비공개, nullifier 등록) — ${who}`;
  }

  const signReq = (key, iss, kid, require) => new SignJWT({
    purpose: '2026 지방선거 투표소 본인확인(단언식)',
    require, nullifier_context: ELECTION, nonce: EC_NONCE, kb_aud: EC_AUD,
  }).setProtectedHeader({ alg: 'ES256', kid }).setIssuer(iss).setAudience('wallet')
    .setExpirationTime('5m').sign(key);

  console.log('\n'); line('═');
  console.log('  익명·1인1표 투표 (SD-JWT-VC, ASSERT 단언식) — 값을 공개하지 않고 증명');
  line('═');

  line();
  console.log('  [1] 발급 — SD-JWT-VC (성인, Seoul 거주, 커밋먼트 C); KB는 선관위 nonce/aud 결속');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN], { KB_NONCE: EC_NONCE, KB_AUD: EC_AUD }); console.log('  발급 완료 (발급자는 secret 모름)'); }
    catch (e) { console.log('  (gen 실패; 기존 fixture)', e.message); }
  } else console.log('  기존 fixture 사용');

  line();
  console.log('  [2] 선관위가 "요구값"을 담아 서명 요청 (age_over_18==true, resident_city=="Seoul")');
  line();
  const ecRequest = await signReq(ec.privateKey, 'seoul-election-commission', ecPubJwk.kid, REQUIRE_SEOUL);
  console.log(`  EC request 서명됨 (요구값을 단언 — 홀더는 값을 공개하지 않음)`);

  line();
  console.log('  [3] 첫 투표 — 월렛이 "요구값에 부합함"을 ZK로 단언 (값 비공개)');
  line();
  const v1 = await walletHandleRequest(ecRequest);
  console.log(`  요청검증: ${v1.ok ? 'OK (신뢰된 선관위)' : '거부'}`);
  console.log(`  단언내용: ${v1.asserted.join(', ')}  ← 회로가 강제 (실제값은 witness에 숨김)`);
  console.log(`  ZK 증명 : ${v1.accept ? 'ACCEPT (요구값 모두 충족)' : 'REJECT'}`);
  console.log(`  nullifier: ${v1.nullifier}`);
  console.log('  선관위:', ecCountVote(v1, '유권자(첫 방문)'));
  if (!v1.accept || !seen.has(v1.nullifier)) throw new Error('first vote should be counted');

  line();
  console.log('  [4] 재투표 시도 — 같은 사람 (같은 secret → 같은 nullifier)');
  line();
  const v2 = await walletHandleRequest(ecRequest);
  console.log(`  nullifier: ${v2.nullifier}  ${v2.nullifier === v1.nullifier ? '(첫 투표와 동일)' : '(다름?!)'}`);
  console.log('  선관위:', ecCountVote(v2, '유권자(재방문)'));
  if (v2.nullifier !== v1.nullifier) throw new Error('same voter must yield same nullifier');

  line();
  console.log('  [5] 타 지역 투표 — Busan 선관위가 resident_city=="Busan"을 요구');
  line();
  const busanReq = await signReq(ec.privateKey, 'seoul-election-commission', ecPubJwk.kid, REQUIRE_BUSAN);
  const v5 = await walletHandleRequest(busanReq);
  console.log(`  단언시도: resident_city=="Busan" → ZK ${v5.accept ? 'ACCEPT ❌' : 'REJECT ✅'}`);
  console.log('  Busan 선관위:', ecCountVote(v5, '유권자'));
  console.log('  → ★ DISCLOSE판과의 차이: 불일치 시 선관위는 실제 도시(Seoul)를 "전혀 알 수 없음".');
  if (v5.accept) throw new Error('SOUNDNESS: wrong-district assert accepted!');

  line();
  console.log('  [6] 제3자(데이터브로커) 요청 — 자기 키로 서명');
  line();
  const brokerReq = await signReq(broker.privateKey, 'totally-not-the-ec', 'data-broker', REQUIRE_SEOUL);
  const harvest = await walletHandleRequest(brokerReq);
  console.log(`  월렛: ${harvest.ok ? 'OK ❌' : harvest.reason}`);
  if (harvest.ok) throw new Error('PRIVACY: wallet answered an untrusted requester!');

  console.log('\n'); line('═');
  console.log('  결과: 자격을 "값 공개 없이" 단언 — 익명성·1인1표·요청권한·KB결속 충족');
  console.log(`   • 첫 투표 ACCEPT, 재투표 REJECT (nullifier ${v1.nullifier.slice(0, 16)}…)`);
  console.log('   • 요구값은 proof에 강제(검증자 정책 코드 불필요) — 회로 무변경(같은 캐시)');
  console.log('   • ★ 불일치 시 실제값 비공개 (disclose판은 실제값을 드러냄) — 단언식 프라이버시 우위');
  line('═'); console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
