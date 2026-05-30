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
    if (!body) return { ok: false, reason: 'request signature not verified by a trusted EA key → reject (no proof generated)' };
    const res = zkAssert(body.require, body.nullifier_context, body.nonce, body.kb_aud);
    return { ok: true, body, ...res };
  }

  // ASSERT verifier: the policy is IN the proof, so the EC only needs ACCEPT/REJECT
  // + nullifier dedup. No disclosed value is read (none is revealed).
  const seen = new Set();
  function ecCountVote(res, who) {
    if (!res.ok) return `❌ ${res.reason} — ${who}`;
    if (!res.accept) return `❌ requirements unmet (one of eligibility/residence/KB/nullifier) — actual values not disclosed — ${who}`;
    if (seen.has(res.nullifier)) return `❌ nullifier already voted → re-vote rejected — ${who}`;
    seen.add(res.nullifier);
    return `✅ vote counted (required values asserted, actual values not disclosed, nullifier registered) — ${who}`;
  }

  const signReq = (key, iss, kid, require) => new SignJWT({
    purpose: '2026 local election polling-station identity check (assert style)',
    require, nullifier_context: ELECTION, nonce: EC_NONCE, kb_aud: EC_AUD,
  }).setProtectedHeader({ alg: 'ES256', kid }).setIssuer(iss).setAudience('wallet')
    .setExpirationTime('5m').sign(key);

  console.log('\n'); line('═');
  console.log('  anonymous one-person-one-vote (SD-JWT-VC, ASSERT style) — prove without disclosing values');
  line('═');

  line();
  console.log('  [1] issue — SD-JWT-VC (adult, Seoul residence, commitment C); KB bound to EA nonce/aud');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN], { KB_NONCE: EC_NONCE, KB_AUD: EC_AUD }); console.log('  issued (issuer does not know the secret)'); }
    catch (e) { console.log('  (gen failed; existing fixture)', e.message); }
  } else console.log('  using existing fixture');

  line();
  console.log('  [2] EA signs a request carrying the "required values" (age_over_18==true, resident_city=="Seoul")');
  line();
  const ecRequest = await signReq(ec.privateKey, 'seoul-election-commission', ecPubJwk.kid, REQUIRE_SEOUL);
  console.log(`  EC request signed (required values asserted — holder does not disclose the values)`);

  line();
  console.log('  [3] first vote — wallet asserts via ZK that it "matches the required values" (values not disclosed)');
  line();
  const v1 = await walletHandleRequest(ecRequest);
  console.log(`  request check: ${v1.ok ? 'OK (trusted EA)' : 'rejected'}`);
  console.log(`  asserted: ${v1.asserted.join(', ')}  ← enforced by the circuit (actual values hidden in the witness)`);
  console.log(`  ZK proof : ${v1.accept ? 'ACCEPT (all required values satisfied)' : 'REJECT'}`);
  console.log(`  nullifier: ${v1.nullifier}`);
  console.log('  EA:', ecCountVote(v1, 'voter (first visit)'));
  if (!v1.accept || !seen.has(v1.nullifier)) throw new Error('first vote should be counted');

  line();
  console.log('  [4] re-vote attempt — same person (same secret → same nullifier)');
  line();
  const v2 = await walletHandleRequest(ecRequest);
  console.log(`  nullifier: ${v2.nullifier}  ${v2.nullifier === v1.nullifier ? '(same as first vote)' : '(different?!)'}`);
  console.log('  EA:', ecCountVote(v2, 'voter (return visit)'));
  if (v2.nullifier !== v1.nullifier) throw new Error('same voter must yield same nullifier');

  line();
  console.log('  [5] wrong-district vote — Busan EA requires resident_city=="Busan"');
  line();
  const busanReq = await signReq(ec.privateKey, 'seoul-election-commission', ecPubJwk.kid, REQUIRE_BUSAN);
  const v5 = await walletHandleRequest(busanReq);
  console.log(`  assert attempt: resident_city=="Busan" → ZK ${v5.accept ? 'ACCEPT ❌' : 'REJECT ✅'}`);
  console.log('  Busan EA:', ecCountVote(v5, 'voter'));
  console.log('  → ★ difference from the DISCLOSE variant: on a mismatch the EA learns "nothing at all" about the real city (Seoul).');
  if (v5.accept) throw new Error('SOUNDNESS: wrong-district assert accepted!');

  line();
  console.log('  [6] third party (data broker) request — signs with own key');
  line();
  const brokerReq = await signReq(broker.privateKey, 'totally-not-the-ec', 'data-broker', REQUIRE_SEOUL);
  const harvest = await walletHandleRequest(brokerReq);
  console.log(`  wallet: ${harvest.ok ? 'OK ❌' : harvest.reason}`);
  if (harvest.ok) throw new Error('PRIVACY: wallet answered an untrusted requester!');

  console.log('\n'); line('═');
  console.log('  result: eligibility asserted "without disclosing values" — anonymity, one-person-one-vote, request authorization, KB binding satisfied');
  console.log(`   • first vote ACCEPT, re-vote REJECT (nullifier ${v1.nullifier.slice(0, 16)}…)`);
  console.log('   • required values are enforced in the proof (no verifier policy code needed) — no circuit change (same cache)');
  console.log('   • ★ on a mismatch the actual value is not disclosed (the disclose variant reveals it) — assert-style privacy advantage');
  line('═'); console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
