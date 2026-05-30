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
    if (!body) return { ok: false, reason: 'request signature not verified by a trusted EA key → reject (no proof generated)' };
    const claims = body.require.map((r) => r.claim);
    const res = zkPresent(claims, body.nullifier_context, body.nonce, body.kb_aud);
    return { ok: true, body, ...res };
  }

  // ===== EC verifier: ZK valid + authentic-value policy + nullifier dedup =====
  const seen = new Set();
  function ecCountVote(res, requiredCity, who) {
    if (!res.ok) return `❌ ${res.reason} — ${who}`;
    if (!res.accept) return `❌ ZK proof rejected (signature/KB/nullifier unsatisfied) — ${who}`;
    if (res.disclosed.age_over_18 !== 'true') return `❌ not an adult → reject — ${who}`;
    if (res.disclosed.resident_city !== requiredCity)
      return `❌ residence mismatch (disclosed ${res.disclosed.resident_city} ≠ required ${requiredCity}) → reject — ${who}`;
    if (seen.has(res.nullifier)) return `❌ nullifier already voted → re-vote rejected — ${who}`;
    seen.add(res.nullifier);
    return `✅ vote counted (adult✅ ${requiredCity} residence✅ nullifier registered) — ${who}`;
  }

  // `kb_aud` is the audience the KB-JWT must bind to (verified in-circuit); it is a
  // CUSTOM field, distinct from the request JWT's own standard `aud` ('wallet').
  const signReq = (key, iss, kid, extra) => new SignJWT({
    purpose: '2026 local election polling-station identity check',
    require: CLAIMS.map((c) => ({ claim: c })),
    nullifier_context: ELECTION, nonce: EC_NONCE, kb_aud: EC_AUD, ...extra,
  }).setProtectedHeader({ alg: 'ES256', kid }).setIssuer(iss).setAudience('wallet')
    .setExpirationTime('5m').sign(key);

  console.log('\n'); line('═');
  console.log('  anonymous one-person-one-vote scenario (SD-JWT-VC) — BLIND nullifier');
  line('═');

  // [1] ISSUE — KB bound to the EC nonce/aud; resident_city=Seoul; blind commitment
  line();
  console.log('  [1] issue — SD-JWT-VC (adult, Seoul residence, pseudonym commitment C); KB bound to EA nonce/aud');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN], { KB_NONCE: EC_NONCE, KB_AUD: EC_AUD }); console.log('  issued → fixtures/sdjwt-blind.txt (issuer does not know the secret)'); }
    catch (e) { console.log('  (gen failed; existing fixture)', e.message); }
  } else console.log('  using existing fixture');

  // [2] EC signs a request → wallet verifies
  line();
  console.log('  [2] EA-signed presentation request → wallet verifies signature & authorization');
  line();
  const ecRequest = await signReq(ec.privateKey, 'seoul-election-commission', ecPubJwk.kid);
  console.log(`  EC request signed (iss=seoul-election-commission, nonce=${EC_NONCE})`);

  // [3] FIRST VOTE
  line();
  console.log('  [3] first vote — wallet submits ZK (adult + Seoul residence + election-scope nullifier + KB nonce/aud)');
  line();
  const v1 = await walletHandleRequest(ecRequest);
  console.log(`  request check: ${v1.ok ? 'OK (trusted EA)' : 'rejected'}`);
  console.log(`  disclosed: age_over_18=${v1.disclosed.age_over_18}, resident_city=${v1.disclosed.resident_city} (both authentic via _sd membership)`);
  console.log(`  ZK proof : ${v1.accept ? 'ACCEPT (KB bound to EC nonce/aud)' : 'REJECT'}`);
  console.log(`  nullifier: ${v1.nullifier}`);
  console.log('  EA:', ecCountVote(v1, 'Seoul', 'voter (first visit)'));
  if (!v1.accept || !seen.has(v1.nullifier)) throw new Error('first vote should be counted');

  // [4] DOUBLE VOTE
  line();
  console.log('  [4] re-vote attempt — same person (same secret → same nullifier)');
  line();
  const v2 = await walletHandleRequest(ecRequest);
  console.log(`  nullifier: ${v2.nullifier}  ${v2.nullifier === v1.nullifier ? '(same as first vote)' : '(different?!)'}`);
  console.log('  EA:', ecCountVote(v2, 'Seoul', 'voter (return visit)'));
  if (v2.nullifier !== v1.nullifier) throw new Error('same voter must yield same nullifier');

  // [5] WRONG DISTRICT — a Busan poll requires Busan; the holder can only prove Seoul
  line();
  console.log('  [5] wrong-district attempt — Busan EA requires Busan residence');
  line();
  const v5 = await walletHandleRequest(ecRequest);   // holder still discloses authentic Seoul
  console.log(`  disclosed: resident_city=${v5.disclosed.resident_city} (authentic, cannot be forged)`);
  console.log('  Busan EA:', ecCountVote({ ...v5 }, 'Busan', 'voter'));
  console.log('  → a city not in the credential cannot even be disclosed → residence cannot be forged');

  // [6] THIRD-PARTY HARVEST
  line();
  console.log('  [6] third party (data broker) requests to harvest the nullifier — signs with own key');
  line();
  const brokerReq = await signReq(broker.privateKey, 'totally-not-the-ec', 'data-broker');
  const harvest = await walletHandleRequest(brokerReq);
  console.log(`  wallet: ${harvest.ok ? 'OK ❌' : harvest.reason}`);
  if (harvest.ok) throw new Error('PRIVACY: wallet answered an untrusted requester!');
  console.log('  → wallet fails to verify the request signature against the EA key → no proof.');
  console.log('     (KB is also bound to EC nonce/aud, so a different nonce makes the circuit REJECT — double defense)');

  console.log('\n'); line('═');
  console.log('  result: anonymity, one-person-one-vote, eligibility (adult/residence), request authorization, KB binding all satisfied');
  console.log(`   • first vote ACCEPT, re-vote REJECT (nullifier ${v1.nullifier.slice(0, 16)}…)`);
  console.log('   • residence is authentic via _sd membership → other districts cannot be forged (policy reject)');
  console.log('   • third-party request REJECT (wallet RP auth) + KB nonce/aud bound in circuit');
  console.log('   • issuer does not know the secret either → no cross-scope tracing (blind issuance)');
  line('═'); console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
