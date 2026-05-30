// SCENARIO: anonymous, double-vote-resistant voting with a BLIND nullifier.
//
// A voter holds a real mdoc (issued blind: the issuer committed C=SHA(secret‖blind)
// and never learned the secret). At a polling station the voter proves, in ONE
// zero-knowledge proof:
//   * age_over_18 == true            (eligible: adult)
//   * resident_city == "Seoul"        (eligible: lives in this district)
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
      return { ok: false, reason: 'request signature not verified by a trusted EA key → reject (no proof generated)' };
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
    if (!res.accept) return `❌ proof rejected (ineligible/forged) — ${who}`;
    if (seen.has(res.nullifier)) return `❌ nullifier already voted → re-vote rejected — ${who}`;
    seen.add(res.nullifier);
    return `✅ vote counted (nullifier registered) — ${who}`;
  }

  const ELECTION = 'kr-2026-local-election:seoul';   // the DI scope for this poll
  const districtRequire = [
    { claim: 'age_over_18' },                        // must be an adult
    { claim: 'resident_city', equals: 'Seoul' },     // must live in Seoul
  ];

  console.log('\n');
  line('═');
  console.log('  anonymous one-person-one-vote scenario — BLIND nullifier on a real mdoc');
  line('═');

  // [1] ISSUE
  line();
  console.log('  [1] issue — store mdoc in wallet (adult, Seoul residence, pseudonym commitment C)');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN]); console.log('  issued → fixtures/mdoc-blind.bin (issuer does not know the secret)'); }
    catch { console.log('  (gen failed; using existing fixture)'); }
  } else console.log('  using existing fixture');

  // [2] EC signs a presentation request; the wallet verifies it
  line();
  console.log('  [2] EA-signed presentation request → wallet verifies signature & authorization');
  line();
  const ecRequest = await new SignJWT({
    purpose: '2026 local election polling-station identity check',
    district: 'Seoul',
    require: districtRequire,
    nullifier_context: ELECTION,           // the DI scope = this election
    nonce: 'poll-nonce-' + Date.now(),
  }).setProtectedHeader({ alg: 'ES256', kid: ecPubJwk.kid })
    .setIssuer('gimpo-election-commission')
    .setAudience('wallet')
    .setExpirationTime('5m')
    .sign(ec.privateKey);
  console.log('  EC request JWT signed (iss=gimpo-election-commission)');

  // [3] FIRST VOTE
  line();
  console.log('  [3] first vote — wallet submits ZK (adult + Seoul residence + election-scope nullifier)');
  line();
  const v1 = await walletHandleRequest(ecRequest);
  console.log(`  request check: ${v1.ok ? 'OK (trusted EA)' : 'rejected'}`);
  console.log(`  ZK proof : ${v1.accept ? 'ACCEPT (adult✅ Seoul residence✅)' : 'REJECT'}`);
  console.log(`  nullifier: ${v1.nullifier}`);
  console.log('  EA:', ecCountVote(v1, 'voter (first visit)'));
  if (!v1.accept || !seen.has(v1.nullifier)) throw new Error('first vote should be counted');

  // [4] DOUBLE VOTE — same person comes back
  line();
  console.log('  [4] re-vote attempt — same person returns (same secret → same nullifier)');
  line();
  const v2 = await walletHandleRequest(ecRequest);
  console.log(`  nullifier: ${v2.nullifier}  ${v2.nullifier === v1.nullifier ? '(same as first vote)' : '(different?!)'}`);
  console.log('  EA:', ecCountVote(v2, 'voter (return visit)'));
  if (v2.nullifier !== v1.nullifier) throw new Error('same voter must yield same nullifier');

  // [5] ADDRESS FORGERY — same voter tries to vote as a Seoul resident
  line();
  console.log('  [5] address forgery attempt — claim "Busan" residence with a Seoul credential');
  line();
  const forged = zkPresent(
    [{ id: 'age_over_18', hex: CBOR_TRUE }, { id: 'resident_city', hex: cborText('Busan') }],
    'kr-2026-local-election:busan');
  console.log(`  ZK proof : ${forged.accept ? 'ACCEPT ❌ (address forgery succeeded?!)' : 'REJECT ✅ (credential says Seoul — value mismatch)'}`);
  if (forged.accept) throw new Error('SOUNDNESS: forged address accepted!');

  // [6] THIRD-PARTY HARVEST — a data broker tries to learn the nullifier
  line();
  console.log('  [6] third party (data broker) requests to harvest the nullifier — signs with own key');
  line();
  const brokerRequest = await new SignJWT({
    purpose: 'prize-draw identity check (impersonation)',
    require: districtRequire,
    nullifier_context: ELECTION,            // tries to reuse the election scope
    nonce: 'evil',
  }).setProtectedHeader({ alg: 'ES256', kid: 'data-broker' })
    .setIssuer('totally-not-the-ec')
    .setAudience('wallet')
    .setExpirationTime('5m')
    .sign(broker.privateKey);
  const harvest = await walletHandleRequest(brokerRequest);
  console.log(`  wallet: ${harvest.ok ? 'OK ❌' : harvest.reason}`);
  if (harvest.ok) throw new Error('PRIVACY: wallet answered an untrusted requester!');
  console.log('  → wallet fails to verify the request signature against the EA key → no proof is produced.');
  console.log('     (even if produced, the election-scope nullifier is blind, so issuer/third party cannot compute it)');

  // summary
  console.log('\n');
  line('═');
  console.log('  result: anonymity, one-person-one-vote, eligibility (adult/residence), request authorization all satisfied');
  console.log(`   • first vote ACCEPT, re-vote REJECT (nullifier ${v1.nullifier.slice(0, 16)}…)`);
  console.log('   • address forgery REJECT (bound to credential value)');
  console.log('   • third-party request REJECT (wallet only answers EA signatures)');
  console.log('   • issuer does not know the secret either → no cross-scope tracing (blind issuance)');
  line('═');
  console.log('');
}

main().catch((e) => { console.error(e); process.exit(1); });
