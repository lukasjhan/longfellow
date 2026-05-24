// Demo: pseudonymous NULLIFIER (CI/DI-like) on top of a full SD-JWT-VC ZK proof.
//
// The issuer embeds a per-person `pseudonym_secret` (an _sd claim, so the holder
// can't choose it). For a verifier-chosen `context_id`, the circuit proves in ZK:
//   nullifier == SHA256( secret ‖ context_id )
// revealing only the nullifier (the secret stays hidden). Properties shown:
//   [2] same (secret, context)  -> SAME nullifier   (duplicate/Sybil detection = DI)
//   [3] different context       -> DIFFERENT nullifier (scopes unlinkable)
//   [4] empty context (global)  -> CI-like cross-service pseudonym
//   [5] forged nullifier        -> REJECT            (locked to one per scope)
//
// Run:  node src/demo-nullifier.js   (after build:native)

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
// default to the fast 2-circuit split; MONO=1 uses the single-circuit monolith
const SPLIT = process.env.MONO !== '1';
const BIN = path.join(ROOT, SPLIT ? 'native/sdjwt_null_split' : 'native/sdjwt_nullifier');
const GEN = path.join(ROOT, 'tools/gen-sdjwt.mjs');
const FIX = path.join(ROOT, 'fixtures/sdjwt.txt');
const JWK = path.join(ROOT, 'fixtures/issuer-jwk.json');
const CLAIMS = 'age_over_18';
const VCT = 'https://credentials.example/pid';
const NONCE = '1234567890';
const AUD = 'https://verifier.example';
const line = () => console.log('─'.repeat(70));

function sh(cmd, args, env = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', process.env.DEBUG === '1' ? 'inherit' : 'pipe'],
    env: { ...process.env, ...env },
  });
}

// run the nullifier binary for a given context; return {ok, accept, nullifier}
function runNull(context, env = {}) {
  try {
    const out = sh(BIN, [FIX, JWK, '1700000000', CLAIMS, VCT, NONCE, AUD, context], env);
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { ok: true, accept: /ACCEPT/.test(out), nullifier: m && m[1], out };
  } catch (e) {
    const out = (e.stdout || '').toString();
    const m = out.match(/nullifier : ([0-9a-f]+)/);
    return { ok: false, accept: false, nullifier: m && m[1], out };
  }
}

function main() {
  if (!fs.existsSync(BIN)) {
    console.error('sdjwt_nullifier not found — run: pnpm run build:native');
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE — SD-JWT-VC with a per-person `pseudonym_secret` (in _sd)');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN]); console.log('  issued fresh credential → fixtures/'); }
    catch { console.log('  (gen failed; using committed fixture)'); }
  } else {
    console.log('  using committed fixture (no node_modules for gen)');
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [2] context-A → nullifier  (then re-run: must be the SAME = DI dedup)');
  line();
  const a1 = runNull('context-A');
  const a2 = runNull('context-A');
  console.log(`  run #1: ${a1.nullifier}  ${a1.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  console.log(`  run #2: ${a2.nullifier}  ${a2.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  if (!a1.accept || !a2.accept) throw new Error('context-A should ACCEPT');
  if (a1.nullifier !== a2.nullifier) throw new Error('same (secret,context) must give the SAME nullifier!');
  console.log('  → 같은 (secret, context) → 같은 nullifier ✅ (중복가입/Sybil 탐지 = DI)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] context-B → must be a DIFFERENT nullifier (scopes unlinkable)');
  line();
  const b = runNull('context-B');
  console.log(`  context-B: ${b.nullifier}  ${b.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  if (!b.accept) throw new Error('context-B should ACCEPT');
  if (b.nullifier === a1.nullifier) throw new Error('different context must give a DIFFERENT nullifier!');
  console.log('  → 다른 context → 다른 nullifier ✅ (서비스 간 연결 불가)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [4] empty context (global) → CI-like cross-service pseudonym');
  line();
  const g = runNull('');
  console.log(`  global: ${g.nullifier}  ${g.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  if (!g.accept) throw new Error('global should ACCEPT');
  console.log('  → 빈 context = 모든 곳에서 같은 값 (CI). scope를 주면 DI.');

  console.log('\n' + '─'.repeat(70));
  console.log('  [5] ADVERSARIAL — claim a FORGED nullifier for the same secret/context');
  line();
  const evil = runNull('context-A', { EVIL_NULL: '1' });
  console.log(`  → ${evil.accept ? 'ACCEPT ❌ (Sybil broken!)' : 'REJECT ✅ (한 scope당 nullifier 하나로 고정)'}`);
  if (evil.accept) throw new Error('SOUNDNESS: a forged nullifier was accepted!');

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ 가명 nullifier (CI/DI) on SD-JWT-VC — 발급자 커밋 secret + ZK');
  console.log('     nullifier = SHA(secret ‖ context); secret은 _sd 멤버십으로 숨김.');
  console.log('     같은 scope=같은 가명(중복탐지), 다른 scope=비연결, 위조=거부.');
  console.log('═'.repeat(70) + '\n');
}

main();
