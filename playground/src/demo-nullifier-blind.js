// Demo: BLIND-ISSUANCE pseudonymous NULLIFIER on SD-JWT-VC.
//
// Difference from demo-nullifier.js: the issuer NEVER sees the secret. The holder
// generates secret+blind, commits C = SHA256(secret‖blind), and the issuer signs
// ONLY `pseudonym_commitment` = base64url(C). The circuit proves, in ZK:
//   * C is issuer-committed (∈ _sd)                              (Sybil binding)
//   * the holder knows (secret,blind) that OPEN C                (knowledge)
//   * nullifier = SHA256(secret ‖ SHA256(context))              (the pseudonym)
// the SAME hidden `secret` feeds both the opening and the nullifier.
//
// Properties shown:
//   [2] same (secret, context)   -> SAME nullifier      (DI dedup)
//   [3] different context        -> DIFFERENT nullifier (scopes unlinkable)
//   [4] empty context (global)   -> CI-like pseudonym
//   [5] forged nullifier         -> REJECT              (one per scope)
//   [6] wrong secret (no opening)-> REJECT  ← the BLIND property: only someone
//                                   who knows the committed secret can prove,
//                                   yet the issuer never learned it.
//
// Run:  node src/demo-nullifier-blind.js   (after build:native)

import { execFileSync } from 'node:child_process';
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

function runNull(context, env = {}) {
  try {
    const out = sh(BIN, [FIX, JWK, '1700000000', CLAIMS, VCT, NONCE, AUD, context],
                   { HOLDER_SECRET: SECRET, ...env });
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { ok: true, accept: /ACCEPT/.test(out), nullifier: m && m[1], out };
  } catch (e) {
    const out = (e.stdout || '').toString();
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { ok: false, accept: false, nullifier: m && m[1], out };
  }
}

function main() {
  if (!fs.existsSync(BIN)) {
    console.error('sdjwt_null_blind not found — run: pnpm run build:native');
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE (BLIND) — holder commits C=SHA(secret‖blind); issuer signs C only');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { console.log(sh('node', [GEN]).trim()); }
    catch { console.log('  (gen failed; using committed fixture)'); }
  } else {
    console.log('  using committed fixture (no node_modules for gen)');
  }
  console.log('  → 발급자는 commitment만 봤고 secret은 본 적 없음 (역추적 불가)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [2] context-A → nullifier  (re-run: must be the SAME = DI dedup)');
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

  console.log('\n' + '─'.repeat(70));
  console.log('  [6] BLIND PROPERTY — prover WITHOUT the committed secret cannot prove');
  line();
  const evil2 = runNull('context-A', { EVIL_SECRET: '1' });
  console.log(`  → ${evil2.accept ? 'ACCEPT ❌ (binding broken!)' : 'REJECT ✅ (commitment opening이 secret을 강제)'}`);
  if (evil2.accept) throw new Error('SOUNDNESS: a non-committed secret was accepted!');
  console.log('  → 발급자조차 모르는 secret을 아는 사람만 증명 가능 (issuer-blind + binding)');

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ BLIND 가명 nullifier on SD-JWT-VC');
  console.log('     크리덴셜엔 commitment C만 있고 secret은 홀더만 보유.');
  console.log('     ③ open(C=SHA(secret‖blind)) + ④ nullifier=SHA(secret‖SHA(ctx)) — 같은 secret.');
  console.log('     발급자 역추적 불가 + Sybil/결정성 유지. (CI/DI보다 강한 프라이버시)');
  console.log('═'.repeat(70) + '\n');
}

main();
