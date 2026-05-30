// Demo: BLIND-ISSUANCE pseudonymous NULLIFIER on a REAL ISO 18013-5 mdoc.
//
// Difference from demo-mdoc-nullifier.js: the issuer NEVER sees the secret. The
// holder generates secret+blind, commits C = SHA256(secret‖blind), and the
// issuer signs ONLY `pseudonym_commitment` = C (a 32-byte CBOR byte string in
// the signed MSO). The hash circuit proves, in ZK:
//   * C is issuer-committed (∈ MSO valueDigests)                 (Sybil binding)
//   * the holder knows (secret,blind) that OPEN C                (knowledge)
//   * nullifier = SHA256(secret ‖ SHA256(context))              (the pseudonym)
// the SAME hidden `secret` feeds the opening and the nullifier.
//
// Properties shown:
//   [2] same (secret, context)    -> SAME nullifier      (DI dedup)
//   [3] different context         -> DIFFERENT nullifier (scopes unlinkable)
//   [4] forged nullifier          -> REJECT              (one per scope)
//   [5] wrong secret (no opening) -> REJECT  ← the BLIND property: only someone
//                                    who knows the committed secret can prove,
//                                    yet the issuer never learned it.
//
// Run:  node src/demo-mdoc-nullifier-blind.js   (after build:native)

import { execFileSync } from 'node:child_process';
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
const ATTR_ID = 'age_over_18';
const ATTR_HEX = 'f5'; // CBOR true
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
    const out = sh(BIN, [MDOC, ISSUER, TR, NOW, ATTR_ID, ATTR_HEX, context],
                   { HOLDER_SECRET: SECRET, ...env });
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { accept: /ACCEPT \(real mdoc/.test(out), nullifier: m && m[1], out };
  } catch (e) {
    const out = (e.stdout || '').toString();
    const m = out.match(/nullifier\s*: ([0-9a-f]+)/);
    return { accept: false, nullifier: m && m[1], out };
  }
}

function main() {
  if (!fs.existsSync(BIN)) {
    console.error('mdoc_null_blind not found — run: pnpm run build:native');
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE+PRESENT (BLIND) — holder commits C=SHA(secret‖blind); issuer signs C only');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { console.log(sh('node', [GEN]).trim()); }
    catch (e) { console.log('  (gen failed; using committed fixture)', e.message); }
  } else {
    console.log('  using committed fixture (no node_modules for gen)');
  }
  console.log('  → issuer saw only the commitment(MSO), never the secret (no back-tracing)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [2] context-A → nullifier  (re-run: must be the SAME = DI dedup)');
  line();
  const a1 = runNull('context-A');
  const a2 = runNull('context-A');
  console.log(`  run #1: ${a1.nullifier}  ${a1.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  console.log(`  run #2: ${a2.nullifier}  ${a2.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  if (!a1.accept || !a2.accept) throw new Error('context-A should ACCEPT');
  if (a1.nullifier !== a2.nullifier) throw new Error('same (secret,context) must give the SAME nullifier!');
  console.log('  → same (secret, context) → same nullifier ✅ (duplicate-signup/Sybil detection = DI)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [3] context-B → must be a DIFFERENT nullifier (scopes unlinkable)');
  line();
  const b = runNull('context-B');
  console.log(`  context-B: ${b.nullifier}  ${b.accept ? 'ACCEPT ✅' : 'REJECT ❌'}`);
  if (!b.accept) throw new Error('context-B should ACCEPT');
  if (b.nullifier === a1.nullifier) throw new Error('different context must give a DIFFERENT nullifier!');
  console.log('  → different context → different nullifier ✅ (services cannot be linked)');

  console.log('\n' + '─'.repeat(70));
  console.log('  [4] ADVERSARIAL — claim a FORGED nullifier for the same secret/context');
  line();
  const evil = runNull('context-A', { EVIL_NULL: '1' });
  console.log(`  → ${evil.accept ? 'ACCEPT ❌ (Sybil broken!)' : 'REJECT ✅ (one nullifier fixed per scope)'}`);
  if (evil.accept) throw new Error('SOUNDNESS: a forged nullifier was accepted!');

  console.log('\n' + '─'.repeat(70));
  console.log('  [5] BLIND PROPERTY — prover WITHOUT the committed secret cannot prove');
  line();
  const evil2 = runNull('context-A', { EVIL_SECRET: '1' });
  console.log(`  → ${evil2.accept ? 'ACCEPT ❌ (binding broken!)' : 'REJECT ✅ (commitment opening forces the secret)'}`);
  if (evil2.accept) throw new Error('SOUNDNESS: a non-committed secret was accepted!');
  console.log('  → only someone who knows the secret (unknown even to the issuer) can prove (issuer-blind + binding)');

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ BLIND pseudonymous nullifier on a REAL mdoc');
  console.log('     MSO holds only the commitment C(58 20 32B); only the holder has the secret.');
  console.log('     opening(C=SHA(secret‖blind)) + nullifier=SHA(secret‖SHA(ctx)) — same secret.');
  console.log('     no issuer back-tracing + Sybil/determinism preserved. MAC-linked across MdocSignature+MdocHash circuits.');
  console.log('═'.repeat(70) + '\n');
}

main();
