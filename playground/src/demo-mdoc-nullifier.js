// Demo: pseudonymous NULLIFIER (CI/DI-like) on top of a REAL ISO 18013-5 mdoc
// ZK presentation (two MAC-linked circuits: MdocSignature + MdocHash).
//
// The issuer embeds a per-person `pseudonym_secret` as a normal mdoc attribute
// (hashed into the signed MSO valueDigests, so the holder can't choose it). For
// a verifier-chosen `context`, the hash circuit proves in ZK:
//   nullifier == SHA256( secret(64B) ‖ SHA256(context) )
// extracting the secret in-circuit by a literal CBOR anchor — it is never
// revealed. Properties shown:
//   [2] same (secret, context)  -> SAME nullifier   (duplicate/Sybil detection = DI)
//   [3] different context       -> DIFFERENT nullifier (scopes unlinkable)
//   [4] forged nullifier        -> REJECT            (locked to one per scope)
//
// Run:  node src/demo-mdoc-nullifier.js   (after build:native)

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'native/mdoc_null_split');
const GEN = path.join(ROOT, 'tools/gen-mdoc.mjs');
const MDOC = path.join(ROOT, 'fixtures/mdoc.bin');
const ISSUER = path.join(ROOT, 'fixtures/mdoc-issuer.json');
const TR = path.join(ROOT, 'fixtures/mdoc-transcript.bin');
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

// run the mdoc nullifier binary for a given context; return {accept, nullifier}
function runNull(context, env = {}) {
  try {
    const out = sh(BIN, [MDOC, ISSUER, TR, NOW, ATTR_ID, ATTR_HEX, context], env);
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
    console.error('mdoc_null_split not found — run: pnpm run build:native');
    process.exit(1);
  }

  console.log('\n' + '─'.repeat(70));
  console.log('  [1] ISSUE+PRESENT — real mdoc with a per-person `pseudonym_secret`');
  line();
  if (fs.existsSync(path.join(ROOT, 'node_modules'))) {
    try { sh('node', [GEN]); console.log('  issued+presented fresh mdoc → fixtures/mdoc.bin'); }
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
  console.log('  [4] ADVERSARIAL — claim a FORGED nullifier for the same secret/context');
  line();
  const evil = runNull('context-A', { EVIL_NULL: '1' });
  console.log(`  → ${evil.accept ? 'ACCEPT ❌ (Sybil broken!)' : 'REJECT ✅ (한 scope당 nullifier 하나로 고정)'}`);
  if (evil.accept) throw new Error('SOUNDNESS: a forged nullifier was accepted!');

  console.log('\n' + '═'.repeat(70));
  console.log('  ✅ 가명 nullifier (CI/DI) on a REAL mdoc — 발급자 커밋 secret + ZK');
  console.log('     nullifier = SHA(secret ‖ SHA(context)); secret은 MSO 멤버십+리터럴');
  console.log('     앵커로 회로 안에서만 추출(비공개). 같은 scope=같은 가명(중복탐지),');
  console.log('     다른 scope=비연결, 위조=거부. mdoc Signature+Hash 2회로에 MAC 결속.');
  console.log('═'.repeat(70) + '\n');
}

main();
