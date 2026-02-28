// Decode + verify a compact SD-JWT-VC, showing EXACTLY the checks the future ZK
// circuit must perform. Dependency-free (uses node:crypto for SHA-256).
//
// This is the plaintext reference for "Approach C": prove a disclosure's digest
// is a member of the issuer-signed `_sd` array, and that the disclosure decodes
// to (claimName, claimValue). Works for any value type (string/date/bool/num).
//
// Usage:  node src/decode-sdjwt.js [path-to-sdjwt.txt]
//         (default: fixtures/sdjwt.txt — run tools/gen-sdjwt.mjs to (re)create)

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const b64urlToBuf = (s) => Buffer.from(s, 'base64url');
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest();

function main() {
  const file = process.argv[2] || path.resolve(__dirname, '../fixtures/sdjwt.txt');
  if (!fs.existsSync(file)) {
    console.error(`SD-JWT not found: ${file}\n(run: node tools/gen-sdjwt.mjs)`);
    process.exit(1);
  }
  const compact = fs.readFileSync(file, 'utf8').trim();

  // Compact form: <issuer-jwt> ~ <disc1> ~ <disc2> ~ ... ~ [<kbjwt>]
  const parts = compact.split('~');
  const jwt = parts[0];
  const last = parts[parts.length - 1];
  const hasKb = last !== '' && last.split('.').length === 3;
  const discStrs = parts.slice(1, hasKb ? -1 : parts.length).filter(Boolean);

  const [h, p] = jwt.split('.');
  const header = JSON.parse(b64urlToBuf(h).toString('utf8'));
  const payload = JSON.parse(b64urlToBuf(p).toString('utf8'));

  console.log(`\nSD-JWT file: ${path.relative(process.cwd(), file)}`);
  console.log('═'.repeat(74));
  console.log('  ISSUER JWT');
  console.log('═'.repeat(74));
  console.log('  alg / typ   :', header.alg, '/', header.typ);
  console.log('  iss / vct   :', payload.iss, '/', payload.vct);
  console.log('  iat / exp   :', new Date(payload.iat * 1e3).toISOString(),
    '→', new Date(payload.exp * 1e3).toISOString());
  console.log('  _sd_alg     :', payload._sd_alg);
  console.log('  _sd digests :', (payload._sd || []).length, '(서명된 다이제스트 집합)');
  console.log('  cnf.jwk     :', payload.cnf?.jwk ? `present (${payload.cnf.jwk.crv})` : 'none');

  const sdSet = new Set(payload._sd || []);

  console.log('\n' + '═'.repeat(74));
  console.log('  DISCLOSURES  (각 클레임을 개별 salt+해시 → _sd 멤버십이 곧 증명 단위)');
  console.log('═'.repeat(74));
  console.log('  claim'.padEnd(16), 'type'.padEnd(8), 'value'.padEnd(16), 'digest∈_sd');
  console.log('  ' + '─'.repeat(70));
  let allOk = true;
  for (const ds of discStrs) {
    const arr = JSON.parse(b64urlToBuf(ds).toString('utf8')); // [salt, name, value]
    const [, name, value] = arr;
    // The circuit's core check: base64url(SHA-256(ascii(disclosure))) ∈ _sd
    const digest = b64url(sha256(Buffer.from(ds, 'ascii')));
    const inSd = sdSet.has(digest);
    allOk &&= inSd;
    const t = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    console.log(
      '  ' + String(name).padEnd(16),
      t.padEnd(8),
      JSON.stringify(value).padEnd(16),
      inSd ? '✅ ' + digest.slice(0, 10) + '…' : '❌ NOT IN _sd',
    );
  }

  console.log('\n' + '─'.repeat(74));
  console.log(`  ${allOk ? '✅' : '❌'} 모든 disclosure 해시가 서명된 _sd에 포함됨`);
  console.log('  → 회로가 증명할 것 (Approach C):');
  console.log('     1) 발급자 ES256 서명이 payload(=_sd 포함)에 유효');
  console.log('     2) (홀더) Key Binding 서명 유효');
  console.log('     3) now ≤ exp  (유효기간)');
  console.log('     4) 선택 disclosure: SHA(disclosure) ∈ _sd  +  (claim,value) 일치');
  console.log('     ※ 값이 문자열/날짜/불리언/숫자 무엇이든 동일 — 파싱 불필요');
  console.log('─'.repeat(74) + '\n');
}

main();
