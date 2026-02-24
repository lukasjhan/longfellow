// SD-JWT(+KB) zero-knowledge demo (longfellow's experimental JWT circuit).
//
//   1) issue   : load a bundled, ES256-signed example SD-JWT-VC + KB token
//   2) present : prove the (private) token contains  "given_name":"Erika"
//   3) verify  : check the proof WITHOUT seeing the token  (expect ACCEPT)
//   4) verify' : claim a different value  (expect REJECT)
//
// The disclosed attribute is a STRING substring  "id":"value"  — booleans like
// age_over_18:true are not provable with this circuit.
//
// Usage:
//   node src/demo-jwt.js [exampleIndex] [attrId] [attrValue]
//   e.g. node src/demo-jwt.js 1 family_name Mustermann

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JWT_ARTIFACTS, issueExampleJwt, jwtProve, jwtVerify } from './jwt.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIR = JWT_ARTIFACTS;
const p = (f) => path.join(DIR, f);
const line = () => console.log('─'.repeat(70));
const step = (n, t) => {
  console.log('\n' + '─'.repeat(70));
  console.log(`  [${n}] ${t}`);
  line();
};

async function main() {
  const index = Number(process.argv[2] ?? 0);
  const attrId = process.argv[3] ?? 'given_name';
  const attrValue = process.argv[4] ?? 'Erika';
  fs.mkdirSync(DIR, { recursive: true });

  // 1) ISSUE ----------------------------------------------------------------
  step(1, `ISSUE  — 예제 SD-JWT-VC(+KB) 토큰 #${index} 로드 (ES256 서명됨)`);
  const issued = issueExampleJwt({ index, outdir: DIR });
  console.log('  issuer pkx :', issued.pkx.slice(0, 26) + '…');
  console.log('  e2 (KB hash):', issued.e2.slice(0, 26) + '…');
  console.log('  sha_blocks :', issued.sha_blocks);
  console.log('  note       :', issued.note);
  console.log('  token      :', p('jwt.txt'), `(${fs.readFileSync(p('jwt.txt')).length} chars, 비공개 witness)`);

  // 2) PRESENT --------------------------------------------------------------
  step(2, `PRESENT — "${attrId}":"${attrValue}" 가 토큰에 있음을 영지식 증명`);
  const pr = jwtProve({
    jwt: p('jwt.txt'),
    pkx: issued.pkx,
    pky: issued.pky,
    e2: issued.e2,
    attrId,
    attrValue,
    shaBlocks: issued.sha_blocks,
    out: p('proof.bin'),
  });
  if (!pr.ok) throw new Error('prover failed: ' + JSON.stringify(pr));
  console.log(`  proof ${pr.proof_len}B in ${pr.prove_ms}ms (sha_blocks=${pr.sha_blocks})`);

  // 3) VERIFY (valid) — verifier does NOT get the token ---------------------
  step(3, 'VERIFY — 토큰 없이(pk·e2·attr만) 검증 (expect ACCEPT)');
  const v1 = jwtVerify({
    pkx: issued.pkx,
    pky: issued.pky,
    e2: issued.e2,
    attrId,
    attrValue,
    shaBlocks: issued.sha_blocks,
    proof: p('proof.bin'),
  });
  console.log(`  result: ${v1.ok ? 'ACCEPT ✅' : 'REJECT ❌'} (${v1.verify_ms}ms)`);
  if (!v1.ok) throw new Error('expected accept');

  // 4) VERIFY (wrong value) -------------------------------------------------
  step(4, 'VERIFY — 다른 값으로 클레임 (expect REJECT)');
  const wrong = attrValue.slice(0, -1) + (attrValue.endsWith('z') ? 'y' : 'z');
  console.log(`  "${attrId}":"${attrValue}" → "${attrId}":"${wrong}" 로 위조`);
  const v2 = jwtVerify({
    pkx: issued.pkx,
    pky: issued.pky,
    e2: issued.e2,
    attrId,
    attrValue: wrong,
    shaBlocks: issued.sha_blocks,
    proof: p('proof.bin'),
  });
  console.log(`  result: ${v2.ok ? 'ACCEPT ❌(unexpected)' : 'REJECT ✅'}`);
  if (v2.ok) throw new Error('SECURITY: wrong value accepted!');

  console.log('\n' + '═'.repeat(70));
  console.log(`  ✅ SD-JWT ZK: "${attrId}=${attrValue}" 공개/검증 성공, 위조 거부`);
  console.log('     (검증자는 토큰 원문을 보지 못함 — 서명·다른 클레임 비공개)');
  console.log('═'.repeat(70) + '\n');
}

main().catch((e) => {
  console.error('\n✗ demo-jwt failed:', e.message);
  process.exit(1);
});
