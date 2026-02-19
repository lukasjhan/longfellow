// Multi-attribute ZK presentation demo.
//
// Picks an example mdoc (default #3 = Sprind-Funke, which carries 5 attributes),
// extracts the EXACT CBOR value bytes for the requested attributes straight from
// the mdoc, builds an N-attribute circuit, then proves + verifies disclosure of
// several attributes at once. Finally shows that lying about one value (while
// keeping the others honest) is rejected.
//
// Usage:
//   node src/demo-multi.js [exampleIndex] [id1,id2,...]
//   e.g. node src/demo-multi.js 3 family_name,age_over_18
//        node src/demo-multi.js 3 family_name,height,age_over_18

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { issueExample, present, verify } from './longfellow.js';
import { ensureCircuit } from './circuits.js';
import { attributesOf, showValue } from './cbor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.resolve(__dirname, '../artifacts-multi');
const p = (f) => path.join(DIR, f);
const line = () => console.log('─'.repeat(70));
const step = (n, t) => {
  console.log('\n' + '─'.repeat(70));
  console.log(`  [${n}] ${t}`);
  line();
};

async function main() {
  const index = Number(process.argv[2] ?? 3);
  const wantIds = (process.argv[3] ?? 'family_name,age_over_18').split(',').map((s) => s.trim());
  fs.mkdirSync(DIR, { recursive: true });

  // 1) ISSUE -----------------------------------------------------------------
  step(1, `ISSUE  — example #${index} 로드`);
  const issued = issueExample({ index, outdir: DIR });
  console.log('  doctype:', issued.doctype, '| now:', issued.now);

  // 2) mdoc에서 실제 속성 + raw CBOR 값 추출 ---------------------------------
  step(2, 'EXTRACT — mdoc 안의 issuer-signed 속성 (raw CBOR 값)');
  const all = attributesOf(fs.readFileSync(p('mdoc.bin')));
  for (const a of all)
    console.log(`    • ${a.id.padEnd(22)} = ${showValue(a.value).padEnd(26)} valueHex=${a.valueHex}`);

  const requested = wantIds.map((id) => {
    const a = all.find((x) => x.id === id);
    if (!a) throw new Error(`attribute "${id}" not in this mdoc (have: ${all.map((x) => x.id).join(', ')})`);
    return { namespace: a.namespace, id: a.id, valueHex: a.valueHex };
  });
  console.log(`\n  → 동시에 공개할 속성 ${requested.length}개:`, requested.map((r) => r.id).join(', '));

  // 3) SETUP — cached N-attribute circuit -----------------------------------
  step(3, `SETUP  — ${requested.length}-속성 회로 (캐시)`);
  const { circuit, spec, cached } = ensureCircuit(requested.length);
  console.log(`  ${cached ? '(cached)' : '(generated now)'} ${spec.system} v${spec.version}, ${spec.num_attributes}-attr, ${spec.circuit_len}B`);

  const common = {
    circuit,
    transcript: p('transcript.bin'),
    pkx: issued.pkx,
    pky: issued.pky,
    now: issued.now,
    doctype: issued.doctype,
    spec,
  };

  // 4) PRESENT ---------------------------------------------------------------
  step(4, `PRESENT — ${requested.length}개 속성을 한 번에 영지식 증명`);
  const pr = present({ ...common, mdoc: p('mdoc.bin'), attributes: requested, out: p('proof.bin') });
  if (!pr.ok) throw new Error('prover failed: code ' + pr.code);
  console.log(`  proof ${pr.proof_len}B in ${pr.prove_ms}ms`);

  // 5) VERIFY (valid) --------------------------------------------------------
  step(5, 'VERIFY — 정직한 클레임 (expect ACCEPT)');
  const v1 = verify({ ...common, attributes: requested, proof: p('proof.bin') });
  console.log(`  ${v1.ok ? 'ACCEPT ✅' : 'REJECT ❌'} (code ${v1.code}, ${v1.verify_ms}ms)`);
  if (!v1.ok) throw new Error('expected accept');

  // 6) VERIFY (lie about one value) -----------------------------------------
  step(6, 'VERIFY — 한 속성 값만 위조 (expect REJECT)');
  const tampered = requested.map((r, i) => {
    if (i !== 0) return r;
    // flip the last byte of the first attribute's value (stays valid CBOR length)
    const b = Buffer.from(r.valueHex, 'hex');
    b[b.length - 1] ^= 0x01;
    return { ...r, valueHex: b.toString('hex') };
  });
  console.log(`  "${requested[0].id}" 값을 ${requested[0].valueHex} → ${tampered[0].valueHex} 로 위조`);
  const v2 = verify({ ...common, attributes: tampered, proof: p('proof.bin') });
  console.log(`  ${v2.ok ? 'ACCEPT ❌(unexpected)' : 'REJECT ✅'} (code ${v2.code})`);
  if (v2.ok) throw new Error('SECURITY: lying about a value was accepted!');

  console.log('\n' + '═'.repeat(70));
  console.log(`  ✅ 다속성 증명 성공: ${requested.map((r) => r.id).join(' + ')} 동시 공개 / 위조 거부`);
  console.log('═'.repeat(70) + '\n');
}

main().catch((e) => {
  console.error('\n✗ demo-multi failed:', e.message);
  process.exit(1);
});
