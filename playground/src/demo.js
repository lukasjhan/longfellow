// End-to-end playground demo:
//   1) issue   : take a bundled, already-ECDSA-signed example mdoc
//   2) setup   : generate (and cache) the ZK circuit
//   3) present : produce a zero-knowledge proof of "age_over_18"
//   4) verify  : check the proof  (expect ACCEPT)
//   5) verify' : check a tampered proof  (expect REJECT — demonstrates soundness)
//
// Run:  pnpm run demo   (after: pnpm run build:native)

import fs from 'node:fs';
import path from 'node:path';
import {
  ARTIFACTS,
  issueExample,
  generateCircuit,
  present,
  verify,
  ATTR_AGE_OVER_18,
} from './longfellow.js';

const ART = ARTIFACTS;
const p = (f) => path.join(ART, f);
const line = () => console.log('─'.repeat(64));

function step(n, title) {
  console.log('');
  line();
  console.log(`  [${n}] ${title}`);
  line();
}

async function main() {
  fs.mkdirSync(ART, { recursive: true });
  const attributes = [ATTR_AGE_OVER_18];

  // 1) ISSUE ----------------------------------------------------------------
  step(1, 'ISSUE  — load a bundled, ECDSA-signed example mDL');
  const issued = issueExample({ index: 0, outdir: ART });
  console.log('  issuer pkx :', issued.pkx.slice(0, 26) + '…');
  console.log('  doctype    :', issued.doctype);
  console.log('  now        :', issued.now);
  console.log('  mdoc bytes :', issued.mdoc_size, '(artifacts/mdoc.bin)');

  // 2) SETUP (one-time circuit) --------------------------------------------
  step(2, 'SETUP  — generate the ZK circuit for 1 attribute (cached)');
  let spec;
  const specPath = p('spec.json');
  if (fs.existsSync(p('circuit.bin')) && fs.existsSync(specPath)) {
    spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
    console.log('  (cached) circuit.bin + spec.json already present');
  } else {
    spec = generateCircuit({ attrs: 1, out: p('circuit.bin') });
    fs.writeFileSync(specPath, JSON.stringify(spec, null, 2));
    console.log(`  generated in ${spec.gen_ms} ms`);
  }
  console.log('  system       :', spec.system, '(v' + spec.version + ')');
  console.log('  circuit_hash :', spec.circuit_hash.slice(0, 24) + '…');
  console.log('  circuit_len  :', spec.circuit_len, 'bytes (compressed)');

  // 3) PRESENT --------------------------------------------------------------
  step(3, 'PRESENT — prove "age_over_18 = true" in zero knowledge');
  const pr = present({
    circuit: p('circuit.bin'),
    mdoc: p('mdoc.bin'),
    transcript: p('transcript.bin'),
    pkx: issued.pkx,
    pky: issued.pky,
    now: issued.now,
    doctype: issued.doctype,
    spec,
    attributes,
    out: p('proof.bin'),
  });
  if (!pr.ok) throw new Error('prover failed: code ' + pr.code);
  console.log(`  proof produced: ${pr.proof_len} bytes in ${pr.prove_ms} ms`);
  console.log('  (no name, birthdate, or signature is revealed — only "≥18")');

  // 4) VERIFY (valid) -------------------------------------------------------
  step(4, 'VERIFY — check the proof (expect ACCEPT)');
  const v1 = verify({
    circuit: p('circuit.bin'),
    transcript: p('transcript.bin'),
    pkx: issued.pkx,
    pky: issued.pky,
    now: issued.now,
    doctype: issued.doctype,
    spec,
    attributes,
    proof: p('proof.bin'),
  });
  console.log(`  result: ${v1.ok ? 'ACCEPT ✅' : 'REJECT ❌'} (code ${v1.code}, ${v1.verify_ms} ms)`);
  if (!v1.ok) throw new Error('expected the valid proof to be accepted');

  // 5) VERIFY (tampered) ----------------------------------------------------
  step(5, 'VERIFY — check a TAMPERED proof (expect REJECT)');
  const buf = fs.readFileSync(p('proof.bin'));
  const mid = Math.floor(buf.length / 2);
  buf[mid] ^= 0xff; // flip one byte
  fs.writeFileSync(p('proof_tampered.bin'), buf);
  const v2 = verify({
    circuit: p('circuit.bin'),
    transcript: p('transcript.bin'),
    pkx: issued.pkx,
    pky: issued.pky,
    now: issued.now,
    doctype: issued.doctype,
    spec,
    attributes,
    proof: p('proof_tampered.bin'),
  });
  console.log(`  result: ${v2.ok ? 'ACCEPT ❌(unexpected)' : 'REJECT ✅'} (code ${v2.code})`);
  if (v2.ok) throw new Error('SECURITY: tampered proof was accepted!');

  console.log('');
  line();
  console.log('  ✅ DONE — issue → present → verify works; tampering rejected.');
  line();
}

main().catch((e) => {
  console.error('\n✗ demo failed:', e.message);
  process.exit(1);
});
