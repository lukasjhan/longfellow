// Step-by-step playground CLI. State is persisted in artifacts/ so each step
// can be run independently:
//
//   node src/playground.js issue     # load example mdoc + build circuit
//   node src/playground.js present   # produce the ZK proof
//   node src/playground.js verify    # verify the ZK proof
//
// (or just: pnpm run issue / present / verify)

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
const attributes = [ATTR_AGE_OVER_18];

function loadIssued() {
  if (!fs.existsSync(p('issued.json')))
    throw new Error('run "issue" first (artifacts/issued.json missing)');
  return JSON.parse(fs.readFileSync(p('issued.json'), 'utf8'));
}
function loadSpec() {
  if (!fs.existsSync(p('spec.json')))
    throw new Error('run "issue" first (artifacts/spec.json missing)');
  return JSON.parse(fs.readFileSync(p('spec.json'), 'utf8'));
}

function doIssue() {
  fs.mkdirSync(ART, { recursive: true });
  const index = Number(process.argv[3] ?? 0);
  const issued = issueExample({ index, outdir: ART });
  console.log('issued example mdoc:', JSON.stringify(issued));
  const spec = generateCircuit({ attrs: 1, out: p('circuit.bin') });
  fs.writeFileSync(p('spec.json'), JSON.stringify(spec, null, 2));
  console.log('circuit ready    :', JSON.stringify(spec));
}

function doPresent() {
  const issued = loadIssued();
  const spec = loadSpec();
  const r = present({
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
  console.log('present (prove)  :', JSON.stringify(r));
  if (!r.ok) process.exit(1);
}

function doVerify() {
  const issued = loadIssued();
  const spec = loadSpec();
  const r = verify({
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
  console.log('verify           :', JSON.stringify(r), r.ok ? 'ACCEPT ✅' : 'REJECT ❌');
  process.exit(r.ok ? 0 : 1);
}

const cmd = process.argv[2];
try {
  if (cmd === 'issue') doIssue();
  else if (cmd === 'present') doPresent();
  else if (cmd === 'verify') doVerify();
  else {
    console.error('usage: node src/playground.js <issue|present|verify> [exampleIndex]');
    process.exit(2);
  }
} catch (e) {
  console.error('✗', e.message);
  process.exit(1);
}
