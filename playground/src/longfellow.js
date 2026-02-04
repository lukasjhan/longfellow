// Thin Node.js wrapper around the longfellow_cli C++ binary.
//
// Every call spawns the CLI as a subprocess and parses its single-line JSON
// result from stdout. This keeps the binding trivial (no native addon / ABI),
// which is ideal for a playground. Swap to N-API later if you need in-process
// calls.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const CLI = path.resolve(__dirname, '../native/longfellow_cli');
export const ARTIFACTS = path.resolve(__dirname, '../artifacts');

function runCli(args) {
  if (!fs.existsSync(CLI)) {
    throw new Error(
      `longfellow_cli not found at ${CLI}\n` +
        `Build it first:  pnpm run build:native  (or: bash native/build.sh)`,
    );
  }
  // The C++ library is chatty on stderr (INFO logs). Capture it and only
  // surface it when DEBUG=1, so the playground output stays readable.
  const debug = process.env.DEBUG === '1' || process.env.DEBUG === 'true';
  let stdout;
  try {
    stdout = execFileSync(CLI, args, {
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      stdio: ['ignore', 'pipe', debug ? 'inherit' : 'pipe'],
    });
  } catch (err) {
    // verify-failure / prover-failure exit non-zero but still print JSON.
    stdout = err.stdout ? err.stdout.toString() : '';
    if (debug && err.stderr) process.stderr.write(err.stderr);
    if (!stdout) throw err;
  }
  const lines = stdout.trim().split('\n').filter(Boolean);
  const last = lines[lines.length - 1];
  try {
    return JSON.parse(last);
  } catch {
    throw new Error(`could not parse CLI output as JSON:\n${stdout}`);
  }
}

function attrArgs(attributes) {
  // attributes: [{ namespace, id, valueHex }]
  const out = [];
  for (const a of attributes) {
    out.push('--attr', `${a.namespace}:${a.id}:${a.valueHex}`);
  }
  return out;
}

/**
 * "Issue" step (for the playground we reuse a bundled, already ECDSA-signed
 * example mdoc). Writes mdoc.bin, transcript.bin, issued.json into `outdir`.
 * Returns the issued.json contents.
 */
export function issueExample({ index = 0, outdir = ARTIFACTS } = {}) {
  fs.mkdirSync(outdir, { recursive: true });
  return runCli(['export-example', '--index', String(index), '--outdir', outdir]);
}

/**
 * Generate (and cache) the ZK circuit for `attrs` attributes.
 * Returns { ok, system, circuit_hash, num_attributes, version, circuit_len }.
 */
export function generateCircuit({ attrs = 1, out } = {}) {
  const target = out ?? path.join(ARTIFACTS, 'circuit.bin');
  return runCli(['gencircuit', '--attrs', String(attrs), '--out', target]);
}

/**
 * "Present" step: produce a zero-knowledge presentation proof.
 * spec = { system, circuit_hash } from generateCircuit().
 * Returns { ok, proof_len, prove_ms }.
 */
export function present({
  circuit,
  mdoc,
  transcript,
  pkx,
  pky,
  now,
  doctype,
  spec,
  attributes,
  out,
}) {
  return runCli([
    'prove',
    '--circuit', circuit,
    '--mdoc', mdoc,
    '--transcript', transcript,
    '--pkx', pkx,
    '--pky', pky,
    '--now', now,
    '--doctype', doctype,
    '--system', spec.system,
    '--circuit-hash', spec.circuit_hash,
    ...attrArgs(attributes),
    '--out', out,
  ]);
}

/**
 * "Verify" step: check a presentation proof.
 * Returns { ok, code, verify_ms }.
 */
export function verify({
  circuit,
  transcript,
  pkx,
  pky,
  now,
  doctype,
  spec,
  attributes,
  proof,
}) {
  return runCli([
    'verify',
    '--circuit', circuit,
    '--transcript', transcript,
    '--pkx', pkx,
    '--pky', pky,
    '--now', now,
    '--doctype', doctype,
    '--system', spec.system,
    '--circuit-hash', spec.circuit_hash,
    ...attrArgs(attributes),
    '--proof', proof,
  ]);
}

// Common request: prove the holder is over 18 (ISO mDL namespace).
export const ATTR_AGE_OVER_18 = {
  namespace: 'org.iso.18013.5.1',
  id: 'age_over_18',
  valueHex: 'f5', // CBOR true
};
