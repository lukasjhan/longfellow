// Circuit cache. ZK circuits depend only on the number of attributes (N),
// not on the specific mdoc, so we generate them once per N and reuse.
//
//   circuits/circuit-<N>attr.bin   — the compressed circuit bytes
//   circuits/manifest.json         — N -> { system, circuit_hash, ... }
//
// generate_circuit() is deterministic: the resulting circuit_hash matches the
// hardcoded registry (kZkSpecs), so a cached circuit is interchangeable with a
// freshly generated one.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateCircuit } from './longfellow.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const CIRCUITS_DIR = path.resolve(__dirname, '../circuits');
export const SUPPORTED_N = [1, 2, 3, 4]; // matches kZkSpecs

export const circuitPath = (n) => path.join(CIRCUITS_DIR, `circuit-${n}attr.bin`);
const manifestPath = () => path.join(CIRCUITS_DIR, 'manifest.json');

function loadManifest() {
  try {
    return JSON.parse(fs.readFileSync(manifestPath(), 'utf8'));
  } catch {
    return {};
  }
}
function saveManifest(m) {
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });
  fs.writeFileSync(manifestPath(), JSON.stringify(m, null, 2) + '\n');
}

// Generate the circuit for N attributes, write it + update the manifest.
export function buildCircuit(n) {
  if (!SUPPORTED_N.includes(n))
    throw new Error(`unsupported attribute count N=${n} (supported: ${SUPPORTED_N.join(', ')})`);
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });
  const r = generateCircuit({ attrs: n, out: circuitPath(n) });
  if (!r.ok) throw new Error(`gencircuit(${n}) failed: ${JSON.stringify(r)}`);
  const m = loadManifest();
  m[n] = {
    system: r.system,
    circuit_hash: r.circuit_hash,
    num_attributes: r.num_attributes,
    version: r.version,
    circuit_len: r.circuit_len,
  };
  saveManifest(m);
  return { circuit: circuitPath(n), spec: m[n], gen_ms: r.gen_ms, cached: false };
}

// Return the cached circuit for N, building it on demand if missing.
export function ensureCircuit(n) {
  const m = loadManifest();
  if (m[n] && fs.existsSync(circuitPath(n)))
    return { circuit: circuitPath(n), spec: m[n], cached: true };
  return buildCircuit(n);
}

export function buildAll(ns = SUPPORTED_N) {
  return ns.map((n) => ({ n, ...buildCircuit(n) }));
}
