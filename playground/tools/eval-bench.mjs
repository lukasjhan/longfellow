// §7 Evaluation benchmark harness.
//
// Runs each feature × format circuit binary R times, parses the metrics the
// binaries already print (prove / verify ms, proof bundle KB, per-circuit
// ninputs / circuit KB / proof KB, ACCEPT/REJECT), and emits:
//   - a markdown table to stdout (paste into §7),
//   - fixtures/eval-results.json  (raw + aggregated),
//   - fixtures/eval-results.csv   (one row per cell),
//   - fixtures/eval-table.md      (the paper table).
//
// Usage:
//   node tools/eval-bench.mjs                 # all rows, REPS=7
//   REPS=11 node tools/eval-bench.mjs         # more repetitions
//   ROWS=sdjwt-blind,mdoc-revoc node tools/eval-bench.mjs   # subset
//   NOGEN=1 node tools/eval-bench.mjs         # skip fixture (re)generation
//
// Notes:
//   * The binaries' `prove_ms`/`verify_ms` already EXCLUDE circuit build
//     (build is timed separately). We still do 1 warmup run per row to warm
//     the on-disk circuit cache and the OS page cache.
//   * prove/verify are wall-clock on this machine; report the machine in §7.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');           // playground/
const NAT = (b) => path.join(ROOT, 'native', b);
const FX = (f) => path.join(ROOT, 'fixtures', f);
const GEN = (g) => path.join(ROOT, 'tools', g);

const REPS = parseInt(process.env.REPS || '7', 10);
const WARMUP = parseInt(process.env.WARMUP || '1', 10);
const NOGEN = process.env.NOGEN === '1';
const ONLY = (process.env.ROWS || '').split(',').map((s) => s.trim()).filter(Boolean);

// shared SD-JWT statement constants (mirror the demos)
const VCT = 'https://credentials.example/pid';
const NONCE = '1234567890';
const AUD = 'https://verifier.example';
const CTX = 'context-A';
const EPOCH = '7';
// shared mdoc statement constants
const NOW = '2026-06-01T00:00:00Z';
const ATTR_ID = 'age_over_18';
const ATTR_HEX = 'f5';

// One row per evaluation cell. `gen` fixtures are produced once (unless NOGEN).
const ROWS = [
  // ---- SD-JWT VC ----
  { key: 'sdjwt-base', format: 'SD-JWT VC', feature: 'base (SD + sig)',
    bin: NAT('sdjwt_split'), gen: 'gen-sdjwt.mjs', need: ['sdjwt.txt', 'issuer-jwk.json'],
    args: [FX('sdjwt.txt'), FX('issuer-jwk.json'), '1700000000', 'given_name,age_over_18,height', VCT, NONCE, AUD] },
  { key: 'sdjwt-null', format: 'SD-JWT VC', feature: '+ nullifier',
    bin: NAT('sdjwt_null_split'), gen: 'gen-sdjwt.mjs', need: ['sdjwt.txt', 'issuer-jwk.json'],
    args: [FX('sdjwt.txt'), FX('issuer-jwk.json'), '1700000000', ATTR_ID, VCT, NONCE, AUD, CTX] },
  { key: 'sdjwt-blind', format: 'SD-JWT VC', feature: '+ blind nullifier',
    bin: NAT('sdjwt_null_blind'), gen: 'gen-sdjwt-blind.mjs', need: ['sdjwt-blind.txt', 'issuer-jwk-blind.json', 'holder-secret.txt'],
    args: [FX('sdjwt-blind.txt'), FX('issuer-jwk-blind.json'), '1700000000', ATTR_ID, VCT, NONCE, AUD, CTX],
    env: { HOLDER_SECRET: FX('holder-secret.txt') } },
  { key: 'sdjwt-revoc', format: 'SD-JWT VC', feature: '+ revocation',
    bin: NAT('sdjwt_revoc_split'), gen: 'gen-sdjwt.mjs', need: ['sdjwt.txt', 'issuer-jwk.json'],
    args: [FX('sdjwt.txt'), FX('issuer-jwk.json'), '1700000000', ATTR_ID, VCT, NONCE, AUD, EPOCH] },
  // ---- ISO mdoc ----
  { key: 'mdoc-null', format: 'ISO mdoc', feature: '+ nullifier',
    bin: NAT('mdoc_null_split'), gen: 'gen-mdoc.mjs', need: ['mdoc.bin', 'mdoc-issuer.json', 'mdoc-transcript.bin'],
    args: [FX('mdoc.bin'), FX('mdoc-issuer.json'), FX('mdoc-transcript.bin'), NOW, ATTR_ID, ATTR_HEX, CTX] },
  { key: 'mdoc-blind', format: 'ISO mdoc', feature: '+ blind nullifier',
    bin: NAT('mdoc_null_blind'), gen: 'gen-mdoc-blind.mjs', need: ['mdoc-blind.bin', 'mdoc-blind-issuer.json', 'mdoc-blind-transcript.bin', 'mdoc-holder-secret.txt'],
    args: [FX('mdoc-blind.bin'), FX('mdoc-blind-issuer.json'), FX('mdoc-blind-transcript.bin'), NOW, ATTR_ID, ATTR_HEX, CTX],
    env: { HOLDER_SECRET: FX('mdoc-holder-secret.txt') } },
  { key: 'mdoc-revoc', format: 'ISO mdoc', feature: '+ revocation',
    bin: NAT('mdoc_revoc_split'), gen: 'gen-mdoc.mjs', need: ['mdoc.bin', 'mdoc-issuer.json', 'mdoc-transcript.bin'],
    args: [FX('mdoc.bin'), FX('mdoc-issuer.json'), FX('mdoc-transcript.bin'), NOW, ATTR_ID, ATTR_HEX, EPOCH] },
];

function run(cmd, args, env = {}) {
  return execFileSync(cmd, args, {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env },
  });
}

// flexible metric extraction (works across the sig/hash split binaries)
function parse(out) {
  const num = (re) => { const m = out.match(re); return m ? parseInt(m[1], 10) : null; };
  const prove = num(/prove\s*=\s*(\d+)\s*ms/i);
  const verify = num(/verify\s*=\s*(\d+)\s*ms/i);
  const bundle = num(/bundle\s*=\s*(\d+)\s*KB/i);
  const build = num(/circuits ready in\s*(\d+)\s*ms/i);
  const sig = out.match(/sig\s*\(Fp256\)\s*:\s*ninputs=(\d+)\s*circuit=(\d+)\s*KB\s*proof=(\d+)\s*KB/i);
  const hash = out.match(/hash\s*\(GF2\^128\)\s*:\s*ninputs=(\d+)\s*circuit=(\d+)\s*KB\s*proof=(\d+)\s*KB/i);
  const accepts = (out.match(/ACCEPT/g) || []).length;
  const rejects = (out.match(/REJECT/g) || []).length;
  const accept = accepts > 0 && rejects === 0;
  return {
    prove_ms: prove, verify_ms: verify, bundle_kb: bundle, build_ms: build,
    sig_ninputs: sig ? +sig[1] : null, sig_circ_kb: sig ? +sig[2] : null, sig_proof_kb: sig ? +sig[3] : null,
    hash_ninputs: hash ? +hash[1] : null, hash_circ_kb: hash ? +hash[2] : null, hash_proof_kb: hash ? +hash[3] : null,
    accept,
  };
}

const stat = (xs) => {
  const a = xs.filter((x) => x != null).sort((p, q) => p - q);
  if (!a.length) return null;
  const n = a.length, mean = a.reduce((s, x) => s + x, 0) / n;
  const median = n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2;
  const sd = Math.sqrt(a.reduce((s, x) => s + (x - mean) ** 2, 0) / n);
  return { median, mean: +mean.toFixed(1), min: a[0], max: a[n - 1], sd: +sd.toFixed(1), n };
};

// Regenerate each distinct fixture generator ONCE per invocation so the holder
// secret/blind always match the freshly-built commitment (blind rows REJECT on
// a stale fixture). NOGEN skips regeneration and just checks files exist.
const genDone = new Set();
function ensureFixtures(row) {
  const missing = () => row.need.filter((f) => !fs.existsSync(FX(f)));
  if (NOGEN) {
    const m = missing();
    if (m.length) { console.error(`  ! ${row.key}: NOGEN but missing ${m.join(', ')}`); return false; }
    return true;
  }
  if (genDone.has(row.gen)) return true;
  if (!fs.existsSync(path.join(ROOT, 'node_modules'))) {
    const m = missing();
    if (m.length) { console.error(`  ! ${row.key}: missing ${m.join(', ')} and no node_modules to gen`); return false; }
    return true;
  }
  try { run('node', [GEN(row.gen)]); genDone.add(row.gen); return true; }
  catch (e) { console.error(`  ! gen failed for ${row.key}: ${(e.stdout || e.message || '').toString().slice(0, 200)}`); return false; }
}

function measure(row) {
  if (!ensureFixtures(row)) return { ...row, error: 'fixtures' };
  let last = '';
  const exec = () => { try { last = run(row.bin, row.args, row.env || {}); } catch (e) { last = (e.stdout || '').toString() + (e.stderr || '').toString(); } return parse(last); };
  for (let i = 0; i < WARMUP; i++) exec();              // warm circuit/page cache
  const samples = [];
  for (let i = 0; i < REPS; i++) samples.push(exec());
  fs.writeFileSync(FX(`eval-raw-${row.key}.txt`), last);  // keep last raw output
  const ok = samples.every((s) => s.accept);
  const last0 = samples[samples.length - 1];
  return {
    key: row.key, format: row.format, feature: row.feature, bin: path.basename(row.bin), accept: ok,
    prove: stat(samples.map((s) => s.prove_ms)),
    verify: stat(samples.map((s) => s.verify_ms)),
    bundle_kb: last0.bundle_kb ?? (((last0.sig_proof_kb ?? 0) + (last0.hash_proof_kb ?? 0)) || null),
    build_ms: last0.build_ms,
    sig: { ninputs: last0.sig_ninputs, circ_kb: last0.sig_circ_kb, proof_kb: last0.sig_proof_kb },
    hash: { ninputs: last0.hash_ninputs, circ_kb: last0.hash_circ_kb, proof_kb: last0.hash_proof_kb },
    samples,
  };
}

function main() {
  const rows = ROWS.filter((r) => !ONLY.length || ONLY.includes(r.key));
  console.log(`\n§7 eval harness — REPS=${REPS}, WARMUP=${WARMUP}, rows=${rows.length}\n`);
  const results = [];
  for (const row of rows) {
    process.stdout.write(`  running ${row.key.padEnd(12)} (${path.basename(row.bin)}) … `);
    const r = measure(row);
    if (r.error) { console.log(`SKIP (${r.error})`); continue; }
    console.log(`${r.accept ? 'ACCEPT' : 'REJECT/FAIL'}  prove=${r.prove?.median}ms verify=${r.verify?.median}ms bundle=${r.bundle_kb}KB`);
    results.push(r);
  }

  // markdown table (paper §7 Table 2)
  const md = [];
  md.push('| Format | Feature | Prove (ms) | Verify (ms) | Proof (KB) | Sig inputs | Hash inputs | OK |');
  md.push('|---|---|--:|--:|--:|--:|--:|:--:|');
  for (const r of results) {
    const pv = r.prove ? `${r.prove.median} <span title="min..max,sd">(${r.prove.min}–${r.prove.max}, σ${r.prove.sd})</span>` : 'n/a';
    const vv = r.verify ? `${r.verify.median} (${r.verify.min}–${r.verify.max}, σ${r.verify.sd})` : 'n/a';
    md.push(`| ${r.format} | ${r.feature} | ${r.prove?.median ?? 'n/a'} | ${r.verify?.median ?? 'n/a'} | ${r.bundle_kb ?? 'n/a'} | ${r.sig.ninputs ?? 'n/a'} | ${r.hash.ninputs ?? 'n/a'} | ${r.accept ? '✅' : '❌'} |`);
  }
  const table = md.join('\n');
  console.log('\n' + table + '\n');
  console.log(`(median of ${REPS} runs; prove/verify exclude circuit build; build≈${results.map(r=>r.build_ms).filter(Boolean).join('/')} ms cold)\n`);

  // CSV
  const csv = ['key,format,feature,bin,accept,prove_median_ms,prove_min_ms,prove_max_ms,prove_sd,verify_median_ms,verify_min_ms,verify_max_ms,verify_sd,bundle_kb,sig_ninputs,sig_circ_kb,sig_proof_kb,hash_ninputs,hash_circ_kb,hash_proof_kb,build_ms,reps'];
  for (const r of results) csv.push([r.key, `"${r.format}"`, `"${r.feature}"`, r.bin, r.accept,
    r.prove?.median, r.prove?.min, r.prove?.max, r.prove?.sd, r.verify?.median, r.verify?.min, r.verify?.max, r.verify?.sd,
    r.bundle_kb, r.sig.ninputs, r.sig.circ_kb, r.sig.proof_kb, r.hash.ninputs, r.hash.circ_kb, r.hash.proof_kb, r.build_ms, REPS].join(','));

  fs.writeFileSync(FX('eval-results.json'), JSON.stringify({ reps: REPS, warmup: WARMUP, generatedAt: NOW, results }, null, 2));
  fs.writeFileSync(FX('eval-results.csv'), csv.join('\n'));
  fs.writeFileSync(FX('eval-table.md'), table + '\n');
  console.log(`wrote fixtures/eval-results.json, eval-results.csv, eval-table.md`);
}

main();
