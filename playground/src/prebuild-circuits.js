// Pre-generate and cache the ZK circuits for each supported attribute count,
// so present/verify never pay the one-time generation cost at runtime.
//
//   pnpm run circuits            # build N = 1,2,3,4
//   node src/prebuild-circuits.js 1 2   # build only N = 1,2

import { buildAll, SUPPORTED_N, CIRCUITS_DIR } from './circuits.js';

const ns = process.argv.slice(2).map(Number).filter((n) => Number.isInteger(n));
const targets = ns.length ? ns : SUPPORTED_N;

console.log(`Building circuits for N = ${targets.join(', ')}`);
console.log(`into ${CIRCUITS_DIR}\n`);

const res = buildAll(targets);

console.log(' N | circuit_hash (16)  |   size(B) | gen(ms)');
console.log('---+--------------------+-----------+--------');
for (const r of res)
  console.log(
    ` ${r.n} | ${r.spec.circuit_hash.slice(0, 16)}… | ${String(r.spec.circuit_len).padStart(9)} | ${r.gen_ms}`,
  );
console.log('\n✅ cached (circuits/*.bin + manifest.json)');
