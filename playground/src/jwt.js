// Node wrapper around the jwt_cli binary (longfellow's experimental
// SD-JWT(+KB) ZK circuit). Same subprocess-pattern as longfellow.js.
//
// NOTE: this circuit proves a STRING attribute appears in the token payload as
// the substring  "id":"value"  — boolean/number claims are not provable here.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const JWT_CLI = path.resolve(__dirname, '../native/jwt_cli');
export const JWT_ARTIFACTS = path.resolve(__dirname, '../artifacts-jwt');

function runCli(args) {
  if (!fs.existsSync(JWT_CLI))
    throw new Error(`jwt_cli not found at ${JWT_CLI}\nBuild it: pnpm run build:native`);
  const debug = process.env.DEBUG === '1' || process.env.DEBUG === 'true';
  let stdout;
  try {
    stdout = execFileSync(JWT_CLI, args, {
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      stdio: ['ignore', 'pipe', debug ? 'inherit' : 'pipe'],
    });
  } catch (err) {
    stdout = err.stdout ? err.stdout.toString() : '';
    if (debug && err.stderr) process.stderr.write(err.stderr);
    if (!stdout) throw err;
  }
  const lines = stdout.trim().split('\n').filter(Boolean);
  try {
    return JSON.parse(lines[lines.length - 1]);
  } catch {
    throw new Error(`could not parse jwt_cli output:\n${stdout}`);
  }
}

/** Dump a bundled example SD-JWT(+KB) token + issuer key to `outdir`. */
export function issueExampleJwt({ index = 0, outdir = JWT_ARTIFACTS } = {}) {
  fs.mkdirSync(outdir, { recursive: true });
  return runCli(['export-example', '--index', String(index), '--outdir', outdir]);
}

/** Prove the (private) token contains "attrId":"attrValue". */
export function jwtProve({ jwt, pkx, pky, e2, attrId, attrValue, shaBlocks, out }) {
  return runCli([
    'prove',
    '--jwt', jwt,
    '--pkx', pkx,
    '--pky', pky,
    '--e2', e2,
    '--attr-id', attrId,
    '--attr-value', attrValue,
    '--sha-blocks', String(shaBlocks),
    '--out', out,
  ]);
}

/** Verify a proof. The token is NOT supplied here. */
export function jwtVerify({ pkx, pky, e2, attrId, attrValue, shaBlocks, proof }) {
  return runCli([
    'verify',
    '--pkx', pkx,
    '--pky', pky,
    '--e2', e2,
    '--attr-id', attrId,
    '--attr-value', attrValue,
    '--sha-blocks', String(shaBlocks),
    '--proof', proof,
  ]);
}
