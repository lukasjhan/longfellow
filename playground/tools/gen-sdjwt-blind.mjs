// Generate a REAL SD-JWT-VC for the BLIND pseudonym nullifier demo.
//
// Unlike gen-sdjwt.mjs (which embeds the raw `pseudonym_secret` value, so the
// issuer KNOWS the secret and can de-anonymize), here the HOLDER generates the
// secret and a blinding factor, computes a hiding commitment
//   C = SHA256( secret(32B) ‖ blind(32B) )
// and the ISSUER signs ONLY `pseudonym_commitment` = base64url(C). The issuer
// never sees `secret`/`blind`, so it cannot compute any nullifier.
//
// The holder's private material is written to fixtures/holder-secret.txt
// (= secret_hex ‖ blind_hex, 128 hex chars) for the prover (native binary).
//
// Output (playground/fixtures/):
//   sdjwt-blind.txt        compact SD-JWT (commitment in _sd, NOT the secret)
//   issuer-jwk-blind.json  issuer public key (+ hex x/y)
//   holder-jwk-blind.json  holder key (Key Binding)
//   holder-secret.txt      secret_hex ‖ blind_hex  (holder-only, never sent to issuer)
//   parsed-blind.json      decoded payload + disclosures (for inspection)

import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../fixtures');
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const jwkHex = (b64u) => '0x' + Buffer.from(b64u, 'base64url').toString('hex');

function makeDisclosure(name, value) {
  const salt = b64url(randomBytes(16));
  const json = JSON.stringify([salt, name, value]);
  const disclosure = b64url(Buffer.from(json, 'utf8'));
  const digest = b64url(sha256(new TextEncoder().encode(disclosure)));
  return { name, value, salt, json, disclosure, digest };
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  const issuer = await generateKeyPair('ES256', { extractable: true });
  const holder = await generateKeyPair('ES256', { extractable: true });
  const issuerPub = await exportJWK(issuer.publicKey);
  const holderPub = await exportJWK(holder.publicKey);

  // ===== HOLDER side: pick secret + blind, build the hiding commitment =====
  const secret = randomBytes(32);
  const blind = randomBytes(32);
  const commitment = sha256(Buffer.concat([secret, blind])); // 32 bytes
  const commitment_b64 = b64url(commitment);                 // 43 chars, the issuer-signed value

  // ===== ISSUER side: signs ONLY the commitment (never sees secret/blind) =====
  const disclosures = [
    makeDisclosure('given_name', 'Erika'),
    makeDisclosure('family_name', 'Mustermann'),
    makeDisclosure('birthdate', '1963-08-12'),
    makeDisclosure('age_over_18', true),
    makeDisclosure('height', 175),
    // BLIND: the commitment, NOT the secret. Issuer-committed (in _sd) so the
    // holder cannot swap it; but the issuer learns nothing about the secret.
    makeDisclosure('pseudonym_commitment', commitment_b64),
  ];

  const sd = disclosures.map((d) => d.digest).sort();
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'https://issuer.example/eudi',
    vct: 'https://credentials.example/pid',
    iat: now,
    exp: now + 3600 * 24 * 30,
    cnf: { jwk: holderPub },
    _sd_alg: 'sha-256',
    _sd: sd,
  };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
    .sign(issuer.privateKey);

  const sdPart = jwt + '~' + disclosures.map((d) => d.disclosure).join('~') + '~';
  const sd_hash = b64url(sha256(new TextEncoder().encode(sdPart)));
  const kbjwt = await new SignJWT({
    nonce: process.env.KB_NONCE || '1234567890',
    aud: process.env.KB_AUD || 'https://verifier.example',
    iat: now,
    sd_hash,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(holder.privateKey);

  const compact = sdPart + kbjwt;

  fs.writeFileSync(path.join(OUT, 'sdjwt-blind.txt'), compact);
  fs.writeFileSync(
    path.join(OUT, 'issuer-jwk-blind.json'),
    JSON.stringify({ jwk: issuerPub, x_hex: jwkHex(issuerPub.x), y_hex: jwkHex(issuerPub.y) }, null, 2),
  );
  fs.writeFileSync(
    path.join(OUT, 'holder-jwk-blind.json'),
    JSON.stringify({ jwk: holderPub, x_hex: jwkHex(holderPub.x), y_hex: jwkHex(holderPub.y) }, null, 2),
  );
  // holder-only secret material (the prover reads this; the issuer never had it)
  fs.writeFileSync(
    path.join(OUT, 'holder-secret.txt'),
    secret.toString('hex') + blind.toString('hex'),
  );
  fs.writeFileSync(
    path.join(OUT, 'parsed-blind.json'),
    JSON.stringify({ payload, disclosures, commitment_b64 }, null, 2),
  );

  console.log('BLIND SD-JWT-VC generated → playground/fixtures/');
  console.log('  compact length    :', compact.length, 'chars');
  console.log('  commitment (in _sd):', commitment_b64);
  console.log('  → issuer signed the COMMITMENT only; secret/blind stay with the holder');
  console.log('  holder-secret.txt :', 64, 'hex secret +', 64, 'hex blind (never sent to issuer)');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
