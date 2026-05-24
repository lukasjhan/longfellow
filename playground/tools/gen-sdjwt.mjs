// Generate a REAL SD-JWT-VC (with selective-disclosure salted digests `_sd`)
// signed with ES256, plus a holder key for Key Binding. Dumps a fixture the
// future SD-JWT ZK circuit can target.
//
// Run with research-eudi-module's deps available, e.g.:
//   NODE_PATH=/home/unknown/research-eudi-module/node_modules \
//     node playground/tools/gen-sdjwt.mjs
//
// Output (playground/fixtures/):
//   sdjwt.txt        compact SD-JWT:  <issuer-jwt>~<disc1>~<disc2>~...~
//   issuer-jwk.json  issuer public key (jwk + hex x/y for the circuit)
//   holder-jwk.json  holder key (for Key Binding later)
//   parsed.json      decoded payload + disclosures + _sd (for inspection)

import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../fixtures');
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const jwkHex = (b64u) => '0x' + Buffer.from(b64u, 'base64url').toString('hex');

// One SD-JWT Disclosure for an object property:
//   disclosure = base64url(utf8( JSON([salt, claimName, claimValue]) ))
//   digest     = base64url( SHA-256( ascii(disclosure) ) )
function makeDisclosure(name, value) {
  const salt = b64url(randomBytes(16));
  const json = JSON.stringify([salt, name, value]);
  const disclosure = b64url(Buffer.from(json, 'utf8'));
  const digest = b64url(sha256(new TextEncoder().encode(disclosure)));
  return { name, value, salt, json, disclosure, digest };
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  // Issuer + holder ES256 (P-256) keys.
  const issuer = await generateKeyPair('ES256', { extractable: true });
  const holder = await generateKeyPair('ES256', { extractable: true });
  const issuerPub = await exportJWK(issuer.publicKey);
  const holderPub = await exportJWK(holder.publicKey);

  // Selectively-disclosable claims — note the MIXED TYPES (the whole point).
  // BIG=1 generates a fuller PID-sized credential (more `_sd` entries + a longer
  // presented bundle) to exercise the GENEROUS circuit capacities — this one
  // would NOT fit the old tight constants (kMaxSHA=13 / PB=18).
  const BIG = process.env.BIG === '1';
  const disclosures = [
    makeDisclosure('given_name', 'Erika'),       // string
    makeDisclosure('family_name', 'Mustermann'), // string
    makeDisclosure('birthdate', '1963-08-12'),   // date (string)
    makeDisclosure('age_over_18', true),         // boolean
    makeDisclosure('height', 175),               // number
    // per-person secret for pseudonymous nullifiers (CI/DI-like). Fixed 64 hex
    // chars (32 bytes). Issuer-committed (in _sd) so the holder can't choose it →
    // nullifier = SHA(secret ‖ context_id) is Sybil-sound. Stays hidden in ZK.
    makeDisclosure('pseudonym_secret', randomBytes(32).toString('hex')),
    ...(BIG ? [
      makeDisclosure('age_over_21', true),
      makeDisclosure('age_in_years', 61),
      makeDisclosure('nationality', 'DE'),
      makeDisclosure('place_of_birth', 'Berlin'),
      makeDisclosure('resident_city', 'Köln'),
      makeDisclosure('resident_postal_code', '51147'),
      makeDisclosure('resident_street', 'Heidestraße 17'),
      makeDisclosure('email', 'erika@example.de'),
    ] : []),
  ];
  const sfx = BIG ? '-big' : '';

  // Digests go in `_sd` (sorted, per spec). Other claims stay in the clear.
  const sd = disclosures.map((d) => d.digest).sort();
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'https://issuer.example/eudi',
    vct: 'https://credentials.example/pid',
    iat: now,
    exp: now + 3600 * 24 * 30, // valid 30 days
    cnf: { jwk: holderPub },   // holder key -> enables Key Binding
    _sd_alg: 'sha-256',
    _sd: sd,
  };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
    .sign(issuer.privateKey);

  // Presented SD-JWT (issuer JWT + disclosures + trailing '~').
  const sdPart = jwt + '~' + disclosures.map((d) => d.disclosure).join('~') + '~';

  // Key Binding JWT: holder signs over a hash of the presented SD-JWT.
  const sd_hash = b64url(sha256(new TextEncoder().encode(sdPart)));
  // nonce/aud are verifier-supplied in a real flow; allow override so a demo can
  // issue a KB-JWT bound to a freshly chosen nonce (KB freshness / audience).
  const kbjwt = await new SignJWT({
    nonce: process.env.KB_NONCE || '1234567890',
    aud: process.env.KB_AUD || 'https://verifier.example',
    iat: now,
    sd_hash,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(holder.privateKey);

  // Full compact SD-JWT with Key Binding.
  const compact = sdPart + kbjwt;

  fs.writeFileSync(path.join(OUT, `sdjwt${sfx}.txt`), compact);
  fs.writeFileSync(
    path.join(OUT, `issuer-jwk${sfx}.json`),
    JSON.stringify({ jwk: issuerPub, x_hex: jwkHex(issuerPub.x), y_hex: jwkHex(issuerPub.y) }, null, 2),
  );
  fs.writeFileSync(
    path.join(OUT, `holder-jwk${sfx}.json`),
    JSON.stringify({ jwk: holderPub, x_hex: jwkHex(holderPub.x), y_hex: jwkHex(holderPub.y) }, null, 2),
  );
  fs.writeFileSync(
    path.join(OUT, `parsed${sfx}.json`),
    JSON.stringify({ payload, disclosures }, null, 2),
  );

  console.log('SD-JWT-VC generated → playground/fixtures/');
  console.log('  compact length:', compact.length, 'chars');
  console.log('  disclosures   :', disclosures.length, '(string/date/boolean/number)');
  console.log('  _sd digests   :', sd.length);
  console.log('\nExample disclosure (age_over_18, boolean):');
  const b = disclosures.find((d) => d.name === 'age_over_18');
  console.log('  JSON      :', b.json);
  console.log('  disclosure:', b.disclosure);
  console.log('  digest    :', b.digest, '  (∈ _sd:', sd.includes(b.digest) + ')');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
