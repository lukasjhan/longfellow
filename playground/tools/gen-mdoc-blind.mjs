// Issue + PRESENT a real ISO 18013-5 mdoc for the BLIND pseudonym nullifier.
//
// Unlike gen-mdoc.mjs (which embeds the raw `pseudonym_secret`, so the issuer
// KNOWS the secret), here the HOLDER generates secret+blind, commits
//   C = SHA256( secret(32B) ‖ blind(32B) )
// and the ISSUER signs ONLY `pseudonym_commitment` = C (a 32-byte CBOR byte
// string, `58 20 <32B>`). The issuer never sees secret/blind, so it cannot
// compute any nullifier.
//
// Output (playground/fixtures/):
//   mdoc-blind.bin            DeviceResponse bytes (commitment in issuerSigned)
//   mdoc-blind-transcript.bin SessionTranscript bytes
//   mdoc-blind-issuer.json    issuer pubkey (hex), doctype, device jwk, commitment hex
//   mdoc-holder-secret.txt    secret_hex ‖ blind_hex  (holder-only, never sent to issuer)
//
// Run:  node tools/gen-mdoc-blind.mjs

import {
  Issuer, DeviceSignedBuilder, CoseKey, SignatureAlgorithm,
  Document, DeviceResponse,
} from '@lukas.j.han/mdoc';
import { generateKeyPair, exportJWK } from 'jose';
import { sha256 } from '@noble/hashes/sha2';
import { webcrypto as wc, randomBytes } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../fixtures');
const DOCTYPE = 'org.iso.18013.5.1.mDL', NS = 'org.iso.18013.5.1';

const priKey = {
  kty: 'EC', crv: 'P-256',
  x: 'OaZeIP61nC2LoRY_IaIzh7WsRwdmZaakNrjCVk3GykE',
  y: '6zq24x5tW9iN3HWcweu5lqqb2-AalvxiqCmY9SMEz9I',
  d: 'cCwwCZkqvQlYFkNfpifIfoYjpaYcGIIDvacQ2EbgREo',
};
const PEM = `-----BEGIN CERTIFICATE-----
MIICIjCCAcigAwIBAgIUC9zq5aG/XJSWB+Fni4LObaqv8+AwCgYIKoZIzj0EAwIw
ajELMAkGA1UEBhMCS1IxDjAMBgNVBAgMBVNlb3VsMQ4wDAYDVQQHDAVTZW91bDES
MBAGA1UECgwJSG9wYWUgRGV2MScwJQYDVQQDDB5tZGwtdmVyaWZpZXItYXBpLmRl
di5ob3BhZS5hcHAwHhcNMjUxMjEwMDIwNTAwWhcNMjYxMjEwMDIwNTAwWjBqMQsw
CQYDVQQGEwJLUjEOMAwGA1UECAwFU2VvdWwxDjAMBgNVBAcMBVNlb3VsMRIwEAYD
VQQKDAlIb3BhZSBEZXYxJzAlBgNVBAMMHm1kbC12ZXJpZmllci1hcGkuZGV2Lmhv
cGFlLmFwcDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDmmXiD+tZwti6EWPyGi
M4e1rEcHZmWmpDa4wlZNxspB6zq24x5tW9iN3HWcweu5lqqb2+AalvxiqCmY9SME
z9KjTDBKMCkGA1UdEQQiMCCCHm1kbC12ZXJpZmllci1hcGkuZGV2LmhvcGFlLmFw
cDAdBgNVHQ4EFgQU6LT3JygLQcoJ2U4LZ9TZHSM+K1YwCgYIKoZIzj0EAwIDSAAw
RQIgceK0+hvfc5V3LJ/2um5RP2KphITytabEOlH4xHwIl1wCIQCpXZGUDxJoJvIU
Dlkk70sESvvyJO0KjHtOy2IvOtb90g==
-----END CERTIFICATE-----`;

const EC = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGO = { name: 'ECDSA', hash: 'SHA-256' };
const ctx = {
  crypto: {
    random: (n) => wc.getRandomValues(new Uint8Array(n)),
    digest: async ({ digestAlgorithm, bytes }) =>
      new Uint8Array(await wc.subtle.digest(digestAlgorithm, bytes)),
  },
  cose: {
    sign1: {
      sign: async ({ sign1, key }) => {
        const ck = await wc.subtle.importKey('jwk', key.jwk, EC, false, ['sign']);
        return new Uint8Array(await wc.subtle.sign(SIGN_ALGO, ck, sign1.toBeSigned));
      },
    },
  },
};

const b64uToHex = (b64u) => '0x' + Buffer.from(b64u, 'base64url').toString('hex');

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  // ===== HOLDER side: pick secret + blind, build the hiding commitment =====
  const secret = randomBytes(32);
  const blind = randomBytes(32);
  const commitment = Buffer.from(sha256(Buffer.concat([secret, blind]))); // 32 bytes
  // → CBOR-encoded as a byte string `58 20 <32B>` by @lukas.j.han/mdoc

  const der = new Uint8Array(new X509Certificate(PEM).rawData);
  const certB64 = Buffer.from(der).toString('base64');
  const dev = await generateKeyPair('ES256', { extractable: true });
  const devPub = await exportJWK(dev.publicKey);
  const devPriv = await exportJWK(dev.privateKey);

  // ---- ISSUE (issuer signs the COMMITMENT only; never sees secret/blind) ----
  const issuer = new Issuer(DOCTYPE, ctx);
  issuer.addIssuerNamespace(NS, {
    family_name: 'Mustermann', given_name: 'Erika', age_over_18: true, height: 175,
    resident_city: '김포시',            // address attribute (for the voting scenario)
    pseudonym_commitment: commitment,   // Buffer → CBOR byte string
  });
  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(priKey),
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    validityInfo: { signed: new Date(), validFrom: new Date(), validUntil: new Date('2035-12-31T23:59:59.999Z') },
    deviceKeyInfo: { deviceKey: CoseKey.fromJwk({ kty: 'EC', crv: 'P-256', x: devPub.x, y: devPub.y }) },
    certificate: der,
  });

  // ---- PRESENT (empty deviceNS, ES256, chosen transcript) ----
  const transcript = new Uint8Array([0x83, 0xf6, 0xf6, 0xf6]); // CBOR [null,null,null]
  const deviceSigned = await new DeviceSignedBuilder(DOCTYPE, ctx).sign({
    signingKey: CoseKey.fromJwk(devPriv),
    algorithm: SignatureAlgorithm.ES256,
    sessionTranscript: transcript,
    derCertificate: certB64,
  });

  const dr = new DeviceResponse({
    documents: [new Document({ docType: DOCTYPE, issuerSigned, deviceSigned })],
    status: 0,
  });
  const bytes = dr.encode();

  fs.writeFileSync(path.join(OUT, 'mdoc-blind.bin'), Buffer.from(bytes));
  fs.writeFileSync(path.join(OUT, 'mdoc-blind-transcript.bin'), Buffer.from(transcript));
  fs.writeFileSync(path.join(OUT, 'mdoc-blind-issuer.json'), JSON.stringify({
    doctype: DOCTYPE, namespace: NS,
    pkx_hex: b64uToHex(priKey.x), pky_hex: b64uToHex(priKey.y),
    device_jwk: devPriv, commitment_hex: commitment.toString('hex'),
  }, null, 2));
  // holder-only secret material (the prover reads this; the issuer never had it)
  fs.writeFileSync(path.join(OUT, 'mdoc-holder-secret.txt'),
    secret.toString('hex') + blind.toString('hex'));

  console.log('BLIND mdoc issued+presented →', path.join(OUT, 'mdoc-blind.bin'), `(${bytes.length} bytes)`);
  console.log('  commitment (in MSO):', commitment.toString('hex'));
  console.log('  → issuer signed the COMMITMENT only; secret/blind stay with the holder');
  console.log('  pkx:', b64uToHex(priKey.x));
}

main().catch((e) => { console.error(e); process.exit(1); });
