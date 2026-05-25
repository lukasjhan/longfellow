// Issue + PRESENT a real ISO 18013-5 mdoc using @lukas.j.han/mdoc (no OID4VP
// presentation-definition needed), including a per-person `pseudonym_secret`.
// Produces a DeviceResponse with ALL issuer attributes in issuerSigned, an
// ES256 deviceSignature over a chosen SessionTranscript, and EMPTY device
// namespaces — the shape longfellow's mdoc prover consumes.
//
// Output (playground/fixtures/):
//   mdoc.bin            DeviceResponse bytes
//   mdoc-transcript.bin SessionTranscript bytes (→ longfellow --transcript)
//   mdoc-issuer.json    issuer pubkey (hex), doctype, device jwk, secret
//
// Run:  node tools/gen-mdoc.mjs

import {
  Issuer, DeviceSignedBuilder, CoseKey, SignatureAlgorithm,
  Document, DeviceResponse,
} from '@lukas.j.han/mdoc';
import { generateKeyPair, exportJWK } from 'jose';
import { webcrypto as wc, randomBytes } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../fixtures');
const DOCTYPE = 'org.iso.18013.5.1.mDL', NS = 'org.iso.18013.5.1';

// TEST issuer key + cert (from research-eudi-module mdoc.test-utils.ts)
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

// Minimal MdocContext: only crypto.random/digest + cose.sign1.sign are exercised
// by issue + signature-present.
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
  const secret = randomBytes(32).toString('hex');
  // per-credential revocation handle (hidden element; its valueDigests entry =
  // 256-bit rev_id used by the signed-span revocation circuit). 64 hex chars.
  const revid = randomBytes(32).toString('hex');
  const der = new Uint8Array(new X509Certificate(PEM).rawData);
  const certB64 = Buffer.from(der).toString('base64');

  // fresh holder/device keypair (private needed to present)
  const dev = await generateKeyPair('ES256', { extractable: true });
  const devPub = await exportJWK(dev.publicKey);
  const devPriv = await exportJWK(dev.privateKey);

  // ---- ISSUE ----
  const issuer = new Issuer(DOCTYPE, ctx);
  issuer.addIssuerNamespace(NS, {
    family_name: 'Mustermann', given_name: 'Erika', age_over_18: true, height: 175,
    pseudonym_secret: secret, revocation_id: revid,
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

  // ---- ASSEMBLE DeviceResponse ----
  const dr = new DeviceResponse({
    documents: [new Document({ docType: DOCTYPE, issuerSigned, deviceSigned })],
    status: 0,
  });
  const bytes = dr.encode();

  fs.writeFileSync(path.join(OUT, 'mdoc.bin'), Buffer.from(bytes));
  fs.writeFileSync(path.join(OUT, 'mdoc-transcript.bin'), Buffer.from(transcript));
  fs.writeFileSync(path.join(OUT, 'mdoc-issuer.json'), JSON.stringify({
    doctype: DOCTYPE, namespace: NS,
    pkx_hex: b64uToHex(priKey.x), pky_hex: b64uToHex(priKey.y),
    device_jwk: devPriv, pseudonym_secret: secret, revocation_id: revid,
  }, null, 2));

  console.log('mdoc issued+presented →', path.join(OUT, 'mdoc.bin'), `(${bytes.length} bytes)`);
  console.log('  transcript:', Buffer.from(transcript).toString('hex'), '→ mdoc-transcript.bin');
  console.log('  pkx:', b64uToHex(priKey.x));
  console.log('  pseudonym_secret:', secret);
}

main().catch((e) => { console.error(e); process.exit(1); });
