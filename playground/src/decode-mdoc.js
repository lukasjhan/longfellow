// Decode an ISO 18013-5 mdoc (DeviceResponse) and show what the ISSUER
// actually signed into it — i.e. exactly which (attribute = value) facts are
// available to selectively disclose in ZK.
//
// Usage:
//   node src/decode-mdoc.js [path-to-mdoc.bin]   (default: artifacts/mdoc.bin)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Cbor, BYTES, isBytes, showValue, decodeEmbedded } from './cbor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function main() {
  const file = process.argv[2] || path.resolve(__dirname, '../artifacts/mdoc.bin');
  if (!fs.existsSync(file)) {
    console.error(`mdoc not found: ${file}\n(run "pnpm run issue" first)`);
    process.exit(1);
  }
  const root = new Cbor(fs.readFileSync(file)).decode();

  const docs = root.get?.('documents');
  if (!Array.isArray(docs)) {
    console.error('not a DeviceResponse (no "documents")');
    process.exit(1);
  }
  console.log(`\nmDoc file: ${path.relative(process.cwd(), file)}`);
  console.log(`version  : ${root.get('version')}`);
  console.log(`documents: ${docs.length}`);

  docs.forEach((doc, di) => {
    const docType = doc.get('docType');
    const issuerSigned = doc.get('issuerSigned');
    const nameSpaces = issuerSigned?.get('nameSpaces');

    console.log('\n' + '═'.repeat(70));
    console.log(`  document[${di}]  docType = ${docType}`);
    console.log('═'.repeat(70));

    console.log('\n  ▶ ISSUER-SIGNED ATTRIBUTES  (← 이게 ZK로 공개 가능한 후보)');
    if (nameSpaces instanceof Map) {
      for (const [ns, items] of nameSpaces) {
        console.log(`\n    namespace: ${ns}   (${items.length} attributes)`);
        for (const it of items) {
          const item = decodeEmbedded(it);
          const id = item.get('elementIdentifier');
          const val = item.get('elementValue');
          const did = item.get('digestID');
          console.log(
            `      • ${String(id).padEnd(22)} = ${showValue(val).padEnd(28)} (digestID ${did})`,
          );
        }
      }
    }

    const issuerAuth = issuerSigned?.get('issuerAuth');
    if (Array.isArray(issuerAuth)) {
      const mso = decodeEmbedded(issuerAuth[2]);
      console.log('\n  ▶ MSO (Mobile Security Object — 발급자가 ECDSA로 서명한 본문)');
      if (mso instanceof Map) {
        console.log(`      digestAlgorithm : ${mso.get('digestAlgorithm')}`);
        const vd = mso.get('valueDigests');
        if (vd instanceof Map)
          for (const [ns, digs] of vd)
            console.log(`      valueDigests    : ${digs.size} hashes in "${ns}"`);
        const vi = mso.get('validityInfo');
        if (vi instanceof Map) {
          console.log(`      validityInfo    : signed=${showValue(vi.get('signed'))}`);
          console.log(`                        validFrom=${showValue(vi.get('validFrom'))}`);
          console.log(`                        validUntil=${showValue(vi.get('validUntil'))}`);
        }
        const dki = mso.get('deviceKeyInfo');
        if (dki instanceof Map)
          console.log(`      deviceKey       : present (${dki.get('deviceKey') instanceof Map ? 'COSE_Key' : '?'})`);
      }
      const sig = issuerAuth[3];
      if (isBytes(sig))
        console.log(`      issuer signature: ECDSA ${sig[BYTES].length} bytes  (← ZK에서 숨겨짐)`);
    }

    const deviceSigned = doc.get('deviceSigned');
    if (deviceSigned instanceof Map) {
      console.log('\n  ▶ DEVICE-SIGNED (세션 바인딩용 — present 시 디바이스 키로 서명)');
      console.log('      deviceAuth present:', deviceSigned.has('deviceAuth'));
    }
  });

  console.log('\n' + '─'.repeat(70));
  console.log('  요약: 위 "ISSUER-SIGNED ATTRIBUTES"의 각 (id = 값)이 곧');
  console.log('        longfellow로 "정확히 이 값"을 영지식 공개할 수 있는 항목입니다.');
  console.log('        MSO 서명·다른 속성·deviceKey 등은 proof에서 숨겨집니다.');
  console.log('─'.repeat(70) + '\n');
}

main();
