// Decode an ISO 18013-5 mdoc (DeviceResponse) and show what the ISSUER
// actually signed into it — i.e. exactly which (attribute = value) facts are
// available to selectively disclose in ZK.
//
// Dependency-free: includes a tiny CBOR decoder (definite-length only, which
// is what mdoc uses).
//
// Usage:
//   node src/decode-mdoc.js [path-to-mdoc.bin]
//   (default: artifacts/mdoc.bin)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ----------------------------- tiny CBOR decoder ---------------------------
const BYTES = Symbol('bytes');
const TAG = Symbol('tag');

class Cbor {
  constructor(buf) {
    this.b = buf;
    this.p = 0;
  }
  u8() {
    return this.b[this.p++];
  }
  take(n) {
    const s = this.b.subarray(this.p, this.p + n);
    this.p += n;
    return s;
  }
  arg(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return this.u8();
    if (ai === 25) {
      const v = this.b.readUInt16BE(this.p);
      this.p += 2;
      return v;
    }
    if (ai === 26) {
      const v = this.b.readUInt32BE(this.p);
      this.p += 4;
      return v;
    }
    if (ai === 27) {
      const v = Number(this.b.readBigUInt64BE(this.p));
      this.p += 8;
      return v;
    }
    throw new Error(`unsupported additional-info ${ai} (indefinite length?)`);
  }
  decode() {
    const ib = this.u8();
    const mt = ib >> 5;
    const ai = ib & 0x1f;
    switch (mt) {
      case 0:
        return this.arg(ai); // unsigned int
      case 1:
        return -1 - this.arg(ai); // negative int
      case 2:
        return { [BYTES]: Buffer.from(this.take(this.arg(ai))) };
      case 3:
        return Buffer.from(this.take(this.arg(ai))).toString('utf8');
      case 4: {
        const n = this.arg(ai);
        const a = [];
        for (let i = 0; i < n; i++) a.push(this.decode());
        return a;
      }
      case 5: {
        const n = this.arg(ai);
        const m = new Map();
        for (let i = 0; i < n; i++) {
          const k = this.decode();
          m.set(typeof k === 'string' || typeof k === 'number' ? k : JSON.stringify(k), this.decode());
        }
        return m;
      }
      case 6: {
        const tag = this.arg(ai);
        return { [TAG]: tag, value: this.decode() };
      }
      case 7:
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        if (ai === 26) {
          const v = this.b.readFloatBE(this.p);
          this.p += 4;
          return v;
        }
        if (ai === 27) {
          const v = this.b.readDoubleBE(this.p);
          this.p += 8;
          return v;
        }
        return `(simple ${ai})`;
      default:
        throw new Error(`bad major type ${mt}`);
    }
  }
}

const isBytes = (v) => v && typeof v === 'object' && BYTES in v;
const isTag = (v) => v && typeof v === 'object' && TAG in v;
const hex = (buf, max = 16) => {
  const h = Buffer.from(buf).toString('hex');
  return h.length > max * 2 ? h.slice(0, max * 2) + '…' : h;
};

// Render an mdoc elementValue for humans.
function showValue(v) {
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'boolean') return String(v) + (v ? '  ✅' : '');
  if (typeof v === 'number') return String(v);
  if (v === null) return 'null';
  if (isBytes(v)) return `bytes(${v[BYTES].length})=${hex(v[BYTES])}`;
  if (isTag(v)) {
    const t = v[TAG];
    const label =
      t === 0 ? 'tdate' : t === 1004 ? 'full-date' : t === 1 ? 'epoch' : `tag${t}`;
    return `${label}(${showValue(v.value)})`;
  }
  if (Array.isArray(v)) return `[${v.map(showValue).join(', ')}]`;
  if (v instanceof Map) return `{${[...v.keys()].join(', ')}}`;
  return String(v);
}

// Decode CBOR wrapped as a byte-string and/or tag(24, bytes), possibly nested
// (e.g. a COSE payload bstr that itself holds tag24(bstr(MSO))).
function decodeEmbedded(v) {
  let cur = v;
  for (let i = 0; i < 4; i++) {
    if (isBytes(cur)) cur = new Cbor(cur[BYTES]).decode();
    else if (isTag(cur) && cur[TAG] === 24 && isBytes(cur.value))
      cur = new Cbor(cur.value[BYTES]).decode();
    else break;
  }
  return cur;
}

// ----------------------------- mdoc walker ---------------------------------
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

    // ---- the disclosable facts: issuer-signed attributes ----
    console.log('\n  ▶ ISSUER-SIGNED ATTRIBUTES  (← 이게 ZK로 공개 가능한 후보)');
    if (nameSpaces instanceof Map) {
      for (const [ns, items] of nameSpaces) {
        console.log(`\n    namespace: ${ns}   (${items.length} attributes)`);
        for (const it of items) {
          const item = decodeEmbedded(it); // IssuerSignedItem
          const id = item.get('elementIdentifier');
          const val = item.get('elementValue');
          const did = item.get('digestID');
          console.log(
            `      • ${String(id).padEnd(22)} = ${showValue(val).padEnd(28)} (digestID ${did})`,
          );
        }
      }
    }

    // ---- the issuer signature envelope + MSO ----
    const issuerAuth = issuerSigned?.get('issuerAuth'); // COSE_Sign1 array
    if (Array.isArray(issuerAuth)) {
      const mso = decodeEmbedded(issuerAuth[2]); // payload
      console.log('\n  ▶ MSO (Mobile Security Object — 발급자가 ECDSA로 서명한 본문)');
      if (mso instanceof Map) {
        console.log(`      digestAlgorithm : ${mso.get('digestAlgorithm')}`);
        const vd = mso.get('valueDigests');
        if (vd instanceof Map) {
          for (const [ns, digs] of vd)
            console.log(`      valueDigests    : ${digs.size} hashes in "${ns}"`);
        }
        const vi = mso.get('validityInfo');
        if (vi instanceof Map) {
          console.log(`      validityInfo    : signed=${showValue(vi.get('signed'))}`);
          console.log(`                        validFrom=${showValue(vi.get('validFrom'))}`);
          console.log(`                        validUntil=${showValue(vi.get('validUntil'))}`);
        }
        const dki = mso.get('deviceKeyInfo');
        if (dki instanceof Map) {
          const dk = dki.get('deviceKey');
          console.log(`      deviceKey       : present (${dk instanceof Map ? 'COSE_Key' : '?'})`);
        }
      }
      const sig = issuerAuth[3];
      if (isBytes(sig))
        console.log(`      issuer signature: ECDSA ${sig[BYTES].length} bytes  (← ZK에서 숨겨짐)`);
    }

    // ---- device-signed (session binding) ----
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
