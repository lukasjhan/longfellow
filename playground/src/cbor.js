// Minimal dependency-free CBOR decoder + mdoc attribute extractor.
// Definite-length only (which is what mdoc uses).

export const BYTES = Symbol('bytes');
export const TAG = Symbol('tag');

export class Cbor {
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
        return this.arg(ai);
      case 1:
        return -1 - this.arg(ai);
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

export const isBytes = (v) => v && typeof v === 'object' && BYTES in v;
export const isTag = (v) => v && typeof v === 'object' && TAG in v;

export const hex = (buf, max = 16) => {
  const h = Buffer.from(buf).toString('hex');
  return h.length > max * 2 ? h.slice(0, max * 2) + '…' : h;
};

export function showValue(v) {
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

// Unwrap CBOR wrapped as byte-string and/or tag(24, bytes), possibly nested.
export function decodeEmbedded(v) {
  let cur = v;
  for (let i = 0; i < 4; i++) {
    if (isBytes(cur)) cur = new Cbor(cur[BYTES]).decode();
    else if (isTag(cur) && cur[TAG] === 24 && isBytes(cur.value))
      cur = new Cbor(cur.value[BYTES]).decode();
    else break;
  }
  return cur;
}

// Get the raw bytes of an embedded item (the bstr content), so we can extract
// the EXACT encoded bytes of fields like elementValue.
function embeddedBytes(v) {
  if (isBytes(v)) return v[BYTES];
  if (isTag(v) && v[TAG] === 24 && isBytes(v.value)) return v.value[BYTES];
  return null;
}

// Parse one IssuerSignedItem, capturing the *raw* CBOR bytes of elementValue
// (so it can be fed verbatim to the longfellow prover/verifier).
function parseItemRaw(buf) {
  const c = new Cbor(buf);
  const ib = c.u8();
  if (ib >> 5 !== 5) throw new Error('IssuerSignedItem is not a map');
  const n = c.arg(ib & 0x1f);
  const out = {};
  for (let i = 0; i < n; i++) {
    const k = c.decode();
    const start = c.p;
    const v = c.decode();
    const end = c.p;
    if (k === 'elementIdentifier') out.id = v;
    else if (k === 'digestID') out.digestID = v;
    else if (k === 'elementValue') {
      out.value = v;
      out.valueHex = Buffer.from(buf.subarray(start, end)).toString('hex');
    }
  }
  return out;
}

/**
 * Return all issuer-signed attributes from an mdoc buffer, with the EXACT
 * CBOR-encoded value bytes:
 *   [{ namespace, id, value, valueHex, digestID }]
 */
export function attributesOf(mdocBuf) {
  const root = new Cbor(mdocBuf).decode();
  const docs = root.get('documents');
  const out = [];
  for (const doc of docs) {
    const nameSpaces = doc.get('issuerSigned')?.get('nameSpaces');
    if (!(nameSpaces instanceof Map)) continue;
    for (const [namespace, items] of nameSpaces) {
      for (const it of items) {
        const itemBytes = embeddedBytes(it);
        if (!itemBytes) continue;
        out.push({ namespace, ...parseItemRaw(itemBytes) });
      }
    }
  }
  return out;
}
