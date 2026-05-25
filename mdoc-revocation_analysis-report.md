# mdoc (ISO 18013-5) Privacy-Preserving Revocation — Analysis Report

> Target: `playground/` — a research extension that adds **privacy-preserving revocation** (signed-span non-membership) to a **real mdoc** ZK presentation, on top of longfellow's two-circuit mdoc prover.
> Location: `/home/unknown/longfellow/playground`
> Date: 2026-05-25 · Status: prototype, working + soundness-audited
> Base: this is an **extension** of the mdoc credential proof. The shared construction (signed-span method, the ZK-optimality argument, the soundness threat model, endianness) is documented once in the SD-JWT version, [`sd-jwt-revocation_analysis-report.md`](sd-jwt-revocation_analysis-report.md); the underlying longfellow mdoc circuits are in [`longfellow-zk_analysis-report.md`](longfellow-zk_analysis-report.md); the dedicated-block / CBOR-anchor machinery it reuses is in [`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md). This report covers only what is **mdoc-specific**.

---

## 1. Overview

Prove a **real mdoc** credential is **NOT revoked** in zero knowledge, revealing neither the revocation identifier nor which credential it is. Method = longfellow's own `MdocRevocationSpan` (`lib/circuits/tests/mdoc/mdoc_revocation.h`): a revocation authority (CRA) signs the open gaps `epoch ‖ l ‖ r` between adjacent revoked ids; the holder proves `l < rev_id < r`. Constant-size proof regardless of list size.

Prototype: `native/mdoc_revoc_split.cc` (2-circuit split); demo `pnpm run demo:mdoc-revocation`; issuer adds a `revocation_id` element via `tools/gen-mdoc.mjs`.

## 2. What is mdoc-specific

The whole construction is identical to the SD-JWT version except **how `rev_id` is obtained**, which is in fact *cleaner* on mdoc:

- **`rev_id` = the MSO `valueDigests` entry of a `revocation_id` IssuerSignedItem**, i.e. `SHA256(item)`. In mdoc *every* element's digest is in the signed MSO (whether or not it is disclosed), so the digest is a ready-made hidden, issuer-committed, per-credential 256-bit value. **No in-circuit hex decode is needed** — the digest *is* the 256-bit integer.
- The circuit **reuses the nullifier block's machinery verbatim**: (1) reconstruct the COSE1(MSO) preimage + index range-check, (2) prove `mm = SHA(sec_item)` sits at `sec_mso` in the signed MSO (membership) — `mm` (a `v256`) **is** `rev_id`, (3) a literal CBOR anchor `71 "elementIdentifier" 6D "revocation_id"` binds that `sec_item` is the `revocation_id` element (so `rev_id` is that specific claim's digest, not some other item's). The 64-byte value is **not** extracted (unlike the nullifier) — only the digest matters.
- The span block (`SHA(epoch‖l‖r)=e_span`, epoch pin, `l < rev_id < r`) and the MAC plumbing (extended to a 4th linked value `e_span`, with the CRA ECDSA in the Fp256 sig circuit) are copied unchanged from the SD-JWT version.

Endianness matches `mm`'s convention (`integer(mm) = BE(digest) = BN_bin2bn(digest)`), identical to MdocHash and to the SD-JWT `rev_ebits` — see [`sd-jwt-revocation_analysis-report.md`](sd-jwt-revocation_analysis-report.md) §6.1. `l, r` are stored little-endian in the span and extracted as `lbits[i] = span_pre[8+i/8][i%8]`, exactly as in `MdocRevocationSpan`.

## 3. Architecture & performance

- **sig circuit (Fp256)**: `MdocSignature::assert_signatures` (issuer + device ECDSA) **+ a CRA ECDSA over `e_span`** + the `e_span` MAC.
- **hash circuit (GF(2¹²⁸))**: `MdocHash::assert_valid_hash_mdoc` (unchanged) + the revocation block above.
- **MAC link 3 → 4 values**: `e, dpkx, dpky, e_span`; `a_p[8]`, `a_v` from the post-commit transcript; bundle = `[8 macs][hash proof][sig proof]`. Transcript seeded by the session transcript.

| metric | value (1 disclosed attr, real fixture) |
|---|---|
| prove | ~0.95 s |
| verify | ~0.48 s |
| bundle | ~361 KB |

Independent of the revocation-list size — the holder carries one span.

## 4. Properties (verified by `demo:mdoc-revocation`)

- **Not revoked** → ACCEPT. **Revoked** → REJECT (no signed gap brackets `rev_id`). **Forged status** (non-CRA span) → REJECT. **Stale span** (old epoch) → REJECT. **Tampered MAC** → REJECT in both circuits.

## 5. Soundness audit

Inherits the SD-JWT audit (S1–S5 + privacy) — see [`sd-jwt-revocation_analysis-report.md`](sd-jwt-revocation_analysis-report.md) §6 — verified here on a real mdoc:

| # | Property | Verdict | Negative test |
|---|---|---|---|
| S1 | revoked ⇒ reject | ✅ | `REVOKED=1` (`l = N`) → `l < rev_id` fails → **PROVE REJECTED** (proving impossible) |
| S2 | span CRA-signed | ✅ | `BADSIG=1` → ECDSA unsatisfiable → reject |
| S3 | freshness (epoch pin) | ✅ | `STALE=1` (epoch `e+1` signed, `e` pinned) → reject |
| S4 | cross-circuit binding | ✅ | `TAMPER=1` → both circuits reject |
| S5 | `rev_id` issuer-committed & correct element | ✅ | membership (`mm = SHA(item) ∈ signed MSO valueDigests`) + `revocation_id` CBOR anchor |

The mdoc-specific free indices (`sec_mso`, `sec_anchor`) are audited in the nullifier report ([`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md) §5) and carry over unchanged.

## 6. Limitations / trust assumptions

- **CRA operational model** (same as SD-JWT): the CRA must maintain the sorted revoked set and re-sign spans each epoch (freshness is enforced in-circuit; rotation is operational). The demo simulates a gap with `l = N−1, r = N+1`.
- **Fixed-length element**: `revocation_id` is a 64-hex mdoc element so the item fits the 3-block buffer (`SECB = 3`).
- **rev_id = item digest**: the CRA revokes by the `revocation_id` valueDigests entry (the issuer knows it at issuance).

## 7. Files / run

| File | Role |
|---|---|
| `native/mdoc_revoc_split.cc` | real mdoc 2-circuit split + signed-span non-membership revocation |
| `tools/gen-mdoc.mjs` | issues a `revocation_id` element (`@lukas.j.han/mdoc`) |
| `src/demo-mdoc-revocation.js` | `pnpm run demo:mdoc-revocation` (ACCEPT + 4 soundness rejects) |

```bash
# Direct call: <mdoc.bin> <issuer.json> <transcript.bin> <now> <attr_id> <attr_hex> <epoch>
native/mdoc_revoc_split fixtures/mdoc.bin fixtures/mdoc-issuer.json \
  fixtures/mdoc-transcript.bin 2026-06-01T00:00:00Z age_over_18 f5 7
# negative tests: REVOKED=1 / BADSIG=1 / STALE=1 / TAMPER=1 (each must reject)
```

The CRA P-256 key and span signature are generated on the host with OpenSSL in `main`; `l, r` bracket `rev_id` via BIGNUM.

## 8. Relationship to the nullifier

`mdoc_revoc_split` is `mdoc_null_split` with the nullifier tail (`nullifier = SHA(secret‖SHA(context))`) replaced by the span block, and the membership block repurposed: the digest it already computes (`mm`) becomes `rev_id`. A single credential could carry both `pseudonym_secret` and `revocation_id` as independent blocks (no extra MAC values beyond `e_span`).
