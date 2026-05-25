# SD-JWT-VC Privacy-Preserving Revocation (signed-span non-membership) — Analysis Report

> Target: `playground/` — a research extension that adds **privacy-preserving revocation** to the SD-JWT-VC selective-disclosure ZK proof: the holder proves its credential is **not revoked** without revealing which credential it is.
> Location: `/home/unknown/longfellow/playground`
> Date: 2026-05-25 · Status: prototype, working + soundness-audited
> Base: this is an **extension** of the SD-JWT-VC credential proof. The shared machinery (`_sd` membership, the full SD-JWT-VC proof, the 2-circuit MAC split, the §6 free-index audit) is in [`sd-jwt-longfellow-zk_analysis-report.md`](sd-jwt-longfellow-zk_analysis-report.md); the underlying longfellow circuits in [`longfellow-zk_analysis-report.md`](longfellow-zk_analysis-report.md). The method is longfellow's own `MdocRevocationSpan` (`lib/circuits/tests/mdoc/mdoc_revocation.h`), applied to SD-JWT-VC. This report covers only what is revocation-specific.

---

## 1. Overview

A credential system needs **revocation** (expiry/compromise/withdrawal). The naïve check — "is this credential id on the revoked list?" — **reveals the id**, which breaks the unlinkability the ZK proof is built to provide. The goal here is the privacy-preserving version:

> Prove "my (hidden) revocation identifier `rev_id` is **not** on the revocation list" in zero knowledge, revealing neither `rev_id` nor which credential it is.

i.e. a **non-membership** proof. We use the **signed-span** construction, which gives a **constant-size proof regardless of list size** with no Merkle tree, no accumulator, and no trusted setup — reusing the ECDSA + SHA gadgets the proof already pays for.

Prototype: `native/sdjwt_revoc_split.cc` (2-circuit split); demo `pnpm run demo:revocation`; issuer adds a `revocation_id` claim via `tools/gen-sdjwt.mjs`.

## 2. Why signed-span is the ZK-optimal choice

| approach | circuit size | proof | setup | holder upkeep |
|---|---|---|---|---|
| product (∏(list[i]−id)≠0) | **O(N)** ❌ | const | none | none |
| **signed span** (this) | **const** ✅ | const | none | fetch a fresh span |
| Merkle / sparse Merkle | O(depth) | const | none | path updates ⚠️ |
| RSA / pairing accumulator | very heavy ❌ | const | RSA needs it | witness updates |
| epoch / short-lived | 0 (no gadget) ✅✅ | — | none | re-issue often |

For *actual* revocation, signed-span wins: the marginal cost over the base proof is **one ECDSA verify + one 2-block SHA + two comparisons**, all of which fit the existing two-circuit split. (Epoch/short-lived adds nothing in-circuit but trades away revocation latency; the two compose well.)

## 3. Construction

A revocation authority (**CRA**) maintains the sorted set of revoked identifiers `R = {r_1 < r_2 < … < r_n}` (plus sentinels `0`, `2²⁵⁶−1`). For each adjacent pair it signs an **open gap (span)**:

```
span = epoch ‖ l ‖ r        (8-byte epoch ‖ 32-byte l ‖ 32-byte r, little-endian)
e_span = SHA256(span)        signed by the CRA's ECDSA key
```

A non-revoked `rev_id` falls in exactly one such gap. To prove non-revocation the holder presents the span covering its `rev_id` and proves, in ZK:

```
1. e_span is the CRA's valid ECDSA signature target   (authentic span)
2. e_span == SHA256(epoch ‖ l ‖ r)                    (binds l, r to the signature)
3. epoch == verifier's current epoch                  (freshness)
4. l < rev_id < r                                     (rev_id strictly between two
                                                       adjacent revoked ids ⇒ not revoked)
```

**What is `rev_id`?** The issuer embeds a per-credential `revocation_id` as an `_sd` claim (never disclosed). Its **`_sd` digest** — `SHA256(disclosure)`, read as a big-endian 256-bit integer — is `rev_id`. This is elegant: the digest is already a 256-bit number (no in-circuit hex decode), it is **issuer-committed** (so the holder cannot choose it), and it stays hidden (the `_sd` array entries are proven by membership, never revealed).

- **Public**: the CRA public key `(craPkX, craPkY)`, the current `epoch`.
- **Hidden (witness)**: `rev_id`, the span `(l, r)`, the CRA signature.

The issuer-committed chain (Sybil/forgery resistance, §6-S5): `SHA(revocation_id disclosure) = rev_id ∈ _sd ⊂ signed payload`, `SHA(payload) = e`, `e` verified under the issuer's ECDSA key (MAC-linked to the signature circuit). So `rev_id` is bound to a credential the issuer actually signed, and the `","revocation_id","` anchor binds it to *that specific claim* (not some other `_sd` entry).

## 4. Architecture & performance

The split mirrors the base proof, with the span's ECDSA in the Fp256 circuit and its SHA + comparisons in the cheap GF(2¹²⁸) circuit:

- **sig circuit (Fp256)**: issuer ECDSA + holder KB ECDSA + **CRA ECDSA over `e_span`**.
- **hash circuit (GF(2¹²⁸))**: full SD-JWT-VC proof + revocation block — `revocation_id` `_sd` membership (→ `rev_id`), `SHA(epoch‖l‖r)`, epoch pin, `l < rev_id < r`.
- **MAC link extended 3 → 4 values**: `e, dpkx, dpky, e_span`. One shared key half `a_p[8]`, `a_v` from the post-commit transcript; the 8 macs are public in both circuits, so the prover cannot use a different `e_span` in the sig circuit than the SHA-derived one in the hash circuit. Bundle = `[8 macs][hash proof][sig proof]`.

| metric | value (1 disclosed attr, real fixture) |
|---|---|
| prove | ~2.0 s |
| verify | ~0.8 s |
| bundle | ~403 KB |
| hash-circuit ninputs | ~180.9 k |

The proof size and circuit are **independent of the revocation-list size** — the holder only ever carries one span.

## 5. Properties (verified by `demo:revocation`)

- **Not revoked** → ACCEPT (a CRA-signed gap brackets `rev_id`).
- **Revoked** → REJECT — when `rev_id ∈ R` it sits on a gap endpoint, so no signed gap strictly contains it; `l < rev_id < r` cannot hold.
- **Forged status** (span signed by a non-CRA key) → REJECT.
- **Stale span** (signed for a previous epoch) → REJECT.
- **Tampered link** (MAC bit flipped) → REJECT in both circuits.

## 6. Soundness audit

Threat model: a malicious prover must not (S1) pass while revoked, (S2) forge revocation status, (S3) replay a stale status, (S4) desync the two circuits, (S5) use a non-committed / wrong `rev_id`; plus (P) privacy.

| # | Property | Verdict | Mechanism / negative test |
|---|---|---|---|
| S1 | revoked ⇒ reject | ✅ | `l < rev_id < r` is asserted; a revoked id is a gap endpoint so no signed gap contains it. `REVOKED=1` sets `l = N` → assertion fails → **`eval_circuit failed` (proving is impossible)** |
| S2 | span must be CRA-signed | ✅ | CRA ECDSA over `e_span` in the sig circuit. `BADSIG=1` signs with a non-CRA key → ECDSA unsatisfiable → reject |
| S3 | freshness (no stale span) | ✅ | `span_pre[0..8] == epoch_pub` (public). `STALE=1` signs epoch `e+1` while the verifier pins `e` → mismatch → reject |
| S4 | cross-circuit binding | ✅ | `e_span` is the 4th MAC-linked value. `TAMPER=1` flips a mac bit → both circuits reject |
| S5 | `rev_id` issuer-committed & correct claim | ✅ | `SHA(disclosure)=rev_ebits ∈ _sd` (membership → signed payload → ECDSA chain) + `","revocation_id","` literal anchor binds it to that claim |
| P | unlinkability | ✅* | `rev_id`, `l`, `r`, and the issuer signature are all hidden; only `craPk` + `epoch` are public. A fresh proof each presentation. (*Same residual as the base proof: the issuer's public key is still revealed — see base report §8.1.) |

### 6.1 Endianness note (matches `e`)

`rev_id` as a circuit `v256` equals the big-endian value of the digest (`push_rev_bits(dg)` ⇒ integer `= BE(dg) = BN_bin2bn(dg)`). `e_span` is handled exactly like the issuer hash `e`: sig side `to_montgomery(nat_be(span_dg))`, hash side `push_rev_bits(span_dg)` (= the SHA output), and the MAC covers `to_bytes_field = reverse(span_dg)` — consistent across both. `l, r` are stored little-endian in the span and extracted as `lbits[i] = span_pre[8 + i/8][i%8]` (identical to longfellow's `MdocRevocationSpan`), so `vlt` compares them as integers against `rev_id`.

## 7. Limitations / trust assumptions (not fixable in-circuit)

- **CRA operational model.** Soundness of "not revoked" is only as strong as the CRA's invariant of correctly maintaining the sorted revoked set and **re-signing the spans each epoch** (freshness is enforced in-circuit, but the CRA must rotate). The demo simulates a gap with `l = N−1, r = N+1`; a real CRA derives gaps from the actual revoked set.
- **rev_id = `_sd` digest.** Using the digest as the identifier means the CRA revokes by `revocation_id` `_sd` digest (the issuer knows it at issuance). Fine, but it couples the revocation handle to the issued disclosure.
- **Fixed-length claim.** `revocation_id` is a fixed 64-hex `_sd` claim; the issuer must honor that (it must fit one disclosure).
- **mdoc not yet done.** The same construction applies to mdoc (a `revocation_id` IssuerSignedItem + the identical span block, reusing the extraction path of [`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md)); not yet implemented.

## 8. Files / run

| File | Role |
|---|---|
| `native/sdjwt_revoc_split.cc` | 2-circuit split: SD-JWT-VC proof + signed-span non-membership revocation |
| `tools/gen-sdjwt.mjs` | issues a `revocation_id` (64-hex) as an `_sd` claim |
| `src/demo-revocation.js` | `pnpm run demo:revocation` (6 steps: ACCEPT + 4 soundness rejects) |

```bash
# Direct call: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud> <epoch>
native/sdjwt_revoc_split fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example 7
# negative tests: REVOKED=1 / BADSIG=1 / STALE=1 / TAMPER=1 (each must reject)
```

The CRA P-256 key and span signature are generated on the host with OpenSSL in `main` (the CRA role); `l, r` bracket `rev_id` via BIGNUM.

## 9. Future work

- **mdoc revocation** (the same span block on `mdoc_null_split`).
- **Realistic CRA tooling**: maintain the sorted revoked set, derive/sign spans, publish per-epoch.
- **Compose with short-lived epochs**: most churn handled by expiry; signed spans only for urgent revocation.
- **Combine with the nullifier**: one credential carrying both `pseudonym_secret` and `revocation_id` (independent blocks; no extra MAC values).
