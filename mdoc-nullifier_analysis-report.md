# mdoc (ISO 18013-5) Pseudonymous Nullifier — Analysis Report

> Target: `playground/` — a research extension that adds a **pseudonymous nullifier** (the ZK analogue of Korea's CI/DI) to a **real mdoc** ZK presentation, on top of longfellow's two-circuit mdoc prover.
> Location: `/home/unknown/longfellow/playground`
> Date: 2026-05-24 · Status: prototype, working + soundness-audited
> Base: this is an **extension** of the mdoc credential proof. The shared CI/DI semantics, the nullifier construction philosophy, and the soundness threat model are documented once in the SD-JWT version, [`sd-jwt-nullifier_analysis-report.md`](sd-jwt-nullifier_analysis-report.md); the underlying longfellow mdoc circuits are in [`longfellow-zk_analysis-report.md`](longfellow-zk_analysis-report.md). This report covers only what is **mdoc-specific**.

---

## 1. Overview

A **nullifier** is a deterministic value derived from a per-person secret (and a scope) that is **unlinkable to the identity** yet **unique per (secret, scope)**, so a verifier can enforce "one per person within a scope" while learning nothing about who the person is — exactly Korea's **CI/DI**, but computed by the holder and **proven in zero knowledge** (see [`sd-jwt-nullifier_analysis-report.md`](sd-jwt-nullifier_analysis-report.md) §1–2 for the full CI/DI mapping; it applies verbatim here).

The SD-JWT nullifier report listed **"mdoc not implemented"** as a limitation and a future-work item, because longfellow's public mdoc API only exposes attribute *disclosure* (which reveals the value) — a hidden-secret nullifier needs a custom circuit. **This report is that circuit.**

Prototype: `native/mdoc_null_split.cc`; demo `pnpm run demo:mdoc-nullifier`; issuer embeds `pseudonym_secret` as a normal mdoc attribute via `tools/gen-mdoc.mjs` (which issues + presents a real mdoc using `@lukas.j.han/mdoc`).

## 2. Construction

Two MAC-linked circuits — the standard longfellow mdoc split, **reused unchanged**, plus one added block:

| Circuit | Field | Content |
|---|---|---|
| **sig** | Fp256 | `MdocSignature::assert_signatures` — issuer ECDSA over the MSO hash `e`, device ECDSA over the session-transcript hash. *Unchanged.* |
| **hash** | GF(2¹²⁸) | `MdocHash::assert_valid_hash_mdoc` — SHA(MSO), validFrom/Until, deviceKey, valueDigests membership, public attributes. *Unchanged.* **+ a dedicated nullifier block (this work).** |

The two circuits are linked by MACs over the common values `(e, dpkx, dpky)`: one shared committed key half `a_p`, `a_v` drawn from the post-commit transcript, the macs public in both. Bundle = `[6 macs][hash proof][sig proof]`. The Fiat–Shamir transcript is seeded by the session transcript. (Identical to `mdoc_zk.cc` / `sdjwt_null_split.cc`.)

For a verifier-chosen `context`, the hash circuit additionally proves in zero knowledge:

```
nullifier == SHA256( secret(64 B) ‖ SHA256(context) )
```

- **Public**: `nullifier`, and `context_hash = SHA256(context)`.
- **Hidden (witness)**: `secret` — the 64-byte `pseudonym_secret` value, extracted in-circuit and never revealed.

### 2.1 Why a *dedicated* block, not the attribute path

The natural idea — pass `pseudonym_secret` as one of `MdocHash`'s attributes but keep its value private and feed it to the nullifier — **does not fit**, and the reason is the key mdoc-specific finding:

`@lukas.j.han/mdoc` issues `pseudonym_secret` as a 64-hex-char value, so its `IssuerSignedItem` is **~174 B**:

```
D8 18 58 AA  A4                              ; tag24, bstr(170), map(4)
  68 "digestID" 1A xxxxxxxx                  ; digestID
  66 "random"  58 20 <32 bytes>             ; 32-byte random
  71 "elementIdentifier" 70 "pseudonym_secret"
  6C "elementValue"      78 40 <64 hex>      ; the secret
```

`MdocHash`'s attribute path hard-codes a **2-SHA-block** item buffer (`attrb_[128]`, `attr_sha_[2]`), an `OpenedAttribute.v1[64]` value field, and a documented constraint that *elementIdentifier + elementValue ≤ 56 B*. A 174-byte item (3 SHA blocks) with a 66-byte value field **exceeds all three**. So the secret cannot ride the public-attribute machinery.

Instead the nullifier rides its **own 3-block item buffer** (`SECB = 3`, 192 B), mirroring the proven SD-JWT split-nullifier design. This needs **no change to the longfellow submodule and no change to the issuer**, and keeps a full 256-bit secret.

### 2.2 The nullifier block (`assert_nullifier`)

1. **Membership.** `SHA(sec_item) = mm`. Prove `mm` appears as a 32-byte CBOR byte string (`58 20 …`) inside the **signed MSO** `valueDigests`: shift `w.in_ + 5 + 2` (the MSO buffer that `assert_valid_hash_mdoc` already SHA-binds to `e`) by `sec_mso`, assert the `58 20` tag, and compare the 32 bytes to `mm`. (This replicates `MdocHash`'s attribute MSO-membership, but for a 3-block item; the MSO length / `check_index` are reconstructed and de-duplicated by the compiler.)
2. **Extraction.** Shift `sec_item` by `sec_anchor` and assert the 50-byte literal CBOR anchor

   ```
   71 "elementIdentifier" 70 "pseudonym_secret" 6C "elementValue" 78 40
   ```

   then read the next **64 bytes** as the secret value — **in-circuit only, never published**. The anchor pins both the attribute identity (`pseudonym_secret`) and the value length (`78 40` = text(64)).
3. **Nullifier.** `nullifier = SHA( secret(64) ‖ SHA(context)(32) )`, with the whole 96-byte preimage bound (value, context hash, `0x80` padding, zero fill, length) and `null_nb` fixed — deterministic per `(secret, context)`.

The issuer-committed chain (Sybil resistance): `SHA(sec_item) ∈ valueDigests` ⊂ MSO, `SHA(MSO) = e`, `e` verified under the issuer ECDSA key in the sig circuit (MAC-linked). So the secret is bound to a credential the issuer actually signed.

## 3. Properties (verified by `demo:mdoc-nullifier`)

- Same `(secret, context)` → **same** nullifier — duplicate / Sybil detection (= DI within a scope).
- Different `context` → **different** nullifier — scopes are unlinkable.
- A **forged** nullifier (`EVIL_NULL`) → **unprovable** (the witness cannot satisfy `nullifier == SHA(secret ‖ SHA(context))`) — one nullifier per scope.
- A tampered mac (`TAMPER`) → **both circuits reject** — the MAC link binding `e/dpkx/dpky` across the two circuits is load-bearing.

## 4. Architecture & performance

Measured on `fixtures/mdoc.bin` (1 public attribute, `age_over_18`):

| | sig (Fp256) | hash (GF(2¹²⁸)) |
|---|---|---|
| ninputs | ~3.7 k | ~95.6 k |
| proof | ~195 KB | ~151 KB |

End to end: **prove ≈ 0.95 s, verify ≈ 0.43 s, bundle ≈ 345 KB**. The nullifier SHA lives in the binary-field hash circuit (SHA is cheap there); the signature circuit is untouched. The secret item is `SECB = 3` blocks; the nullifier message is 96 B → `NULLB = 2` blocks.

## 5. Soundness audit

Threat model (same as the SD-JWT version §6): a malicious prover must not (S1) mint ≥2 nullifiers per scope, (S2) use a non-committed secret, (S3) collide distinct scopes; plus (P) privacy.

| # | Property | Verdict |
|---|---|---|
| S1 | determinism (one nullifier per scope) | ✅ **guaranteed** — the whole 96-byte SHA preimage is bound and `null_nb` is fixed; the extraction offset `sec_anchor` is **uniquely forced** because the 50-byte anchor (containing `"pseudonym_secret"`, `"elementValue"`, `78 40`) cannot appear inside the hex value nor be matched twice in a single item |
| S2 | secret is issuer-committed | ✅ `SHA(sec_item) ∈ valueDigests` → `SHA(MSO)=e` → issuer ECDSA (§2.2); a different `sec_item` would need a SHA collision with a signed digest |
| S3 | scope separation | ✅ binds `SHA256(context)` (length-independent), inheriting the SD-JWT S3 fix; `CTXLEN = 32` |
| P | issuer non-traceability | ⚠️ limited (§6) |

### 5.1 Free-index audit (mdoc nullifier-specific)

The block adds two host-provided indices; both are constrained so a wrong value fails:

| Index | Points at | Safety basis | Verdict |
|---|---|---|---|
| `sec_mso` | the item's 32-byte digest inside the MSO | range-checked `< len(MSO)`; the window must start with `58 20` and the following 32 bytes must equal `SHA(sec_item)` — i.e. a real, signed digest | ✅ (signature + hash) |
| `sec_anchor` | the anchor offset inside `sec_item` | the 50-byte literal `71 elementIdentifier 70 pseudonym_secret 6C elementValue 78 40` must match; **uniquely forced** (one such field per item; hex value bytes cannot reproduce the anchor) | ✅ guaranteed |

> `null_nb` is asserted `== NULLB` and `null_pre` is fully bound to `secret ‖ SHA(context) ‖ canonical padding`, so the nullifier SHA input is constant (no free witness). `context_hash` is a public input. `sec_nb` is fixed `== SECB`.

## 6. Limitations / trust assumptions (not fixable in-circuit)

Same model as the SD-JWT nullifier (see that report §7):

- **Issuer can de-anonymize / link (P).** The issuer knows `secret`, so it can compute the nullifier for any scope. Same trust model as CI/DI. **Blind issuance** (the issuer signs a commitment to a secret it never learns) removes this — **now implemented, see §9**.
- **Sybil = one secret per person.** Only as strong as the issuer's policy of issuing one `pseudonym_secret` per real person across re-issuances. Not enforceable in-circuit (as with CI/DI).
- **Fixed format.** `pseudonym_secret` is a fixed 64-hex value and its `IssuerSignedItem` must fit `SECB = 3` SHA blocks; `elementIdentifier` must immediately precede `elementValue` (the contiguous-anchor assumption). `@lukas.j.han/mdoc` satisfies all of these; an issuer that reorders or pads differently would need the anchor / `SECB` adjusted.
- **Device binding.** The proof is a faithful mdoc presentation (device signature over the session transcript is verified), so it is not replayable across transcripts; but unlinkability still reveals the issuer's public key (see base report).

## 7. Files / run

| File | Role |
|---|---|
| `native/mdoc_null_split.cc` | two-circuit mdoc present/verify (`MdocSignature` + `MdocHash`) + nullifier block |
| `tools/gen-mdoc.mjs` | issues a real mdoc with `pseudonym_secret` (64-hex) via `@lukas.j.han/mdoc` |
| `src/demo-mdoc-nullifier.js` | `pnpm run demo:mdoc-nullifier` (issue → determinism → scoping → forgery-reject) |

```bash
# Direct call: <mdoc.bin> <issuer.json> <transcript.bin> <now> <attr_id> <attr_hex> <context>
native/mdoc_null_split fixtures/mdoc.bin fixtures/mdoc-issuer.json \
  fixtures/mdoc-transcript.bin 2026-06-01T00:00:00Z age_over_18 f5 context-A
# env: EVIL_NULL=1 (forged nullifier → unprovable), TAMPER=1 (break MAC link → reject)
```

## 8. Future work

- **Blind issuance** → close the issuer-traceability gap (P) — ✅ **done, see §9**.
- **Length-agnostic / multiple secrets** — generalize the anchor + `SECB` to other issuer encodings.
- Verifier-side **context binding** — carry the `context` in a trust-anchor-signed structure rather than a plain string.
- **Issuance-time well-formedness proof** for blind issuance (issuer signs only single, well-shaped commitments) — see §9.5.
- Rate-limiting / one-time-use variants (cf. Semaphore, RLN).

---

## 9. Advanced — blind issuance (removes issuer traceability)

§1–8 embed the secret in the credential, so the **issuer knows it** and can compute any scope's nullifier (limitation **P**, §6). This section evolves the construction so the **issuer never learns the secret**, closing P. The CI/DI mapping, the commitment idea, and the full Sybil/soundness argument are shared with the SD-JWT version — see [`sd-jwt-nullifier_analysis-report.md`](sd-jwt-nullifier_analysis-report.md) §10; this section covers only what is **mdoc-specific**.

Prototype: `native/mdoc_null_blind.cc`; demo `pnpm run demo:mdoc-nullifier-blind`; issuer `tools/gen-mdoc-blind.mjs`. The §1–8 files are unchanged.

### 9.1 Commitment as a CBOR byte string

The holder generates `secret` (32 B) + `blind` (32 B) and commits `C = SHA256(secret ‖ blind)`. The issuer signs **only** `pseudonym_commitment = C`, which `@lukas.j.han/mdoc` issues as a **CBOR byte string** (`58 20 <32 B>`) — verified empirically. This is *cleaner than the SD-JWT case*: there the commitment is base64url and must be decoded in-circuit, whereas here the 32 raw bytes sit directly in the signed item, so no decode is needed. The anchor becomes

```
71 "elementIdentifier" 74 "pseudonym_commitment" 6C "elementValue" 58 20   (54 B)
```

followed by the 32 commitment bytes. `secret`/`blind` live only on the holder side (`mdoc-holder-secret.txt`); the prover reads them via `HOLDER_SECRET`.

### 9.2 What changes in `assert_nullifier` (vs §2.2)

Steps (1) MSO-preimage + index range-check and (2) membership `SHA(item) ∈ MSO valueDigests` are **unchanged** — now proving the *commitment* item is issuer-signed. The rest:

3. **Extraction** — shift the 54-byte anchor to the front, assert it, then take the next 32 bytes as `C`; build a `v256 cm` from them in SHA bit-order (the same reversal `MdocHash` uses for `mm`).
4. **Opening (new)** — bind `open_pre = secret ‖ blind ‖ padding` and assert `SHA(open_pre) == cm` via one `assert_message_hash` (the expected digest *is* the extracted commitment, so no separate witness/compare is needed). Proves the holder knows `(secret, blind)` behind the issuer-committed `C`.
5. **Nullifier** — `SHA(secret ‖ context_hash)`, fully bound; the **same `secret` wires** feed (4) and (5).

Net new circuitry over §2.2 = **one SHA block (opening) + a wider anchor**; the secret is now a hidden witness (32 B) rather than extracted from the item.

### 9.3 Properties (verified by `demo:mdoc-nullifier-blind`)

§3, plus the decisive blind property:

| Step | Check | Result |
|---|---|---|
| same `(secret, context)` | identical nullifier | ✅ DI dedup |
| different `context` | different nullifier | ✅ unlinkable |
| `EVIL_NULL` (forged nullifier) | unprovable | ✅ REJECT |
| **`EVIL_SECRET`** (secret that doesn't open `C`) | **`eval_circuit failed`** (hash circuit) | ✅ **REJECT** |
| `TAMPER` (flip a MAC bit) | both circuits reject | ✅ REJECT |

### 9.4 Performance (measured, 1 public attr + blind nullifier)

| | sig (Fp256) | hash (GF(2¹²⁸)) |
|---|---|---|
| ninputs | ~3.7 k | ~100 k |
| proof | ~195 KB | ~151 KB |

End to end: **prove ≈ 1.1 s, verify ≈ 0.5 s, bundle ≈ 346 KB** — essentially identical to §4 (the opening adds one SHA block in the cheap binary field). Cache `circuits-cache/mdoc-nullblind-hash-<geo>.bin`; the sig circuit (and its cache) is shared with §1–8 unchanged.

### 9.5 Soundness

Identical threat model and verdicts to the SD-JWT blind version ([`sd-jwt-nullifier_analysis-report.md`](sd-jwt-nullifier_analysis-report.md) §10.5): S1 (determinism) and S3 (scope) unchanged; **S2** now anchors the secret via the *commitment* (`SHA(commitment item) ∈ valueDigests → SHA(MSO)=e → issuer ECDSA`, **plus** the opening `SHA(secret‖blind)==C`); **P** is now achieved — the issuer only ever saw `C` (hiding), so it cannot compute any nullifier. Sybil still relies on the issuer's one-per-person policy (§6), independent of blinding.

Free-index audit: `sec_mso` and `sec_anchor` are as §5.1 (the anchor is now 54 B ending in `58 20`; the literal anchor uniquely forces the offset, and the 32 value bytes are pinned by the opening `SHA(secret‖blind)==C` rather than a hash-attestation). `secret`/`blind` are direct hidden witnesses (no index to mispoint), shared between opening and nullifier.

> Issuance-time well-formedness (the issuer should require a proof that `C` is a single, well-shaped commitment) is a separate protocol step, simplified in the demo — same as the SD-JWT version (§10.6).

### 9.6 Files / run

| File | Role |
|---|---|
| `native/mdoc_null_blind.cc` | blind variant — commitment membership + opening + nullifier (in the MdocHash circuit) |
| `tools/gen-mdoc-blind.mjs` | holder commits `C`; issuer signs `pseudonym_commitment` (byte string) only |
| `src/demo-mdoc-nullifier-blind.js` | `pnpm run demo:mdoc-nullifier-blind` |
| `fixtures/mdoc-holder-secret.txt` | holder-only `secret_hex ‖ blind_hex` (never sent to the issuer) |

```bash
# Direct call (reads the holder secret via HOLDER_SECRET = secret_hex ‖ blind_hex):
HOLDER_SECRET=fixtures/mdoc-holder-secret.txt \
native/mdoc_null_blind fixtures/mdoc-blind.bin fixtures/mdoc-blind-issuer.json \
  fixtures/mdoc-blind-transcript.bin 2026-06-01T00:00:00Z age_over_18 f5 context-A
# env: EVIL_NULL=1 (forged nullifier), EVIL_SECRET=1 (secret doesn't open C), TAMPER=1 (break MAC)
```
