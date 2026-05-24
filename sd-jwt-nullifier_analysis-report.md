# SD-JWT-VC Pseudonymous Nullifier (CI/DI) — Analysis Report

> Target: `playground/` — a research extension that turns the SD-JWT-VC selective-disclosure ZK into a **pseudonymous** credential via a **nullifier**, the ZK analogue of Korea's CI/DI.
> Location: `/home/unknown/longfellow/playground`
> Date: 2026-05-24 · Status: prototype, soundness-audited
> Base: this is an **extension** of the credential proof — shared machinery (`_sd` membership, the full SD-JWT-VC proof, the 2-circuit split, the §6 free-index audit) is in [`sd-jwt-longfellow-zk_analysis-report.md`](sd-jwt-longfellow-zk_analysis-report.md).

---

## 1. Overview

A **nullifier** is a deterministic value derived from a per-person secret (and a scope) that is **unlinkable to the identity** yet **unique per (secret, scope)** — so a verifier can detect "one per person within a scope" while learning nothing about who the person is. This is exactly the role of Korea's **CI/DI**, but computed by the holder and **proven in zero knowledge** instead of being handed out by a central identity authority.

Prototype: `native/sdjwt_nullifier.cc` (monolith) and `native/sdjwt_null_split.cc` (2-circuit split); demo `pnpm run demo:nullifier`; issuer adds `pseudonym_secret` via `tools/gen-sdjwt.mjs`.

## 2. Mapping to CI/DI

| Korea real-name id | nullifier form | property |
|---|---|---|
| **CI** (연계정보) | **global** nullifier `PRF(secret)` | same value across all services → cross-service linkable (by design) |
| **DI** (중복확인정보) | **scoped** nullifier `PRF(secret, scope)` | per-service value → unlinkable across services, duplicate-detectable within one |

The scope is a domain separator (service id / verifier id / election id / epoch): include it → DI; omit it → CI.

**Upgrade over CI/DI.** CI/DI are computed by a 본인확인기관 (central authority) that **holds the mapping**. Here the holder computes the nullifier from its own secret and proves *"this nullifier is correctly derived from a secret the issuer committed to"* in ZK — so no central party needs to hold the identity↔pseudonym map, and (for scoped nullifiers) cross-service unlinkability is enforced **cryptographically**, not by policy.

> Note on scope: this targets **unlinkability** (the issuer's signature, a static handle, is hidden and a fresh proof is produced each time), not **inference**. The issuer's public key is still revealed by the credential proof — see the privacy discussion in the base report (§8.1).

## 3. Construction

The issuer embeds a per-person `pseudonym_secret` as an `_sd` claim, so it is **issuer-committed** (the holder cannot choose it). For a verifier-chosen `context`, the circuit proves in zero knowledge:

```
nullifier == SHA256( secret ‖ SHA256(context) )
```

- **Public**: `nullifier`, and `context_hash = SHA256(context)` (the verifier computes it from the agreed scope string; publicly checkable).
- **Hidden (witness)**: `secret` — proven to be in the issuer-signed `_sd` set via membership, then its value fed into the nullifier hash.

The "issuer-committed" chain (which gives Sybil resistance, §6-S2): `SHA(secret_disclosure) ∈ _sd` ⊂ signed payload, `SHA(payload) = e`, and `e` is verified under the issuer's ECDSA key (MAC-linked to the signature circuit in the split). So the secret is bound to a credential the issuer actually signed.

## 4. Properties (verified by `demo:nullifier`)

- Same `(secret, context)` → **same** nullifier — duplicate / Sybil detection (= DI within a scope).
- Different `context` → **different** nullifier — scopes are unlinkable.
- Empty `context` → a single cross-service value (= CI).
- A **forged** nullifier (any value other than the deterministic one) → **REJECT** — one nullifier per scope.

## 5. Architecture & performance

The nullifier SHA is placed in the **GF(2¹²⁸) hash circuit** of the 2-circuit split (binary-field SHA is cheap); the signature circuit is unchanged.

| | monolith (`sdjwt_nullifier`) | split (`sdjwt_null_split`) |
|---|---|---|
| prove | ~13 s (end-to-end) | **~1.6 s** + verify ~0.7 s |
| proof / bundle | ~816 KB | **~387 KB** |

Both produce an **identical** nullifier for the same `(secret, context)`. After the S3 fix the nullifier message is 96 B → `NULLB = 2` SHA blocks.

## 6. Soundness audit

Threat model: a malicious prover must not (S1) mint ≥2 nullifiers per scope, (S2) use a non-committed secret, (S3) collide distinct scopes; plus (P) privacy.

| # | Property | Verdict |
|---|---|---|
| S1 | determinism (one nullifier per scope) | ✅ **guaranteed** — the whole SHA preimage is bound (secret + context_hash + canonical padding) and `null_nb` is fixed; the secret-extraction position is **uniquely forced** because base64url/hex exclude the anchor chars `"`/`,` (stronger than a probabilistic argument) |
| S2 | secret is issuer-committed | ✅ `_sd` membership → signed payload → ECDSA chain (§3) |
| S3 | scope separation | ✅ after fix (below) |
| P | issuer non-traceability | ⚠️ limited (§8) |

**[S3] found & fixed.** The first version padded/truncated `context` into a fixed 64-byte field, so distinct scopes sharing the first 64 bytes **collided** — measured: `A×64` and `A×64+X` produced the same nullifier `bb3169d7…`. **Fix:** bind `SHA256(context)` instead of the raw context (length-independent), `CTXLEN 64→32`, `NULLB 3→2`. Re-measured: `878af16f…` vs `4accdf0c…` — now distinct.

### 6.1 Free-index audit (nullifier-specific)

The nullifier circuit reuses the credential indices (base report §6) and adds these; audited here since it is a distinct circuit:

| Index | Points at | Safety basis | Verdict |
|---|---|---|---|
| `sec_sd_idx` | `_sd` entry for the secret | `base64decode(window) == SHA(secret_disclosure)` → SHA preimage/collision (same as `sd_idx`) | ✅ (hash) |
| `sec_shift` | secret value offset in the disclosure | `","pseudonym_secret","` literal anchor; **uniquely forced** (base64url/hex exclude `"`/`,`) | ✅ guaranteed |
| `sec_len` | decoded disclosure length | wrong length → anchor/membership fails | ✅ |

> `null_nb` is asserted `== NULLB` and `null_pre` is fully bound to `secret ‖ context_hash ‖ canonical-padding`, so the nullifier SHA input is constant (no free witness). `context_hash` is a public input, not a witness.

## 7. Limitations / trust assumptions (not fixable in-circuit)

- **Issuer can de-anonymize / link (P).** The issuer knows `secret`, so it can compute the nullifier for any scope → it can link a user across scopes and to identity. Same trust model as CI/DI (the authority knows). **Blind issuance** (the issuer signs a commitment to a secret it never learns) would remove this — the main future-work item.
- **Sybil = one secret per person.** Sybil resistance is only as strong as the issuer's invariant of issuing **one `pseudonym_secret` per real person** (including across re-issuances). The circuit cannot enforce this — it is issuer policy (as with CI/DI).
- **Fixed-length secret.** `pseudonym_secret` is a fixed 64-hex value; the issuer must honor that.
- **mdoc — now implemented.** longfellow's public mdoc API cannot expose a hidden-secret nullifier (disclosing an attribute reveals it), so an mdoc nullifier needs a custom circuit; that circuit now exists — see [`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md).

## 8. Files / run

| File | Role |
|---|---|
| `native/sdjwt_nullifier.cc` | monolith (single Fp256 circuit) — full SD-JWT-VC proof + nullifier |
| `native/sdjwt_null_split.cc` | 2-circuit split — nullifier SHA in the GF(2¹²⁸) hash circuit (fast) |
| `tools/gen-sdjwt.mjs` | issues `pseudonym_secret` (64-hex) as an `_sd` claim |
| `src/demo-nullifier.js` | `pnpm run demo:nullifier` (default split; `MONO=1` for monolith) |

```bash
# Direct call: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud> <context>
native/sdjwt_null_split fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example "shop-A"
```

## 9. Future work

- **Blind issuance** → close the issuer-traceability gap (P).
- **mdoc nullifier** (custom CBOR circuit) — ✅ done, see [`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md).
- Verifier-side **context binding**: have the wallet verify a trust-anchor-signed JWT carrying the `context` (the demo passes it as a plain string).
- Rate-limiting / one-time-use variants (cf. Semaphore, RLN, Worldcoin).
