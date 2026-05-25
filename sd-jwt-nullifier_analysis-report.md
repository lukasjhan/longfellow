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

- **Issuer can de-anonymize / link (P).** The issuer knows `secret`, so it can compute the nullifier for any scope → it can link a user across scopes and to identity. Same trust model as CI/DI (the authority knows). **Blind issuance** (the issuer signs a commitment to a secret it never learns) removes this — **now implemented, see §10**.
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

- **Blind issuance** → close the issuer-traceability gap (P) — ✅ **done, see §10**.
- **mdoc nullifier** (custom CBOR circuit) — ✅ done, see [`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md).
- Verifier-side **context binding**: have the wallet verify a trust-anchor-signed JWT carrying the `context` (the demo passes it as a plain string).
- **Issuance-time well-formedness proof** for blind issuance (so the issuer signs only single, well-shaped commitments) — see §10.6.
- Rate-limiting / one-time-use variants (cf. Semaphore, RLN, Worldcoin).

---

## 10. Advanced — blind issuance (removes issuer traceability)

The sections above embed the secret itself (`pseudonym_secret`) in the credential, so the **issuer knows it** and can compute any scope's nullifier (limitation **P**, §7). This section evolves the construction so the **issuer never learns the secret**, closing P — while preserving every property of §4 and the Sybil binding of §6.

Prototype: `native/sdjwt_null_blind.cc`; demo `pnpm run demo:nullifier-blind`; issuer `tools/gen-sdjwt-blind.mjs`. The earlier files are unchanged.

### 10.1 Idea: commit, don't reveal

Instead of the issuer choosing the secret, the **holder** generates `secret` (32 B) and a blinding `blind` (32 B), and commits

```
C = SHA256( secret ‖ blind )        // hiding + binding commitment
```

The issuer signs **only** `pseudonym_commitment = base64url(C)` as an `_sd` claim. It never sees `secret`/`blind`, so it cannot compute `SHA256(secret ‖ SHA256(context))` for any scope. (`blind` makes the commitment hiding regardless of secret entropy; binding comes from SHA collision resistance.) The holder's private material (`secret ‖ blind`) stays holder-side (`fixtures/holder-secret.txt`); the prover reads it via `HOLDER_SECRET`.

### 10.2 What the circuit proves (added to the GF(2¹²⁸) hash circuit)

For a verifier-chosen `context`, in one ZK proof, **with `secret`/`blind` hidden**:

1. **Membership** — `SHA(commitment_disclosure) ∈ payload._sd` (so `C` is issuer-committed). *Reused from §3.*
2. **Decode** — extract the 43-char base64url value after the literal anchor `","pseudonym_commitment","` and base64url-decode it → `Cbytes` (32 B). *Reuses the existing decoder.*
3. **Opening (new)** — `open_digest = SHA256(secret ‖ blind)` **and** `open_digest == Cbytes`. Proves the prover knows `(secret, blind)` that open the issuer-committed `C`.
4. **Nullifier** — `nullifier = SHA256(secret ‖ context_hash)`, fully bound (canonical padding, `null_nb` fixed). *Reused from §3.*

The **same `secret` wires** feed both (3) and (4), so the value bound to the issuer's commitment is exactly the one in the pseudonym. Net new circuitry = **one SHA block (opening) + a base64url decode + equality asserts**; everything else (membership, structural, signature, MAC link) is the §3/split machinery unchanged.

### 10.3 Properties (verified by `demo:nullifier-blind`)

All of §4, plus the decisive blind property:

| Step | Check | Result |
|---|---|---|
| same `(secret, context)` | identical nullifier | ✅ DI dedup |
| different `context` | different nullifier | ✅ unlinkable |
| empty `context` | single global value | ✅ CI |
| `EVIL_NULL` (forged nullifier) | unprovable | ✅ REJECT |
| **`EVIL_SECRET`** (secret that doesn't open `C`) | **`eval_circuit failed`** | ✅ **REJECT** |
| `TAMPER` (flip a MAC bit) | both circuits reject | ✅ REJECT |

`EVIL_SECRET` is the new one: a party that knows the public commitment `C` but not the secret cannot prove — the **opening** (3) forces the secret. So only the legitimate holder proves, **yet the issuer never learned the secret**.

### 10.4 Performance (measured, 1 attribute + nullifier)

| | sig (Fp256) | hash (GF(2¹²⁸)) |
|---|---|---|
| ninputs | ~3.7 k | ~185.8 k |
| proof | ~194 KB | ~194 KB |

End to end: **prove ≈ 1.8 s, verify ≈ 0.77 s, bundle ≈ 389 KB**. Versus the non-blind split (§5), the extra opening adds only one SHA block in the cheap binary field, so cost is essentially unchanged. Cache: `circuits-cache/sdjwt-nullblind-hash-<geo>.bin`; transcript label `"sdjwt-blind"`.

### 10.5 Soundness

Same threat model as §6. How each property survives blinding:

| # | Property | Verdict (blind) |
|---|---|---|
| S1 | determinism (one nullifier per scope) | ✅ unchanged — `null_pre` fully bound, `null_nb` fixed (§6) |
| S2 | secret is issuer-anchored | ✅ now via the **commitment**: `SHA(commitment_disclosure) ∈ _sd` → signed payload → ECDSA, **plus** the opening `C == SHA(secret‖blind)` ties the hidden secret to that signed `C` (a different secret needs a SHA collision with `C`) |
| S3 | scope separation | ✅ unchanged — binds `SHA256(context)` |
| **P** | **issuer non-traceability** | ✅ **now achieved** — the issuer only ever saw `C` (hiding), so it cannot compute the nullifier for any scope |

> **Sybil still needs issuer policy.** Hiding the secret does **not** weaken "one per person": that invariant comes from the issuance gate (KYC + one credential per real identity), independent of whether the issuer sees the secret. A holder choosing its own secret is like choosing a password — it grants no new identity; the credential is still issued once, to the authenticated person.

Free-index audit (new/changed indices; `secret`/`blind` are direct witnesses, not free indices):

| Index | Points at | Safety basis | Verdict |
|---|---|---|---|
| `com_sd_idx` | commitment's `_sd` entry | `base64decode(window) == SHA(commitment_disclosure)` → SHA preimage/collision | ✅ (hash) |
| `com_shift` | commitment value offset | `","pseudonym_commitment","` literal anchor; base64url excludes `"`/`,` → uniquely forced | ✅ guaranteed |
| `com_len` | decoded disclosure length | wrong length → anchor/membership fails | ✅ |

> `secret`/`blind` are private input wires pinned by the opening (`SHA(secret‖blind)==C`) and the nullifier (`SHA(secret‖ctx_hash)==nullifier`); there is no index to mispoint, and the same `secret` wires feed both.

### 10.6 What blind issuance does NOT solve

- **Issuance-time well-formedness (demo simplification).** A real issuer should require the holder to prove, at issuance, that `C` is a *well-formed commitment to a single secret of the right shape* — otherwise a holder could commit garbage or multiple secrets. The demo's issuer trusts the holder's `C`; this issuance-time proof is a separate protocol step (not the presentation circuit). The presentation ZK above is complete.
- **Credential sharing.** A holder voluntarily handing `(credential, secret, blind)` to another party is out of scope (mitigated by device binding / KB; common to all credential systems and to CI/DI).
- **Issuer's 1-per-person policy.** As in §7, Sybil resistance still relies on the issuer issuing one credential per real identity.
- **Inference.** The issuer public key (→ issuing country for a PID) is still revealed by the credential proof (base report §8.1).

### 10.7 Files / run

| File | Role |
|---|---|
| `native/sdjwt_null_blind.cc` | blind variant — commitment membership + opening + nullifier (in the GF(2¹²⁸) hash circuit) |
| `tools/gen-sdjwt-blind.mjs` | holder commits `C=SHA(secret‖blind)`; issuer signs `pseudonym_commitment` only |
| `src/demo-nullifier-blind.js` | `pnpm run demo:nullifier-blind` (issue → DI → scoping → CI → forged / wrong-secret / tamper reject) |
| `fixtures/holder-secret.txt` | holder-only `secret_hex ‖ blind_hex` (never sent to the issuer) |

```bash
# Direct call: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud> <context>
#   reads the holder secret via HOLDER_SECRET (= secret_hex ‖ blind_hex)
HOLDER_SECRET=fixtures/holder-secret.txt \
native/sdjwt_null_blind fixtures/sdjwt-blind.txt fixtures/issuer-jwk-blind.json 1700000000 \
  "age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example "shop-A"
# env: EVIL_NULL=1 (forged nullifier), EVIL_SECRET=1 (secret doesn't open C), TAMPER=1 (break MAC)
```

### 10.8 Usage: disclose vs assert per claim

The `<claims>` argument is comma-separated; each claim picks its own mode:

| Claim syntax | Mode | Effect |
|---|---|---|
| `name` | **disclose** | reveal the value to the verifier (prints `disclosed: name = value`) |
| `name=<json>` | **assert** | prove `value == <json>` **without revealing it** (prints `asserted: name == <json>`); a mismatch yields no proof |

Both share the **same circuit and cache** — the value is a public input (`pattern`); only its source differs (disclose = the holder's value, assert = the verifier's required value). You can mix modes in one proof.

Value format (assert) — `<json>` is the JSON encoding of the value:

| Type | Example | Note |
|---|---|---|
| string | `resident_city="Seoul"` | include the quotes |
| boolean | `age_over_18=true` | no quotes |
| number | `height=175` | no quotes |

```bash
# disclose — reveal the values
native/sdjwt_null_blind … 1700000000 "age_over_18,resident_city" "https://credentials.example/pid" …

# assert — prove the values, hidden; single-quote the arg to keep the inner "
native/sdjwt_null_blind … 1700000000 'age_over_18=true,resident_city="Seoul"' "https://credentials.example/pid" …

# mixed — assert age (hidden), disclose city (revealed)
native/sdjwt_null_blind … 1700000000 'age_over_18=true,resident_city' "https://credentials.example/pid" …
```

> Shell gotcha: an unquoted `resident_city="Seoul"` loses its quotes (→ `resident_city=Seoul`, a non-string) and the pattern won't match — wrap the whole claims arg in `'…'`. In JS, `JSON.stringify(value)` produces the right form (see `src/scenario-voting-sdjwt-assert.js`).
>
> When to use which: **disclose** when the verifier needs the value (display, range/set policy); **assert** when a yes/no suffices and you want to hide the value on mismatch. Conceptual comparison: [`voting-scenario_analysis-report.md`](voting-scenario_analysis-report.md) §5 / §5.1.
>
> ⚠️ `==` caveat: on a **match**, assert reveals the same as disclose (the asserted value is in the public input), so assert's only gain for equality is hiding the value on a **mismatch**. A privacy gain *even on success* needs range/set/derived predicates — not implemented here (equality only).
