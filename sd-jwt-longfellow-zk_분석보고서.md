# SD-JWT-VC × Longfellow-ZK Analysis Report

> Target: `playground/` — implementation porting Longfellow-ZK's mdoc selective-disclosure ZK technique to **SD-JWT-VC**
> Location: `/home/unknown/longfellow/playground`
> Date: 2026-05-24 · Status: hardening in progress after security review
> For analysis of the upstream library, see [`longfellow-zk_분석보고서.md`](longfellow-zk_분석보고서.md)

---

## 1. At a Glance (TL;DR)

Longfellow-ZK provides a public API only for **mdoc (ISO 18013-5)** (the JWT circuit is experimental). This
project ports its **core philosophy (reduce selective disclosure to "membership" over a
digest set signed by the issuer, rather than parsing JSON/CBOR inside the circuit)** and its **two-circuit + MAC architecture**
directly to **SD-JWT-VC**.

- What is proven: standard SD-JWT-VC (`_sd` Disclosure membership) + validity period (exp) + Key Binding +
  sd_hash binding + vct + **nonce/aud (freshness)** + N variable multiple attributes.
- Architecture: same as mdoc, an **Fp256 signature circuit + GF(2¹²⁸) hash circuit** linked by MAC.
- All value types (string/number/boolean/date) handled as membership without parsing.
- Maturity: **experimental/research** (no public API, demo CLI). As of this report, two soundness
  hardenings (exp, nonce/aud) have been applied; remaining items are summarized in §9.

---

## 2. What is proven / verified

A **prover (holder)** proves to a **verifier**, without revealing the raw token, that "I hold a valid credential
and some of its attributes have specific values." The verifier sees **only the public input + proof** and
decides ACCEPT/REJECT (it cannot see the credential, signature, or remaining attributes).

Key point: the circuit does not parse JSON. It reduces the statement to **`SHA(disclosure) ∈ payload._sd` (membership over a set
attested by the issuer signature)** plus several **anchor checks**.

### 2.1 Public vs Private (the ZK boundary)

| Public (seen or chosen by the verifier) | Private (witness, hidden) |
|---|---|
| issuer public key `pkX·pkY` | issuer signature (r,s) |
| `now` (verification time) | **actual exp value** (only the `now≤exp` predicate is exposed) |
| `vct` (expected type) | holder KB signature |
| **`nonce`·`aud`** (verifier challenge) | device key `dpkx·dpky` |
| disclosed `(claim name, value)` × N | salts, sd_hash |
| `e2` (KB hash), MACs | **all other undisclosed claims/disclosures** |
| | raw payload, presented bundle, entire token |

> "given_name=Erika" is **public** (the essence of selective disclosure). What is hidden is the signature, salt, device key,
> **remaining claims**, and the raw text. exp hides its value and proves only the `now≤exp` predicate.

### 2.2 Statements proven by the circuit (full list)

1. Issuer `(pkX,pkY)` ES256-signed payload `P` — sig circuit `verify3(e)` + hash circuit
   `SHA(header.payload)==e`, with `e` linking the two circuits via MAC.
2. `P` has `vct == <public vct>`.
3. `P` has `exp` and `now ≤ exp`.
4. `P`'s `cnf.jwk == device key (dpkx,dpky)`.
5. The holder ES256-signed the KB-JWT with that device key, and its hash is `e2` (sig circuit).
6. KB payload has `nonce==<public nonce>` and `aud==<public aud>`.
7. KB payload's `sd_hash == SHA(presented bundle)`.
8. For each disclosed claim: `SHA(disclosure) ∈ P._sd` (membership) + disclosure decodes to
   `[salt,<public name>,<public value>]` (structural) + disclosure ∈ presented (consent).

---

## 3. Architecture: two circuits + MAC (same as mdoc)

| | Signature circuit | Hash circuit |
|---|---|---|
| Field | `Fp256Base` (P-256) | `f_128` = GF(2¹²⁸) |
| Responsibility | issuer ES256 + holder KB ES256 | SHA + exp + vct + cnf + sd_hash + nonce/aud + N×(membership·structural·consent) |
| Why split | ECDSA fits P-256 arithmetic naturally | SHA/bit operations are ~5× cheaper over a binary field |

The two circuits are linked by a **MAC** over the shared values `e / dpkx / dpky`. Before committing, the prover
commits to its own MAC key half `a_p` and those values, while `a_v` is **derived from the transcript after commit**,
so it cannot put different values into the two circuits (Schwartz–Zippel, forgery probability ≤ 2⁻¹²⁸).
`e2` is a public input to both circuits. (Equivalent to mdoc `mdoc_zk.cc`'s `generate_mac_key`/`compute_macs`.)

Measurements (3 attributes, split): prove ≈ 1.6–2.0s, bundle ≈ 386KB (sig 194 + hash 192). The monolithic
single Fp256 (`sdjwt_full`) is ≈ 13s, so the split is ~8× faster.

---

## 4. What it can / cannot do

| ✅ Can | ❌ Cannot (limitations) |
|---|---|
| Selectively disclose N attributes (string/number/boolean/date) | **value predicates / range proofs**: cannot prove "age≥18" from a date of birth. `age_over_18` works only because it is a boolean the issuer pre-inserted |
| Prove issuer signature validity (signature hidden) | value comparison/arithmetic — the circuit only checks **value equality** |
| Prove holder binding (KB) (key and signature hidden) | check **revocation/status** |
| Prove `now≤exp` (exp value hidden) | **nbf (not-before)** — only the exp upper bound |
| Match vct·nonce·aud against verifier values | **alg agility** — ES256/P-256/SHA-256 hardcoded |
| Hide remaining claims, raw text, salt, signature | **anonymous issuer** is impossible — the verifier must know pkX,pkY |
| Prevent replay/audience (nonce/aud binding) | cross-credential predicates |
| Fixed-size proof (privacy uniformity) | **which attributes and how many** are disclosed is exposed (a circuit is compiled per N) |
| | nested values are disclosed wholesale (no partial selective disclosure) |

---

## 5. Comparison with mdoc (original, verified)

| Item | mdoc (longfellow original) | SD-JWT-VC (this work) |
|---|---|---|
| Format | ISO 18013-5 (CBOR) | SD-JWT-VC (JSON/base64url) |
| Disclosure unit | `IssuerSignedItem=[digestID,salt,id,value]` | `Disclosure=base64url([salt,name,value])` |
| Signed digest set | MSO `valueDigests` | payload `_sd` |
| Issuer signature | ECDSA P-256 over MSO | ECDSA P-256 over header.payload |
| Holder binding | device signature **over session transcript** (public `htr`) | KB-JWT signature + **nonce/aud public input** |
| Replay prevention | bound to transcript (verifier handover) | bound to nonce/aud (only the mechanism differs) |
| Validity period | `validFrom ≤ now ≤ validUntil` | `now ≤ exp` only (no nbf) |
| Type identification | doctype | vct (in-circuit check) |
| Architecture | 2 circuits (Fp256+GF2¹²⁸)+MAC | **same (ported)** |
| Public API | yes (`run_mdoc_prover/verifier`) | none (experimental CLI) |
| Maturity | production·thorough review·external audit | research·hardening after review |

The biggest semantic difference: mdoc binds the device signature to the **session transcript** (including the
verifier's ephemeral key), giving strong session binding. This implementation achieves the same goal with nonce/aud,
but the binding target differs (entire transcript vs nonce/aud fields). Also, mdoc checks both the upper and lower bounds of the validity period.

---

## 6. Free-index soundness (current state)

The circuit points into a buffer using a **private index** supplied by the host and checks only the bytes at that
position. For each index, the **safety rationale** for "can it point somewhere wrong and prove a falsehood?" is stated.

Terminology:
- **Literal anchor**: the check pattern includes a JSON key (e.g. `"vct":"`), so it passes only when the
  position is the real field → the index is trivially pinned.
- **Value anchor**: the extracted bytes must equal a value attested elsewhere (MAC-linked dpk, etc.) to pass.
- **Hash attestation**: the extracted 32 bytes must equal `SHA(witness)` to pass → pointing somewhere wrong makes
  the target a value the prover cannot choose, so passing would require **breaking SHA preimage/collision** (impossible).

| Index | Points to | Safety rationale | Assumption relied on | Safe? |
|---|---|---|---|:---:|
| `payload_ind/len` | payload region within preimage | indirect — vct/cnf/nonce are read from `dec` and forced | mandatory vct check | ✅ |
| `exp_idx` | decoded payload | **literal** `"exp":` + 10-digit + delimiter | none | ✅ |
| `vct_idx` | decoded payload | **literal** public pattern `"vct":"…"` | none | ✅ |
| `cnf_x_idx`·`cnf_y_idx` | decoded payload | **value** = must match MAC-linked `dpkx/dpky` | dpk value uniqueness | ✅ |
| `nonce_idx`·`aud_idx` | KB payload | **literal** public pattern `"nonce":"…"`/`"aud":"…"` | none | ✅ |
| `sd_idx` (per slot) | decoded payload (`_sd`) | **hash** base64decode(window)==`SHA(disclosure)` | SHA preimage/collision resistance | ✅ |
| `disc_shift` (per slot) | disclosure plaintext | pattern `","…",value]` (value pinned by leading `","` + trailing `]`) | salt randomness | ✅ |
| `disc_in_pres` (per slot) | presented bundle | **value** = must match membership-verified disclosure bytes | none | ✅ |
| `kb_pl_ind/len` | KB preimage | indirect — nonce/aud/sd_hash are read from `kbdec` and forced | nonce/aud check | ✅ |
| `sd_hash_idx` | KB payload | **hash** extracted 32B == `SHA(presented)` | SHA preimage resistance | ✅ |

**Verdict**: all free indices are safe. The safety rationales fall into two classes — (a) those **trivially** pinned by a
literal/value anchor, and (b) those safe by **relying on SHA preimage/collision resistance** like `sd_idx`·`sd_hash_idx`
(pointing somewhere wrong makes it impossible for the prover to satisfy), plus
`disc_shift` which relies on salt randomness. These are all standard cryptographic assumptions and do not break
soundness in the current implementation.

> ℹ️ Comparison: in the past, `exp_idx` had neither an anchor nor digit validation and used only lexicographic comparison,
> so pointing to a wrong position (letters > digits) made the check **easier**, allowing expiry bypass (§7-#1). In contrast, the above `sd_idx`/
> `sd_hash_idx` become **impossible** when pointed wrong, so they are safe — "does a wrong
> index make the check easier or harder" is the dividing line for safety.

---

## 7. Security hardening history

Items found and fixed during review.

**#1 exp validity-period bypass (soundness bug → fixed)**
- Symptom: `exp_idx` was an anchorless witness and the comparison was lexicographic (ASCII letters > digits), so a
  malicious prover pointing `exp_idx` at the letters region made `now≤ed` always true → an **expired token gets ACCEPTed**.
  Demonstrated with a PoC (`EVIL_EXP=1`).
- Fix: validate `"exp":` literal anchor + 10 digits + delimiter (`,`/`}`) before `now≤exp`.
  Applied identically to all three circuits, invalidating the circuit cache geo tag. Pinned with an adversarial regression test
  (split demo `[3b]`, `EVIL_EXP` → REJECT).

**#2 KB freshness / audience (functional gap → added)**
- Symptom: only `e2` (KB hash) was recomputed from the token, and nonce/aud were not matched against the verifier
  challenge, failing to prevent replay/audience confusion (mdoc binds the device signature to the public transcript).
- Fix: add nonce/aud as public inputs, matched in the KB payload via `"nonce":"`/`"aud":"` literal
  anchors (same as vct). Applied to all three circuits, with issuer `KB_NONCE`/`KB_AUD` env support.
  split demo `[6]`: automatically verifies fresh nonce ACCEPT / replayed nonce REJECT. With this, the sd_hash
  binding finally achieves its replay-prevention purpose together with the nonce.

Verification: all three binaries (hash/split/full) ACCEPT correctly, and REJECT on exp·nonce·aud mismatch.
All split/monolith demos green (valid / expired / adversarial-exp / tamper / big / freshness).

---

## 8. Threat model (current assumptions)

- **Trust**: the issuer is honest (signs correct disclosures). The verifier is honest (verifies per code,
  selects public inputs correctly). The public key pkX/pkY is trusted in advance by the verifier.
- **Adversary**: the prover (holder) — attempts to pass a false statement to an honest verifier. Soundness must
  hold in this model (§6; §7-#1 was precisely a bug in this model).
- **Replay/relay**: prevented by nonce/aud + KB signature, under the assumption that the verifier picks a **fresh nonce per session**.
  The nonce is plaintext in the KB payload (a value that need not be hidden).
- **Unlinkability**: a fresh proof per presentation. However, the kinds and count (N) of disclosed attributes and
  the disclosed values themselves are exposed.

---

## 9. Remaining items / limitations

- **#3 (this document)**: free-index safety table — done (§6). All indices ✅, rationale stated.
- alg fixed (ES256/P-256/SHA-256), nbf not checked, exp assumed to be 10 digits.
- Host parsing assumes canonical JSON (no whitespace, specific keys, first match) — robustness against real-world token
  format variations is a separate task.
- revocation/status, W3C VC, public API/Node bindings, and single-bundle serialization cleanup are unimplemented.
- The demo nonce takes the form "the verifier picks it and passes it to the issuer" (in practice, a verifier→holder challenge round-trip).

---

## 10. File map (`playground/`)

| File | Role |
|---|---|
| `native/sdjwt_split.cc` | ⭐ **flagship** — 2 circuits (Fp256 sig + GF2¹²⁸ hash) + MAC, present+verify |
| `native/sdjwt_full.cc` | monolithic single Fp256 circuit (same statement, slower but simpler) |
| `native/sdjwt_hash.cc` | standalone hash-circuit test binary (shares circuit/cache with split) |
| `native/sdjwt_sig.cc` | standalone signature circuit |
| `native/sdjwt_zk.cc` | M3 prototype (exp+membership+structural, compiler backend) |
| `native/sdjwt_eval.cc` | M2/M4 plaintext eval harness (logic verification before ZK) |
| `native/jwt_cli.cc` | drives longfellow's experimental JWT substring circuit (string attributes only) |
| `tools/gen-sdjwt.mjs` | real ES256 SD-JWT-VC issuer (`KB_NONCE`/`KB_AUD`/`BIG` env) |
| `src/decode-sdjwt.js` | dependency-free plaintext reference verifier (spec for what the circuit does) |
| `src/demo-sdjwt-split.js` | split demo (valid/expired/adversarial/tamper/big/freshness) |
| `src/demo-sdjwt-zk.js` | monolith demo |
| `SDJWT_PLAN.md` | design document (Approach C, milestones M1~M9) |

Circuit capacities (fixed, clear error on overflow): `kMaxSHA=32` (payload 2KB), `KBB=6`, `PB=40` (presented
2.5KB), `MAXB=4` (disclosure 256B), `MAXPAT=160`, `MAXVCT=128`, `MAXNONCE=64`, `MAXAUD=128`,
`LOGM=12`. Compiled circuits are zstd-cached by geometry tag (`circuits-cache/`).

---

## 11. Build · Run

```bash
cd playground
pnpm run build:native        # build C++ library + binaries (first time only)
pnpm run demo:sdjwt-split    # ⭐ two-circuit demo: issue→present→verify + negative tests
pnpm run demo:sdjwt-zk       # monolith demo

# Direct call: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud>
native/sdjwt_split fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "given_name,age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example
```

---

## 12. Conclusion

This project faithfully ports Longfellow-ZK's **mdoc selective-disclosure ZK philosophy (membership reduction) and its
two-circuit+MAC architecture** to **standard SD-JWT-VC**. It handles all value types + validity period + Key
Binding + sd_hash + **nonce/aud freshness** + multiple attributes without parsing, and shortens prove by ~8× using the same
split architecture as mdoc.

The exp soundness bug and KB freshness gap found during review were fixed (§7), and the safety rationale for every
free index was stated (§6). The cryptographic core (membership·MAC split) is borrowed from longfellow, and the novelty of
this work is the **sound adaptation to the `_sd` structure + structural disclosure
equality + exp/vct/nonce/aud anchor checks**. It currently approaches mdoc parity, but alg agility·
nbf·revocation·public API remain unimplemented.
