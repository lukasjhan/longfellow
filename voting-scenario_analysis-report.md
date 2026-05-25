# Anonymous One-Person-One-Vote — Scenario Report

> Target: `playground/` — an end-to-end voting scenario built on the **blind pseudonym nullifier** (both mdoc and SD-JWT-VC).
> Location: `/home/unknown/longfellow/playground`
> Date: 2026-05-25 · Status: working demo
> Base: builds on the blind nullifier work — [`mdoc-nullifier_analysis-report.md`](mdoc-nullifier_analysis-report.md) §9 and [`sd-jwt-nullifier_analysis-report.md`](sd-jwt-nullifier_analysis-report.md) §10. The CI/DI / nullifier construction and blind-issuance soundness live there; this report is about the **scenario** that uses them.

---

## 1. The scenario

A voter goes to a polling station and proves, **anonymously**, that they are eligible — **adult** and a **resident of this district** — and that they have **not voted before in this election**, then casts a ballot. Concretely, in one zero-knowledge proof the wallet shows:

- `age_over_18 == true` — eligible (adult)
- `resident_city == "Seoul"` — eligible (lives in the district)
- a **DI nullifier** scoped to this election = `SHA256(secret ‖ SHA256(election_id))`

revealing nothing else — not the name, date of birth, issuer signature, the secret, or any other claim. The election commission (EC) keeps a set of seen nullifiers: the **first** vote registers the nullifier and is counted; a **second** vote produces the **same** nullifier and is rejected → **one person, one vote**, with the voter never identified.

Two properties make this stronger than a classic credential check:
- **Blind issuance** — the issuer committed `C = SHA256(secret ‖ blind)` and *never learned the secret*, so not even the issuer/EC can compute the voter's nullifier for any scope (no central de-anonymization, unlike CI/DI).
- **Per-election scope** — a different election uses a different nullifier context, so a voter is **unlinkable across elections**.

---

## 2. Requirements → where each is enforced

The scenario has five requirements. Crucially, some are **in zero-knowledge (the circuit)** and some are ordinary **application logic** — knowing which is which is the point.

| # | Requirement | Enforced by | In ZK? |
|---|---|---|:---:|
| A | adult (`age_over_18==true`) | credential attribute, proven authentic | ✅ circuit |
| B | district (`resident_city=="Seoul"`) | credential attribute, proven authentic | ✅ circuit |
| C | DI nullifier scoped to the election | `SHA(secret ‖ SHA(election_id))` | ✅ circuit |
| D | one vote per person (double-vote reject) | EC's **seen-nullifier set** | ❌ app |
| E | only the EC may request (third-party reject) | wallet verifies the **signed request** (RP auth) | ❌ app |

> A/B/C are the ZK part — the wallet *proves* them and the EC cannot forge or de-anonymize. D/E are normal app logic, exactly as in OID4VP: the verifier keeps state (seen nullifiers) and authenticates itself to the wallet with a signed request. ZK is not magic glue; it secures *what is shown*, while the surrounding protocol secures *who asks* and *what was already seen*.

---

## 3. Flow

```
issuer ──(blind)──▶ wallet            EC keeps: seen-nullifier set + its signing key
   commits C, never                       │
   learns secret                          │ 1) signed presentation request (nonce, district, election_id)
                                          ▼
   wallet ── verify request signature against its trust list (= EC key) ──▶ ok? else REJECT
        │
        │ 2) ZK present: age_over_18=true + resident_city=Seoul + nullifier(election)
        ▼
   EC ── verify proof ──▶ authentic? ── nullifier ∈ seen? ──▶ REJECT (double vote)
                                       └ new ─▶ register + COUNT
```

---

## 4. Two implementations

| | mdoc (`scenario-voting.js`) | SD-JWT-VC (`scenario-voting-sdjwt.js`) |
|---|---|---|
| Credential | real ISO 18013-5 mdoc (`mdoc_null_blind`) | real SD-JWT-VC (`sdjwt_null_blind`) |
| Eligibility attrs | `RequestedAttribute` (age_over_18, resident_city) | disclosed claims (age_over_18, resident_city) |
| Value handling | **assert** (verifier states the value, §5) | **disclose** (holder reveals the value, §5) |
| Presentation binding | session transcript | **KB-JWT nonce/aud verified in-circuit** |
| Nullifier | `SHA(secret ‖ SHA(election))`, in the GF(2¹²⁸) hash circuit | same |
| Measured (2 attrs) | prove ≈ 1.0 s, verify ≈ 0.4 s, bundle ≈ 344 KB | prove ≈ 2.0 s, verify ≈ 0.75 s, bundle ≈ 391 KB |

Both reuse their existing blind nullifier circuit unchanged; the scenario only adds **app logic** (the seen-nullifier set, the signed request via `jose`). The mdoc binary gained comma-separated multi-attribute disclosure (the circuit already supported N attributes); the SD-JWT binary already supported multiple claims.

---

## 5. Value handling: assert vs disclose

The two demos look different in how the *value* of an attribute (e.g. the city) is checked. This is **a style choice, not a format limitation** — both styles are possible in both formats, because the value is a **public input** to the circuit either way (so neither bakes the value into the circuit; see the caching note below).

| | **① assert / match** (mdoc demo) | **② disclose** (SD-JWT demo) |
|---|---|---|
| Who supplies the value | the **verifier** ("is it == Seoul?") | the **holder** (reveals its value) |
| Circuit proves | `credential_value == verifier_value` | `disclosed_value is issuer-authentic` |
| Outcome | ACCEPT (matches) / **proof fails** (mismatch) | ACCEPT + verifier **reads** the value |
| On mismatch | proof just fails — the real value stays hidden | the real value is revealed |
| Policy decision | inside the circuit | in the verifier's app |

Why the demos differ: mdoc follows longfellow's public `RequestedAttribute{id, cbor_value}` API, which is assert-style; the SD-JWT demo follows SD-JWT's native selective-disclosure model, which is disclose-style. Either format could do either.

**Impact** (the only material differences):
- **Privacy — only on mismatch (the `==` caveat).** On a **match**, assert and disclose are equivalent: the required value sits in the public `pattern` either way, so on success the verifier learns it regardless. Assert's *only* edge for equality is on a **mismatch** (the actual value stays hidden). The real "prove without revealing" payoff appears only with predicates that leak less than the value *even on success* — **range** (`age ≥ 18` from a hidden DOB), **set membership** (`city ∈ {…}`), brackets — which the current circuits do **not** implement (equality only; see the SD-JWT base report `sd-jwt-longfellow-zk_analysis-report.md` §4).
- **Flexibility.** Disclose lets the verifier apply *any* policy on the revealed value (ranges, set membership) with no circuit change; assert tests one specific value.
- **Trust boundary.** Assert bakes the requirement into the proof (a buggy verifier still can't accept a wrong value); disclose relies on the verifier's policy code being correct.
- **Caching / performance — identical.** In both, the value is a public input, so changing it (Seoul→Busan, true→false) **does not rebuild the circuit**; the circuit is cached per *attribute count*, not per value. (Measured: Seoul and Busan presentations load the same cache in ~0.25 s.)

> Address forgery is prevented in both: in mdoc, requesting `Busan` against a `Seoul` credential makes the proof unsatisfiable (REJECT); in SD-JWT, the holder can only disclose its authentic `Seoul`, so a Busan-district verifier's policy rejects it. The holder cannot prove a city it was not issued.

### 5.1 SD-JWT can do assert too (no circuit change)

To make the "both styles in both formats" claim concrete, the SD-JWT binary supports **both modes** via the claim syntax: `name` (disclose) vs `name=<value>` (assert). This is a **host-only change** — the circuit always asserts `holder disclosure suffix == public pattern`; disclose fills that public pattern from the holder's value, assert fills it from the verifier's required value. Same compiled circuit, same cache, no rebuild.

`scenario-voting-sdjwt-assert.js` runs the assert version: the EC states the required values (`age_over_18==true`, `resident_city=="Seoul"`) in its request, and the wallet proves the credential matches **without revealing the values**. The decisive difference shows in the wrong-district step: a Seoul resident at a Busan poll is **rejected without the EC ever learning the real city** (the disclose version reveals `Seoul`). The binary prints `asserted: <name> == <value>` (the required value the verifier chose), never the holder's actual value.

---

## 6. Security properties (per step)

| Step | What it defends against | Mechanism |
|---|---|---|
| eligibility (A/B) | ineligible voter (minor / non-resident) | attribute authenticity via issuer signature (membership in the signed digest set) |
| nullifier (C) | — | deterministic per (secret, election); hides identity |
| double vote (D) | voting twice | same secret ⇒ same nullifier ⇒ EC's seen-set rejects the second |
| address forgery | claiming another district | value bound to the credential (assert fails / disclose reveals authentic) |
| third party (E) | a data broker harvesting the nullifier | wallet answers only requests signed by a trusted requester (the EC) |
| issuer tracing | EC/issuer linking voters | **blind issuance** — the issuer never saw the secret, so it cannot compute the nullifier |
| cross-election linking | correlating a voter across elections | per-election nullifier scope (different context ⇒ different, unlinkable nullifier) |
| replay (SD-JWT) | replaying a captured presentation | KB-JWT bound to the EC's nonce/aud, verified in-circuit |

---

## 7. Limitations / demo simplifications

- **Double-vote set and request authentication are app logic**, not ZK — by design. A real deployment uses a durable nullifier store and a proper RP-authentication / OID4VP signed-request flow; the demo models them in-process (`Set`, a single trusted EC key, `jose`).
- **Issuance-time well-formedness** (the issuer should require the holder to prove `C` is a single, well-shaped commitment) is omitted — same simplification as the blind nullifier reports (mdoc §9.5 / SD-JWT §10.6). The presentation ZK is complete.
- **SD-JWT KB nonce is baked at issuance** in the demo (`KB_NONCE`/`KB_AUD`); a real flow re-creates the KB-JWT per presentation with the verifier's fresh nonce. The scenario issues with the EC's nonce so the in-circuit binding is meaningful.
- **Sybil = one credential per person** still relies on issuer policy (one `pseudonym_commitment` per real identity), as with CI/DI — not enforceable in-circuit.
- **The issuer public key is still revealed** by the credential proof (an inference matter, not a linkability one — see the base reports' privacy sections).

---

## 8. Files / run

| File | Role |
|---|---|
| `src/scenario-voting.js` | `pnpm run scenario:voting` — the mdoc scenario (assert-style values) |
| `src/scenario-voting-sdjwt.js` | `pnpm run scenario:voting-sdjwt` — the SD-JWT-VC scenario (disclose-style + KB nonce/aud) |
| `src/scenario-voting-sdjwt-assert.js` | `pnpm run scenario:voting-sdjwt-assert` — SD-JWT-VC **assert-style** (values not revealed; same circuit, §5.1) |
| `native/mdoc_null_blind.cc` | blind mdoc nullifier circuit (multi-attribute) |
| `native/sdjwt_null_blind.cc` | blind SD-JWT nullifier circuit (prints disclosed claim values) |
| `tools/gen-mdoc-blind.mjs` / `tools/gen-sdjwt-blind.mjs` | blind issuers (commit C; add `resident_city`) |

```bash
cd playground
pnpm run build:native          # once
pnpm run scenario:voting       # mdoc:    issue → request → vote → double-vote/forgery/third-party reject
pnpm run scenario:voting-sdjwt # SD-JWT:  same, plus in-circuit KB nonce/aud binding
pnpm run scenario:voting-sdjwt-assert # SD-JWT assert: prove the values WITHOUT revealing them (§5.1)
```

Each scenario runs: [1] blind issue → [2] EC signs a presentation request, wallet verifies it → [3] first vote ACCEPT (eligibility + nullifier registered) → [4] double vote REJECT (same nullifier) → [5] wrong district REJECT (value bound to the credential) → [6] third-party request REJECT (wallet RP authentication).

---

## 9. Conclusion

The scenario shows the blind pseudonym nullifier doing real work: an **anonymous, one-person-one-vote** flow with cryptographic eligibility (adult + district), cross-election unlinkability, and no central party — not even the issuer — able to trace a voter. It also cleanly separates the **ZK layer** (eligibility, nullifier) from the **app layer** (double-vote set, request authentication), and surfaces the **assert-vs-disclose** value-handling choice that applies to both credential formats.
