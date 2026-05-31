# Design notes & reviewer rationale

Deliberate design decisions and the reasoning behind them — kept here to keep the paper
internally consistent and to answer reviewers. Each entry: **what / why / where**, with
a paste-ready reviewer line where useful.

---

## 1. Notation: abstract primitives vs. concrete instantiation

**What.** The security analysis (§5) is stated over *abstract* primitives — a
hiding/binding commitment `Commit(s;r)` and a PRF/random-oracle nullifier
`H_nul(s,ctx)`. The construction (§4) gives the *concrete* SHA-256 instantiation:
`Commit(s;r) := SHA256(s‖r)` and `H_nul(s,ctx) := SHA256(s‖SHA256(ctx))`, where
`ctx_hash = SHA256(ctx)` is the in-circuit form of the context.

**Why.** Proof modularity. The theorems depend only on the primitives' properties
(hiding, binding, PRF/RO), not on SHA-256 specifically, so the analysis stays valid
under any compliant instantiation. The concrete SHA-256 choice is what keeps the whole
system within longfellow's single assumption — it adds **no new algebraic assumption**.

**Where.** Instantiation mapping stated in §5.1; cross-referenced at §4.4; the statement
`x` uses `ctx` in §4.7 and §5.2 (the circuit's public input is its hash `ctx_hash`).

**Reviewer line.** *The abstract (`Commit`, `H_nul`) vs. concrete (SHA-256) notation is
a deliberate proof-modularity choice: the proofs depend only on the primitives'
properties, while the construction fixes the SHA-256 instantiation. §5.1 now states the
mapping explicitly (`Commit(s;r):=SHA256(s‖r)`, `H_nul(s,ctx):=SHA256(s‖SHA256(ctx))`)
and the `ctx`/`ctx_hash` notation is unified across §4–§5.*

---

## 2. Device binding is verified in-circuit (anti-transfer)

**What.** A presentation verifies **two** ECDSA signatures — the issuer's over the
credential, and the holder's key-binding signature over `e2` under the device key `dpk`,
where `dpk` equals the issuer-attested key (`cnf` for SD-JWT VC, `deviceKey` for mdoc).

**Why.** The nullifier seed `s` is a *soft* (holder-sampled) secret, by design: the
device key is signed in cleartext in `cnf`, so a nullifier derived from it would be
issuer-traceable, and ECDSA is non-deterministic (no stable per-context tag). Anti-
transfer is therefore provided by **device binding**, not by where `s` lives: a valid
presentation requires the secure-element device key, so a leaked `s` alone is useless to
a third party.

**Where.** §4.3 (two ECDSA), §5.2 relation (device-binding clause), §4.6 Table.

**Reviewer line.** *Anti-transfer is enforced by in-circuit device binding (a holder
key-binding ECDSA under the issuer-attested `dpk`), not by the secrecy of `s`; the soft
seed exists precisely to give issuer-untraceability and a deterministic tag, which the
device key cannot.*

---

## 3. Nullifier uniqueness is per-credential (Sybil scope)

**What.** Nullifier uniqueness is *per credential*; one-per-person uniqueness relies on
the issuer issuing one credential per person.

**Why.** Blind issuance hides `s` from the issuer, so it cannot enforce one seed per
person. Issuance is an identified, out-of-band step the issuer already controls, so
"one credential per person" is a standard and reasonable assumption; under it,
per-credential = per-person.

**Where.** §3 goals ("Uniqueness scope and issuance assumption"); note after the
nullifier-uniqueness theorem in §5.

---

## 4. Revocation mechanism credited to longfellow

**What.** Signed-range non-membership revocation is longfellow's `MdocRevocationSpan`
mechanism; our contribution is its extension to SD-JWT VC and its integration.

**Why.** Correct attribution — we do not claim the revocation *mechanism* as novel.

**Where.** §4.5, §8, and Table 1 footnote *a*.
