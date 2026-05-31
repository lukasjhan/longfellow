# §4 Construction — 영문 초안 (v1)

> 논문 산문 초안(영문). 모든 메커니즘은 실제 코드(`playground/native/`)에 근거: `sdjwt_common.h`(seam), `sdjwt_null_blind.cc`(blind nullifier), `sdjwt_revoc_split.cc`(revocation), `tools/gen-sdjwt-blind.mjs`(발급). 관계 $\mathcal{R}$·정리 번호는 §5와 교차참조.
> **확정 사항:** commitment = **SHA-256 해시 commitment**(Pedersen 아님) → 새 대수 가정 0, longfellow의 "SHA-256만" 가정 안에 머무름.

---

## §4 Construction

### 4.1 Overview

Our prover convinces a verifier, in transparent zero-knowledge, that it holds an issuer-signed standard credential satisfying a public statement, while revealing only the disclosed attributes, the truth of a predicate, a per-context nullifier, and an epoch-pinned non-revocation fact. We build on longfellow's transparent argument (Ligero + sumcheck, SHA-256 only) and its *split-circuit* architecture, which we (i) drive from the **IETF SD-JWT VC** wire format, (ii) extend with an **issuer-unlinkable blind nullifier**, and (iii) combine with **signed-range non-membership revocation**—the same three feature blocks running unmodified over ISO mdoc through a shared seam (§4.5). Throughout, every gadget is expressed in SHA-256 and P-256 ECDSA, so no cryptographic assumption beyond longfellow's is introduced.

### 4.2 Split-circuit seam

Proving ECDSA and SHA-256 in a single field is wasteful: ECDSA arithmetic lives in the P-256 base field $\mathbb{F}_p$, whereas SHA-256's bit operations are cheap over $\mathrm{GF}(2^{128})$. Following longfellow, we use **two circuits in their native fields**—a *signature circuit* over $\mathbb{F}_p$ that verifies the issuer's ECDSA signature, and a *hash circuit* over $\mathrm{GF}(2^{128})$ that recomputes the SHA-256 structure of the credential—**linked by a MAC** over the values they share. The shared values are $e$ (the SHA digest the issuer signs), $\mathit{dpk}_x,\mathit{dpk}_y$ (the holder-binding key coordinates), and, when revocation is enabled, $e_{\mathrm{span}}$ (§4.4).

Concretely (`sdjwt_common.h`), the prover commits its half $a_p$ of a $\mathrm{GF}(2^{128})$ MAC key together with the shared values *before* the Fiat–Shamir challenge reveals the verifier's half $a_v$; the resulting MACs are **public inputs to both circuits**. By Schwartz–Zippel, a prover cannot feed two different values of $e$ (or $\mathit{dpk}$, or $e_{\mathrm{span}}$) to the two circuits except with negligible probability. This seam is the single source of truth shared by all feature configurations (`split` / `null_split` / `null_blind` / `revoc_split`); each feature is an additional block over the same seam, which is why the construction generalizes across formats and features without bespoke glue.

### 4.3 SD-JWT VC front-end

An SD-JWT VC is a JWS over a payload containing `_sd`, an array of disclosure digests, plus a holder-binding key in `cnf`; each *disclosure* is `base64url(JSON([salt, name, value]))` and is bound by its digest $\mathsf{SHA256}(\text{disclosure})\in\verb|_sd|$. The signature circuit verifies the issuer's ES256 signature over the payload digest $e$; the hash circuit recomputes, in-circuit: (a) the SD-JWT structure and $e$, (b) for each presented disclosure, its base64url decoding and membership of its digest in `_sd`, and (c) the key-binding JWT digest (`sd_hash`) tying the presentation to the verifier's `nonce`/`aud`.

Each requested claim is handled in one of two modes: **disclose**—the attribute value is matched against a public pattern and revealed—or **assert**—the value remains a hidden witness and only a **predicate** over it (range, equality, set membership; e.g. `age_over_18`, `resident_city = "Seoul"`) is enforced in-circuit. The holder-binding key is verified through the seam but never revealed, closing it as a linkage channel.

### 4.4 Issuer-unlinkable blind nullifier

This is our central construction. The goal is a per-context tag $N$ that (i) is unique per credential within a context, (ii) is unlinkable across contexts, and (iii) cannot be traced even by the issuer.

**Issuance (blind).** The *holder* samples a 256-bit seed $s$ and a 256-bit blinding factor $r$ and forms a hash commitment
$$C = \mathsf{SHA256}(s \,\|\, r).$$
The issuer signs $C$ as an ordinary disclosure, `pseudonym_commitment = base64url(C)`, included in `_sd` like any other attribute (`gen-sdjwt-blind.mjs`). The issuer therefore commits to $C$—the holder cannot later swap it—**yet never observes $s$ or $r$**.

**Presentation.** For a verifier-chosen context the prover takes $\mathit{ctx\_hash}=\mathsf{SHA256}(\mathit{ctx})$ as a public input and proves, entirely in zero-knowledge (`sdjwt_null_blind.cc`):
1. **membership** — $\mathsf{SHA256}(\text{commitment disclosure})\in\verb|_sd|$ (the commitment is issuer-committed);
2. **structure** — the disclosure decodes to `["<salt>","pseudonym_commitment","<C>"]`;
3. **decoding** — the base64url value decodes to the 32-byte $C$;
4. **opening** — $\mathsf{SHA256}(s\,\|\,r)$ equals $C$ (the held $(s,r)$ open the committed value);
5. **nullifier** — $N=\mathsf{SHA256}(s\,\|\,\mathit{ctx\_hash})$, computed from the **same $s$ wires** as the opening.

The only public outputs of this block are $\mathit{ctx\_hash}$ and $N$; the commitment $C$, the disclosure, the seed $s$, and the blind $r$ all remain hidden witnesses. Sharing the $s$ wires between steps 4 and 5 is what binds the value the issuer committed to exactly the value inside the nullifier—without this, a holder could present a nullifier from a seed unrelated to its credential.

**Why this is issuer-untraceable.** The issuer's entire view of the seed is the hash commitment $C=\mathsf{SHA256}(s\|r)$; with a 256-bit random $r$ and SHA-256 modeled as a random oracle, $C$ is hiding and reveals nothing about $s$. The nullifier $N=\mathsf{SHA256}(s\|\mathit{ctx\_hash})$ is then pseudorandom from the issuer's view, so it cannot link $N$ to the credential it issued (formalized as Definition 6 / Theorem 6 in §5). Because both the commitment and the nullifier are SHA-256, the blind nullifier adds **no assumption** beyond longfellow's—hiding rests on the random-oracle heuristic already used for Fiat–Shamir, and binding on SHA-256 collision resistance. This is the property that distinguishes our nullifier from PLUME/Semaphore (no issuer-signed credential), ARC (privately verifiable; issuer is a co-verifier), and e-cash serial numbers (de-anonymize on reuse); see §8.

### 4.5 Signed-range non-membership revocation

We adopt longfellow's signed-range mechanism (`MdocRevocationSpan`) and extend it to SD-JWT VC; we claim the *extension and integration*, not the mechanism. A revocation authority (CRA)—possibly the issuer—sorts the revoked identifiers and signs the **open gaps between adjacent revoked ids** as spans $\mathit{epoch}\,\|\,\ell\,\|\,r$. The credential carries a hidden `revocation_id` (its `_sd` digest, $\mathit{rev\_id}$, is issuer-committed). To prove non-revocation the holder presents one CRA-signed span with $\ell < \mathit{rev\_id} < r$.

In-circuit (`sdjwt_revoc_split.cc`): the CRA's ECDSA signature over $e_{\mathrm{span}}=\mathsf{SHA256}(\mathit{epoch}\|\ell\|r)$ is verified in the signature circuit; $e_{\mathrm{span}}$ is bound to the hash circuit by a **fourth MAC** ($\mathit{mac\_es}$) over the seam; $\mathit{epoch}$ is a public input pinning freshness; and the two strict inequalities $\ell<\mathit{rev\_id}<r$ are checked bitwise. The proof size is **constant regardless of the revocation-list size**, and reveals neither $\mathit{rev\_id}$ nor which gap was used (Theorems 7–8). Because the CRA signs only gaps strictly between revoked ids, no signed span can contain a revoked $\mathit{rev\_id}$—revocation soundness reduces to CRA-signature unforgeability.

### 4.6 Unification across SD-JWT VC and ISO mdoc

The seam of §4.2 and the feature blocks of §4.4–4.5 are **format-agnostic**: they operate on the shared values ($e$, $\mathit{dpk}$, $e_{\mathrm{span}}$) and on issuer-committed digests, not on the surface encoding. Only the *front-end* differs—SD-JWT VC parses a JWS, base64url disclosures, and `_sd` membership (§4.3), whereas mdoc parses CBOR, the Mobile Security Object, and its salted device-namespace hashes. Consequently the blind-nullifier and revocation blocks are identical across the two formats (cf. `sdjwt_null_blind.cc` vs. `mdoc_null_blind.cc`, `sdjwt_revoc_split.cc` vs. `mdoc_revoc_split.cc`), and a single shared header (`sdjwt_common.h`) is the source of truth for both. This is what lets us claim one framework spanning *both* deployed credential formats rather than a point solution.

### 4.7 The full presentation

A complete presentation bundles the signature- and hash-circuit proofs (and, with revocation, the CRA span proof), with the public statement $x=(\mathit{ipk},\mathit{ctx\_hash},N,D,\phi,\mathit{rinfo})$ of §5.2. It simultaneously establishes: a valid issuer signature over an unmodified standard credential; correct selective disclosure of $D$; satisfaction of the predicate $\phi$; a well-formed issuer-untraceable nullifier $N$ for the context; and epoch-fresh non-revocation—exactly clauses 1–6 of the relation $\mathcal{R}$, with no trusted setup.

---

## 작성 메모
- 그림 1개 권장: split seam(sig 회로 $\mathbb{F}_p$ ⊕ hash 회로 $\mathrm{GF}(2^{128})$, MAC로 $e/\mathit{dpk}/e_{\mathrm{span}}$ 링크) + feature 블록 3개. §4.2 이해도 급상승.
- §4.4 commitment 인스턴스 확정(SHA-256 hash-commit) → §5.4의 "COM 구체화 미정" 메모는 해소됨(아래 security 문서도 갱신).
- gate/constraint 수·SHA 블록 수(COMMB=2, NULLB=2, CTXLEN=32 등)는 §7 Evaluation 표에서 실측치로 보강.
- mdoc front-end 세부(MSO/CBOR)는 `mdoc_null_blind.cc`에서 한 번 더 확인 후 §4.6 각주 보강 가능.
- 정직성 유지: §4.5 첫 문장에서 revocation 메커니즘은 longfellow 것임을 명시(§8·§6 리스크와 일관).
