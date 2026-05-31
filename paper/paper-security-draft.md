# §3 Threat Model + §5 Security Analysis — 영문 초안 (v1)

> 논문 산문 초안(영문). 정의/정리는 draft 수준의 형식성 — 제출 전 게임을 코드 수준으로 다듬을 것. 핵심은 **blind nullifier의 issuer-untraceability(Def 6 / Thm 6)** = C2의 무게중심.
> 표기: §4(Construction)에서 정의될 구체 회로를 여기서는 관계 $\mathcal{R}$로 추상화해 참조한다.

---

## §3 Threat Model and Security Goals

### 3.1 System model and parties

The system has three roles. An **issuer** $\mathcal{I}$ holds a signing key $(\mathit{isk},\mathit{ipk})$ and issues standard credentials (IETF SD-JWT VC or ISO mdoc) by signing a set of (salted) attribute hashes together with a holder-binding public key. A **holder** $\mathcal{H}$ stores a credential and acts as prover. A **verifier** (relying party) $\mathcal{V}$ checks a presentation against a public statement (disclosed attributes, a predicate $\phi$, a presentation context $\mathit{ctx}$, and current revocation information). Revocation information is published by a **certificate-revocation authority** $\mathcal{C}$ (which may coincide with $\mathcal{I}$) as signed *gaps* between adjacent revoked identifiers, following longfellow's `MdocRevocationSpan` mechanism.

A **presentation context** $\mathit{ctx}$ is a public string scoping a nullifier (e.g., an election identifier, a service-plus-epoch label). The nullifier is *per-context*: the same credential yields the same tag within a context (enabling one-per-context enforcement) and an unlinkable tag across contexts.

### 3.2 Trust and adversary model

- **No trusted setup.** The scheme is *transparent*: the only public parameters are a collision-resistant hash $H$ (instantiated with SHA-256 and modeled as a random oracle for Fiat–Shamir) and the public description of a commitment scheme. There is no common reference string and hence no toxic waste; soundness rests on no party having honestly discarded a trapdoor (cf. §3.5 of the prior-art notes). This is the central distinction from Groth16-based schemes (Crescent, zk-creds, zk-promises), whose soundness additionally requires the integrity of a circuit-specific setup.
- **Issuer.** Honest at issuance (signs only well-formed credentials) but is treated as an *adversary for unlinkability*: it may later collude with verifiers and use everything it observed at issuance, including the blind-nullifier commitments it signed, to attempt to trace presentations. The issuer's signing key is not compromised (otherwise unforgeability is vacuous).
- **Verifiers.** May be malicious and may collude with one another and with the issuer; they observe presentations and try to (a) link two presentations to one credential/holder, or (b) accept a presentation from a holder without a valid, non-revoked credential.
- **Holder.** A malicious holder tries to forge a presentation (no/expired/revoked credential), to satisfy a predicate it does not, or to present twice under one context with distinct nullifiers (nullifier forgery).
- Channels are confidential and the holder-binding key is held in a secure element; device binding is proven in zero knowledge and never revealed.

### 3.3 Security goals (informal)

1. **Completeness.** An honest holder with a valid, non-revoked credential satisfying the statement always convinces an honest verifier.
2. **Soundness / credential unforgeability.** No efficient adversary lacking a valid issuer signature on a credential consistent with the statement can produce an accepting presentation.
3. **Selective-disclosure zero-knowledge.** A presentation reveals nothing beyond the public statement (disclosed attributes, $\phi$'s truth, $\mathit{ctx}$, the nullifier, and the revocation predicate).
4. **Unlinkability.** Presentations across distinct contexts are mutually unlinkable, both to colluding verifiers (*verifier-unlinkability*) and to the issuer (*issuer-unlinkability*).
5. **Nullifier determinism & uniqueness.** Within a context, one credential yields exactly one nullifier (reuse is detectable), and distinct credentials yield distinct nullifiers except with negligible probability.
6. **Issuer-untraceability of the nullifier (★).** Even the issuer, who signed the blind-nullifier commitment, cannot link a presented nullifier to the credential that produced it.
7. **Revocation soundness & privacy.** A revoked credential cannot produce an accepting presentation; an accepting presentation reveals neither the revocation identifier nor which signed gap was used.

---

## §5 Security Analysis

### 5.1 Building blocks and assumptions

- **Issuer signature** $\mathsf{Sig}=(\mathsf{KGen},\mathsf{Sign},\mathsf{SigVer})$ over the standard credential structure (ECDSA-P256 in SD-JWT VC / mdoc), assumed **EUF-CMA** (ECDSA modeled in the GGM+ROM as standard).
- **Commitment** $\mathsf{COM}=(\mathsf{Commit},\mathsf{Open})$ for the blind-nullifier seed, assumed **computationally hiding** and **computationally binding**. *Instantiated as a SHA-256 hash commitment* $C=\mathsf{SHA256}(s\,\|\,r)$ with a 256-bit blind $r$ (§4.4): hiding holds in the ROM (the same heuristic used for Fiat–Shamir), binding by collision resistance — so $\mathsf{COM}$ adds **no assumption** beyond longfellow's.
- **Nullifier hash / PRF** $H_{\mathsf{nul}}$: a keyed function $N=H_{\mathsf{nul}}(s,\mathit{ctx})$ modeled as a **random oracle** (equivalently, a PRF keyed by the seed $s$).
- **Transparent argument** $\mathsf{NIZK}=(\mathsf{Prove},\mathsf{Ver})$ for $\mathcal{R}$ (Ligero + sumcheck, Fiat–Shamir in the ROM), assumed **knowledge-sound** and **zero-knowledge**. No setup.
- **CRA signature** for revocation gaps, EUF-CMA (instantiated with the same ECDSA, verified in-circuit).

### 5.2 The presentation relation

A presentation is a $\mathsf{NIZK}$ for the relation $\mathcal{R}$ on public statement
$x=(\mathit{ipk},\ \mathit{ctx},\ N,\ D,\ \phi,\ \mathit{rinfo})$
and witness
$w=(\mathit{cred},\ \sigma,\ s,\ r,\ A,\ \pi_{\mathrm{rev}})$,
where $D$ are disclosed attribute values, $A$ the full attribute set, and $\pi_{\mathrm{rev}}$ a revocation witness. $\mathcal{R}(x,w)=1$ iff **all** of the following hold:

1. $\mathsf{SigVer}(\mathit{ipk},\mathit{cred},\sigma)=1$ — valid issuer signature over the *unmodified standard* credential;
2. $\mathit{cred}$ commits to the blind-nullifier seed: a signed attribute equals $C=\mathsf{Commit}(s;r)$;
3. $N=H_{\mathsf{nul}}(s,\mathit{ctx})$ — nullifier well-formed;
4. $D$ is consistent with $\mathit{cred}$ (salted-hash / MSO disclosure correctness) and $A\supseteq D$;
5. $\phi(A)=1$ — predicate satisfied;
6. revocation: the credential's $\mathit{rev\_id}$ lies strictly inside a CRA-signed gap $(\ell,r)$ in $\mathit{rinfo}$, i.e. $\ell<\mathit{rev\_id}<r$ with a valid CRA signature over $(\mathit{epoch}\Vert\ell\Vert r)$.

Critically, the statement $x$ reveals **only** $N$ and $\mathit{ctx}$ (plus $D,\phi,\mathit{rinfo}$); the signature $\sigma$, the commitment $C$, the seed $s$, the opening $r$, the holder-binding key, $\mathit{rev\_id}$, and the chosen gap remain in the witness.

### 5.3 Definitions and theorems

We state each property as a game between a challenger and a PPT adversary $\mathcal{A}$; $\mathsf{negl}$ denotes a negligible function of the security parameter $\lambda$.

---

**Theorem 1 (Completeness).** *If $\mathit{cred}$ is validly issued, non-revoked, and satisfies $(D,\phi)$, then $\mathsf{Ver}$ accepts with probability $1-\mathsf{negl}(\lambda)$.*
*Proof.* Immediate from completeness of $\mathsf{NIZK}$: an honest witness satisfies clauses 1–6 of $\mathcal{R}$. $\square$

---

**Definition 2 (Credential soundness).** $\mathcal{A}$ is given $\mathit{ipk}$ and oracle access to $\mathsf{Issue}$ (recording the set $Q$ of issued credentials). $\mathcal{A}$ wins if it outputs $(x^\*,\pi^\*)$ with $\mathsf{Ver}(x^\*,\pi^\*)=1$ but no $\mathit{cred}\in Q$ both carries a valid signature and is consistent with $x^\*$ (disclosed attributes, predicate, non-revocation).

**Theorem 2.** *If $\mathsf{NIZK}$ is knowledge-sound, $\mathsf{Sig}$ is EUF-CMA, and $\mathsf{COM}$ is binding, then $\Pr[\mathcal{A}\text{ wins}]\le\mathsf{negl}(\lambda)$.*
*Proof sketch.* The knowledge extractor yields $w^\*=(\mathit{cred}^\*,\sigma^\*,s^\*,r^\*,\dots)$ with $\mathcal{R}(x^\*,w^\*)=1$. Clause 1 gives a valid $(\mathit{cred}^\*,\sigma^\*)$; if $\mathit{cred}^\*\notin Q$ this is an EUF-CMA forgery. Otherwise $\mathit{cred}^\*\in Q$, and consistency clauses 4–6 (bound to $\mathit{cred}^\*$ via the signature and, for the nullifier seed, via binding of $C$) contradict the winning condition. $\square$

---

**Definition 3 (Selective-disclosure ZK).** There is a simulator $\mathsf{Sim}$ such that for every PPT $\mathcal{A}$ and every valid $(x,w)$, $\mathcal{A}$ cannot distinguish $\mathsf{Prove}(x,w)$ from $\mathsf{Sim}(x)$.

**Theorem 3.** *Follows directly from zero-knowledge of $\mathsf{NIZK}$: the presentation is a single $\mathsf{NIZK}$ proof for $x$, so $\mathsf{Sim}$ is the argument's simulator. Hence a presentation leaks nothing beyond $x$.* $\square$

---

**Definition 4 (Verifier-unlinkability).** In a left-or-right game, $\mathcal{A}$ (colluding verifiers) chooses two non-revoked credentials $\mathit{cred}_0,\mathit{cred}_1$ that are *equivalent on the challenge statement* (same disclosed values $D$, same $\phi(A)$, and **distinct** challenge context $\mathit{ctx}^\*$ from any context either credential has been presented under). The challenger presents $\mathit{cred}_b$ for random $b$; $\mathcal{A}$ outputs $b'$. Advantage $=|\Pr[b'=b]-\tfrac12|$.

**Theorem 4.** *Advantage $\le\mathsf{negl}(\lambda)$ assuming $\mathsf{NIZK}$ is ZK, $\mathsf{COM}$ is hiding, and $H_{\mathsf{nul}}$ is a RO/PRF.*
*Proof sketch (hybrids).* (H0) real presentation of $\mathit{cred}_b$. (H1) replace the proof by $\mathsf{Sim}(x)$ — indistinguishable by ZK; now the only $b$-dependent part of the view is $x=(\dots,N_b,\mathit{ctx}^\*,D,\phi)$, and $D,\phi$ are equal by the equivalence restriction. (H2) replace $N_b=H_{\mathsf{nul}}(s_b,\mathit{ctx}^\*)$ by a uniform $N$: since $\mathit{ctx}^\*$ is fresh and $s_b$ is high-entropy and never otherwise exposed, RO/PRF security makes this indistinguishable. In H2 the view is independent of $b$. $\square$

*Remark.* Within the **same** context the same credential intentionally yields the same $N$ (that is what enables one-per-context enforcement); unlinkability is therefore defined across distinct contexts, matching the use case.

---

**Definition 5 (Nullifier determinism & uniqueness).** *(determinism)* $N=H_{\mathsf{nul}}(s,\mathit{ctx})$ is a deterministic function of $(s,\mathit{ctx})$, so any two accepting presentations of one credential under one context carry identical $N$. *(uniqueness)* For distinct seeds $s\ne s'$ and any $\mathit{ctx}$, $\Pr[H_{\mathsf{nul}}(s,\mathit{ctx})=H_{\mathsf{nul}}(s',\mathit{ctx})]\le\mathsf{negl}(\lambda)$.

**Theorem 5.** *Determinism is syntactic; uniqueness follows from collision resistance of $H_{\mathsf{nul}}$. Binding of $\mathsf{COM}$ ensures a holder cannot open $C$ to a second seed to obtain a different $N$ within a context (else, with Thm 2's extractor, a binding break).* $\square$

---

**Definition 6 (Issuer-untraceability of the blind nullifier — ★).** The adversary $\mathcal{A}$ *is the issuer*: it outputs $\mathit{ipk}$ and runs $q$ issuance sessions in which the honest holder samples $s_j,r_j$, sends $C_j=\mathsf{Commit}(s_j;r_j)$, and receives $\mathcal{A}$'s signature. $\mathcal{A}$ then names two successfully issued indices $i_0,i_1$ and a fresh context $\mathit{ctx}^\*$; the challenger picks $b\in\{0,1\}$ and returns a presentation of credential $i_b$ under $\mathit{ctx}^\*$ (in particular the nullifier $N_b=H_{\mathsf{nul}}(s_{i_b},\mathit{ctx}^\*)$). $\mathcal{A}$ outputs $b'$ and wins if $b'=b$. *Issuer-untraceability* holds if $|\Pr[b'=b]-\tfrac12|\le\mathsf{negl}(\lambda)$.

**Theorem 6.** *If $\mathsf{COM}$ is hiding, $H_{\mathsf{nul}}$ is a RO/PRF, and $\mathsf{NIZK}$ is ZK, the scheme is issuer-untraceable.*
*Proof sketch (hybrids).* (H0) real challenge presentation of $i_b$. (H1) replace the proof with $\mathsf{Sim}(x)$ (ZK); the issuer's $b$-dependent view is now $C_{i_0},C_{i_1}$ (from issuance) plus $N_b$ and $\mathit{ctx}^\*$. (H2) replace each issuance commitment $C_{i_0},C_{i_1}$ in $\mathcal{A}$'s view by commitments to independent dummy values — indistinguishable by **hiding** of $\mathsf{COM}$; now $\mathcal{A}$'s issuance view is independent of the true seeds $s_{i_0},s_{i_1}$. (H3) replace $N_b$ by a uniform value: because $\mathcal{A}$ never learns $s_{i_b}$ (it is information-theoretically/computationally hidden by $C_{i_b}$ after H2) and $\mathit{ctx}^\*$ is fresh, $\mathcal{A}$ cannot have queried the RO at $(s_{i_b},\mathit{ctx}^\*)$ except with negligible probability, so $N_b$ is pseudorandom. In H3 the entire view is independent of $b$. Summing the hybrid gaps bounds the advantage by $\mathsf{negl}(\lambda)$. $\square$

*Why prior nullifiers fail this game.* In **zk-creds** the clone-resistance tag is designed to *reveal* the holder identity on reuse (it would not survive even Def 4 across reuse). In **zk-promises** the serial number is a freshness token over a public commitment, not derived so the issuer cannot recompute it. In **PLUME/Semaphore** there is no issuer/commitment step at all (the seed is a self-held key, resp. a public leaf the admin knows), so Def 6 is either vacuous or trivially lost. In **ARC**, verification uses the issuer's secret key (private verifiability), so the issuer *is* a co-verifier and can recompute the tag. Our construction is, to our knowledge, the first to satisfy Def 6 while binding to an *unmodified, publicly verifiable* standard credential.

---

**Definition 7 (Revocation soundness).** $\mathcal{A}$ wins if it produces an accepting presentation whose extracted $\mathit{rev\_id}$ is in the revoked set $\mathsf{Rev}$ for the epoch in $\mathit{rinfo}$.

**Theorem 7.** *Assuming the CRA signature is EUF-CMA and $\mathsf{NIZK}$ is knowledge-sound, $\Pr[\mathcal{A}\text{ wins}]\le\mathsf{negl}(\lambda)$.*
*Proof sketch.* The extractor yields a CRA-signed gap $(\ell,r)$ with $\ell<\mathit{rev\_id}<r$. By construction the CRA signs only gaps *between adjacent revoked identifiers*, so no signed gap strictly contains a revoked $\mathit{rev\_id}$; producing one is a CRA-signature forgery. $\square$

**Theorem 8 (Revocation privacy).** *Neither $\mathit{rev\_id}$ nor the chosen gap appears in $x$; privacy follows from Theorem 3 (ZK).* $\square$

### 5.4 Remarks and limitations

- **Assumption surface vs. Groth16 schemes.** Our soundness reduces to EUF-CMA of standard ECDSA, binding of $\mathsf{COM}$, and knowledge-soundness of a hash-based argument (ROM) — *no setup-integrity assumption*. Crescent/zk-creds/zk-promises additionally require a correctly generated circuit-specific CRS (Theorem-level soundness is conditional on the ceremony).
- **Honest-issuer-at-issuance.** Issuer-untraceability (Thm 6) treats the issuer as adversarial *afterwards* but assumes it issues a well-formed signature; a malicious issuer can always refuse service or sign a marked credential, which is out of scope (and equally affects all surveyed schemes).
- **Static possession.** We prove possession of a static credential; stateful properties (reputation, asynchronous bans) as in zk-promises are out of scope by design.
- **ROM/Fiat–Shamir.** Non-interactivity and the nullifier model rely on the random oracle, as in longfellow.

---

## 작성 메모
- Def/Thm는 draft 형식. 제출본에서는 (i) 게임을 의사코드 박스로, (ii) advantage 식을 명시적 합으로, (iii) $\mathsf{COM}$·$H_{\mathsf{nul}}$ 인스턴스를 §4 회로와 정확히 연결.
- **Thm 6가 논문 핵심 정리** — "Why prior nullifiers fail this game" 문단은 §8 Related Work의 nullifier 비교와 교차참조(같은 4개 시스템).
- ECDSA EUF-CMA은 GGM+ROM 인용 필요(보통 Brown). longfellow가 in-circuit ECDSA를 이미 다루므로 그 가정 그대로 차용.
- 홀더-binding(KB-JWT/device key)도 witness로 in-circuit 검증·비노출임을 §4에서 명시 → unlinkability 채널 차단 일관성.
- ✅ $\mathsf{COM}$ 구체화 **확정(2026-05-31)**: SHA-256 해시 commitment $C=\mathsf{SHA256}(s\|r)$, 256-bit blind. hiding=ROM, binding=충돌저항. Pedersen/DL 가정 불필요 → Thm 6 hiding step은 ROM hiding으로 증명. (코드 `gen-sdjwt-blind.mjs`·`sdjwt_null_blind.cc`와 일치.)
