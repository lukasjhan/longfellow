# §8 Related Work — 영문 초안 (v1)

> 논문 산문 초안. `\cite{key}`는 §맨아래 키 매핑 참조(BibTeX로 옮길 것). 모든 사실은 `paper-prior-art-research-ko.md`(1·2·3차)에서 검증됨.
> ⚠️ Idemix/U-Prove 문장은 교과서 사실(멀티쇼 unlinkable / 원쇼 linkable)이나 본 조사에서 1차소스 미검증 → 제출 전 CL 2001/2002·Brands 2000·U-Prove Crypto Spec로 확인.

---

## Related Work

We compare prior approaches along the axes that define our contribution: (i) the **proof system** and whether it requires a **trusted setup**; (ii) the **credential format** the scheme operates over—an *unmodified, deployed standard* credential (SD-JWT VC, ISO mdoc, JWT) versus a *bespoke* signature, commitment, or membership structure; (iii) support for **selective disclosure** and **attribute predicates**; (iv) **unlinkability**, distinguishing *verifier*-unlinkability from full *issuer*-unlinkability; (v) whether the scheme provides a **nullifier**, and if so whether it is *issuer-untraceable*; and (vi) **revocation**. Table~\ref{tab:related} summarizes the comparison.

### Zero-knowledge over existing standard credentials

The line of work closest to ours proves possession of an existing, issuer-signed credential in zero knowledge so that the issuer's signature is never revealed to the verifier. **Longfellow**~\cite{frigo2024longfellow} is, to our knowledge, the first such system to operate on legacy ECDSA(P-256) credentials with no change to issuers or devices and no non-standard assumptions; it is *transparent*, combining the Ligero MPC-in-the-head argument with a sumcheck-based verifiable-computation protocol and relying only on a collision-resistant hash (SHA-256), with Fiat–Shamir in the random-oracle model~\cite{libzk-draft}. Both the longfellow paper and its reference implementation, however, target **ISO mdoc only**—selective disclosure is treated solely as mdoc's CBOR salted hashes—and a plain-JWT circuit was added subsequently; neither addresses the IETF **SD-JWT VC** salted-hash format. Longfellow builds no nullifier (it explicitly names the costly batch-issuance workaround it avoids) and treats revocation as future work, though a signed-range non-membership circuit for mdoc later appeared in its source tree. Our work builds on the same transparent proof system but (a) constructs the first circuits for the SD-JWT VC structure, (b) adds an issuer-unlinkable blind nullifier, and (c) unifies both formats; we credit the signed-range revocation *mechanism* to longfellow and contribute its extension to SD-JWT VC.

**Crescent**~\cite{paquin2024crescent} adds unlinkability and selective disclosure to existing **generic JWT and mDL** credentials through a prepare/show model: a one-time, expensive Groth16 proof is generated and stored, and each presentation is a fresh, re-randomized, unlinkable instance. Crescent is the most closely related system in spirit, but differs on two axes central to us. First, its main proof is a **Groth16 zk-SNARK requiring a circuit-specific trusted setup** (a transparent Spartan sub-prover is used only for ECDSA device binding), so the system as a whole is not transparent. Second, it targets generic JWT rather than the IETF SD-JWT VC standard; a sample `jwt_sd` schema implements Crescent's *own* selective-disclosure mechanism over a plain JWT, which is distinct from the SD-JWT salted-hash format.

**zk-creds**~\cite{rosenberg2023zkcreds} converts existing identity documents—concretely, NFC e-passports following ICAO Doc 9303—into anonymous credentials. Rather than re-verifying the issuer signature at every show, it verifies the original document *once* to justify inserting a fresh commitment as a leaf of a Merkle *issuance list* on a public bulletin board; presentations then prove list membership plus predicates (its LinkG16 variant re-randomizes the costly membership proof for reuse). It uses Groth16 (trusted setup) and provides nullifier-like gadgets, including a clone-resistance mechanism that *de-anonymizes* a holder who reuses a rate-limited token. **zk-promises**~\cite{shih2025zkpromises} generalizes this to stateful anonymous credentials: a client-side "zk-object" with Turing-complete state and asynchronous callbacks, where each update reveals the old version's serial number (a nullifier) to prevent replay, over a bulletin board of commitments. Both are Groth16-based, require additional bulletin-board infrastructure, and operate over *re-committed* state rather than an unmodified standard credential; neither offers an issuer-untraceable blind nullifier bound to a deployed credential format.

**Cinderella**~\cite{delignat2016cinderella} verifies legacy X.509/RSA-PKCS\#1 certificates inside a Pinocchio zk-SNARK; it predates SD-JWT VC and mdoc, requires a per-policy trusted setup, and targets PKI certificates rather than wallet credential formats.

### Anonymous-credential signature schemes

A parallel line designs *new* signatures whose possession can be shown unlinkably. **CL signatures / Idemix**~\cite{camenisch2001cl,camenisch2002cl} achieve multi-show unlinkability, attribute predicates, pseudonyms, and accumulator-based revocation under the Strong-RSA assumption, while **U-Prove**~\cite{brands2000,uprove-spec} issues efficient DL-based tokens that are *one-show*—reuse across presentations is linkable. **BBS/BBS+** and the recent **BBS\#**~\cite{bbs-sharp2025} are leading candidates for European digital identity: BBS\# is pairing-free, runs on NIST P-256 with existing secure-element keys, and provides full issuer-unlinkability, pseudonyms, and accumulator-based revocation. A statement by sixteen cryptographers recommended the BBS family for the EU Digital Identity Wallet, noting that the salted-hash design of SD-JWT and mdoc "cannot ensure unlinkability," a mandatory eIDAS-2 requirement~\cite{eudi-crypto-feedback}. Crucially, every scheme in this category binds to *its own* credential format: deploying it requires issuers to adopt a new signature, and BBS\# additionally requires issuer assistance during presentation to remain pairing-free. Our approach instead leaves the *deployed, ECDSA-signed* SD-JWT VC/mdoc credential unchanged and obtains unlinkability through transparent zero-knowledge.

### Nullifiers and rate-limiting tokens

Our blind nullifier is most directly related to nullifier and rate-limiting primitives. **Semaphore**~\cite{semaphore} derives a per-scope nullifier $\mathsf{hash}(\mathit{scope}, sk)$, but binds to a bespoke Merkle group whose leaves are public identity commitments known to the group admin, and uses Groth16. **PLUME**~\cite{plume2022} produces a deterministic nullifier $\mathsf{hash}(m, pk)^{sk}$ from a *self-held* secp256k1 key; it is transparent and unlinkable, but there is no issuer and no credential in the model. **Privacy Pass ARC** (Anonymous Rate-Limited Credentials)~\cite{arc-draft} is the closest match on the *mechanism*: it yields a per-presentation-context tag that the origin treats as a nullifier and even claims Issuer–Client unlinkability. However, ARC binds only to its own MACGGM algebraic-MAC (KVAC) credential and is **privately verifiable**—the issuer and origin share a secret key and ARC tokens are explicitly "not publicly verifiable"—the antithesis of a transparent, publicly verifiable proof. Finally, in **compact e-cash**~\cite{chl2005} a coin's serial number is issuer-unlinkable only while the holder is honest and *de-anonymizes the spender on double-spend* (the traceable variant additionally lets the bank trace all of a user's coins); our blind nullifier, by contrast, *never* de-anonymizes its holder.

### Unlinkability for deployed SD-JWT VC and mdoc

In deployed, standardized systems the only mechanism for SD-JWT VC/mdoc unlinkability today is **batch issuance**: the issuer mints many single-use credentials with fresh salts and key-binding keys, one consumed per presentation. This is recommended across OpenID4VCI 1.0, RFC 9901, the High-Assurance Interoperability Profile, and the EUDI Architecture and Reference Framework~\cite{openid4vci,rfc9901,haip,eudi-arf}, yet it provides only *verifier*-unlinkability—not issuer-unlinkability—at a recurring per-presentation cost~\cite{etsi119476}.

### Positioning

As Table~\ref{tab:related} shows, no prior system simultaneously (i) requires *no trusted setup*, (ii) operates over an *unmodified deployed standard credential* (both SD-JWT VC and mdoc), and (iii) provides an *issuer-untraceable* nullifier with public verifiability. Transparent systems (longfellow) are mdoc-only and nullifier-free; systems that add unlinkability to standard credentials (Crescent) require a trusted setup; nullifier primitives (PLUME, Semaphore, ARC) are not bound to issuer-signed standard credentials and are variously trusted-setup or privately verifiable; and anonymous-credential signatures (BBS\#, Idemix, U-Prove) require issuers to adopt a new credential format. Our framework occupies the remaining cell, combining selective disclosure, predicates, an issuer-unlinkable blind nullifier, and signed-range revocation over both SD-JWT VC and mdoc.

---

## Table 1 (LaTeX, booktabs) — paper-ready

```latex
\begin{table*}[t]\centering\small
\caption{Comparison of approaches to privacy-preserving credential presentation.
N\,=\,no trusted setup (transparent), T\,=\,trusted setup;
V/I\,=\,verifier/issuer unlinkability; \cmark/\xmark/\pmark = yes/no/partial.}
\label{tab:related}
\begin{tabular}{@{}lllccccll c@{}}
\toprule
System & Proof system & Setup & Format & SD & Pred & Unlink (V/I) & Nullifier (issuer-untraceable?) & Revocation & PubVerif\\
\midrule
Batch issuance (baseline) & --- & --- & SD-JWT/mdoc & \cmark & \xmark & V\,/\,\xmark & \xmark & status list & \cmark\\
Longfellow~\cite{frigo2024longfellow} & Ligero+sumcheck & N & mdoc(+JWT) & \cmark & \pmark & \cmark/\cmark & \xmark & signed-range\textsuperscript{a} & \cmark\\
Crescent~\cite{paquin2024crescent} & Groth16(+Spartan) & T & generic JWT/mDL & \cmark & \pmark & \cmark/\cmark & \xmark & --- & \cmark\\
zk-creds~\cite{rosenberg2023zkcreds} & Groth16+LinkG16 & T & e-passport$\to$recommit & \cmark & \cmark & \cmark/\cmark & \pmark de-anon on reuse & list removal & \cmark\\
zk-promises~\cite{shih2025zkpromises} & Groth16 & T & account state & --- & \cmark & \cmark/\cmark & serial-over-commit (replay) & callback & \cmark\\
BBS\#~\cite{bbs-sharp2025} & BBS+Schnorr NIZK & N\textsuperscript{b} & own BBS-family & \cmark & \cmark & \cmark/\cmark & pseudonym & accumulator & \pmark\\
Idemix~\cite{camenisch2002cl} & CL / Strong-RSA & T & own & \cmark & \cmark & \cmark/\cmark & pseudonym & accumulator & \cmark\\
U-Prove~\cite{brands2000} & Brands / DL & \pmark & own token & \cmark & \cmark & \xmark one-show & --- & token revoke & \cmark\\
Cinderella~\cite{delignat2016cinderella} & Pinocchio SNARK & T & X.509/RSA & \pmark & \cmark & \cmark/\cmark & \xmark & --- & \cmark\\
PLUME~\cite{plume2022} & EC-VRF & N & self-held secp256k1 & --- & --- & \cmark & \cmark (no issuer) & --- & \cmark\\
Semaphore~\cite{semaphore} & Groth16 & T & own Merkle group & --- & --- & \cmark & \xmark admin knows leaf & --- & \cmark\\
ARC~\cite{arc-draft} & KVAC (MACGGM) & N & own MACGGM & \xmark & \xmark & \cmark/\pmark & \pmark per-ctx tag, weak & --- & \xmark private\\
Compact e-cash~\cite{chl2005} & CL / Strong-RSA & T & own coin & --- & --- & \cmark & \xmark de-anon on dbl-spend & --- & \cmark\\
\textbf{This work} & \textbf{Ligero+sumcheck} & \textbf{N} & \textbf{SD-JWT VC + mdoc} & \cmark & \cmark & \textbf{\cmark/\cmark} & \textbf{\cmark issuer-untraceable} & signed-range\textsuperscript{a} & \cmark\\
\bottomrule
\end{tabular}
\\[2pt]
\footnotesize\textsuperscript{a}\,Revocation mechanism due to longfellow's \texttt{MdocRevocationSpan}; we extend it to SD-JWT VC.
\quad\textsuperscript{b}\,BBS\# NIZK needs no setup but requires issuer interaction at presentation (server-aided).
\end{table*}
```

> 한 줄 요지(positioning 문단과 일치): **Setup=N ∧ 표준 SD-JWT VC+mdoc ∧ issuer-untraceable nullifier**가 동시에 ✅인 행은 *This work*뿐.

---

## Citation 키 매핑 (→ BibTeX 작성용)

| 키 | 문헌 | 출처 |
|---|---|---|
| `frigo2024longfellow` | Frigo & shelat, *Anonymous Credentials from ECDSA* | IACR CiC; ePrint 2024/2010 |
| `libzk-draft` | *draft-google-cfrg-libzk-01* (Internet-Draft, **not** a standard) | ietf.org/archive/id/draft-google-cfrg-libzk-01.html |
| `paquin2024crescent` | Paquin, Policharla, Zaverucha, *Crescent* | ePrint 2024/2013; github.com/microsoft/crescent-credentials |
| `rosenberg2023zkcreds` | Rosenberg, White, Garman, Miers, *zk-creds* | IEEE S&P 2023; ePrint 2022/878 |
| `shih2025zkpromises` | Shih, Rosenberg, Kailad, Miers, *zk-promises* | USENIX Security 2025; ePrint 2024/1260 |
| `delignat2016cinderella` | Delignat-Lavaud, Fournet, Kohlweiss, Parno, *Cinderella* | IEEE S&P 2016 |
| `camenisch2001cl` / `camenisch2002cl` | Camenisch–Lysyanskaya, CL signatures | CRYPTO 2001 / SCN 2002 ⚠️1차 확인 |
| `brands2000` / `uprove-spec` | Brands, *Rethinking PKI*; MS U-Prove Crypto Spec | MIT Press 2000 / Microsoft ⚠️1차 확인 |
| `bbs-sharp2025` | *BBS#* (eIDAS-2-targeted, pairing-free) | ePrint 2025/619; NIST WPEC 2024 |
| `semaphore` | Semaphore (PSE) | docs.semaphore.pse.dev |
| `plume2022` | Gupta & Gurkan, *PLUME: ECDSA Nullifier* | ePrint 2022/1255; ERC-7524 |
| `arc-draft` | Privacy Pass ARC (Anonymous Rate-Limited Credentials) | draft-ietf-privacypass-arc-protocol; draft-yun-privacypass-crypto-arc-00 |
| `chl2005` | Camenisch, Hohenberger, Lysyanskaya, *Compact E-Cash* | EUROCRYPT 2005; ePrint 2005/060 |
| `eudi-crypto-feedback` | 16 cryptographers, EUDI ARF feedback (BBS 권고) | GitHub Discussion #211 |
| `openid4vci` | OpenID for Verifiable Credential Issuance 1.0 | openid.net |
| `rfc9901` | RFC 9901 (batch issuance §10.1) | rfc-editor.org |
| `haip` | OpenID4VC High-Assurance Interoperability Profile 1.0 | openid.net |
| `eudi-arf` | EUDI Architecture and Reference Framework | EU Commission |
| `etsi119476` | ETSI TR 119476-1 (unlinkability taxonomy) | etsi.org |

---

## 작성 메모 (수정 시 참고)
- `\cmark`/`\xmark`/`\pmark`는 `pifont`/`amssymb`로 정의(예: `\newcommand{\cmark}{\ding{51}}`). 표 폭이 넘치면 PubVerif·Pred 열을 캡션 각주로 빼고 9열로 축소.
- Idemix/U-Prove 행·문장은 1차소스 확정 전까지 **provisional**. 확정되면 이 메모 삭제.
- longfellow revocation 각주(a)는 **반드시 유지** — 정직성 + 리뷰어 선제차단(우리 revocation 기여를 "확장"으로 한정).
- ARC는 movin target(draft -00/-01/-02 + WG draft) → 제출 시 현행 WG draft로 키 갱신.
