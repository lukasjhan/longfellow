# Abstract + §1 Introduction — 영문 초안 (v1)

> 논문 산문 초안(영문). `\cite{}` 키는 `paper-related-work-draft.md` 매핑 사용. 수치는 §7 실측. 모든 절(§3·§4·§5·§7·§8) 초안 완성 후 작성 → 본문과 정합.

---

## Abstract

Selective-disclosure credentials—IETF **SD-JWT VC** and **ISO mdoc**—are being deployed at national scale in digital identity wallets, yet they provide *no unlinkability*: a static issuer signature over static salted hashes lets colluding verifiers, and the issuer itself, correlate a user's presentations. The only standardized mitigation, *batch issuance*, provides verifier-unlinkability only and at a recurring per-presentation cost. We turn *unmodified* SD-JWT VC and mdoc credentials into anonymous credentials using **transparent, no-trusted-setup zero-knowledge**. Our framework unifies selective disclosure, attribute predicates, an **issuer-unlinkable per-context blind nullifier**, and signed-range non-membership revocation over both formats. The blind nullifier is, to our knowledge, the first that binds to an issuer-signed standard credential, *never de-anonymizes* its holder, and is *publicly verifiable* in transparent zero-knowledge—unlike PLUME/Semaphore nullifiers, Privacy Pass/ARC rate-limit tags, and e-cash double-spend tags. Implemented on longfellow-zk, a presentation proves in under 2 s and verifies in under 0.85 s on commodity hardware ($\approx$1.0 s / $\approx$0.45 s for mdoc), with no trusted setup and no change to issuers or devices; issuer-untraceability costs under 5\% over a plain nullifier.

---

## §1 Introduction

Digital identity wallets are moving from pilots to law. The European Digital Identity (eIDAS 2.0) framework obliges member states to offer wallets to all citizens, and mobile driver's licenses (mDL) are rolling out across U.S. states. Two credential formats dominate these deployments: **IETF SD-JWT VC**, a JSON/JWS credential with salted-hash selective disclosure, and **ISO/IEC 18013-5 mdoc**, its CBOR counterpart. Both let a holder reveal a subset of attributes (e.g., *age ≥ 18*) while hiding the rest.

**The problem: selective disclosure is not unlinkability.** Hiding *which* attributes are shown does not hide *who* is showing them. In both formats the issuer signs a fixed set of salted attribute hashes, and the holder forwards that issuer signature, verbatim, to every relying party. The signature and the salted hashes are therefore stable identifiers: any two relying parties that compare notes—or the issuer colluding with a relying party—can link a user's interactions, and the issuer, who produced the signature, can recognize it anywhere. A standards body taxonomy makes the distinction explicit, separating *verifier*-unlinkability from full *issuer*-unlinkability and noting that the salted-hash formats provide neither natively~\cite{etsi119476}. A statement signed by sixteen cryptographers warned the EU that this design "cannot ensure unlinkability," which eIDAS 2.0 lists as a mandatory requirement~\cite{eudi-crypto-feedback}.

**The state of practice is unsatisfying.** The only mitigation standardized today—across OpenID4VCI, RFC 9901, the High-Assurance Interoperability Profile, and the EUDI reference framework—is *batch issuance*: the issuer mints many single-use credentials, each with fresh salts and key-binding keys, and the holder spends one per presentation~\cite{openid4vci,rfc9901,haip,eudi-arf}. This buys only *verifier*-unlinkability—the issuer can still correlate—at a recurring cost in issuance, storage, and key management, and it fails outright once a credential is reused. Cryptographic alternatives exist but each asks issuers to abandon their deployed credential: BBS#-style anonymous-credential signatures~\cite{bbs-sharp2025} require a new signature scheme (and issuer assistance at presentation), while SNARK-based systems that prove possession of an existing credential—Crescent~\cite{paquin2024crescent}, zk-creds~\cite{rosenberg2023zkcreds}—depend on a circuit-specific *trusted setup* whose compromise silently breaks soundness. None of these targets the SD-JWT VC format that wallets are actually shipping.

**Our approach.** We make *unmodified* SD-JWT VC and ISO mdoc credentials unlinkable by proving their possession in **transparent zero-knowledge**—an argument system (Ligero + sumcheck) that needs no common reference string and rests only on SHA-256, building on longfellow~\cite{frigo2024longfellow}. The issuer keeps signing ordinary ECDSA credentials; the holder, at presentation, produces a proof that reveals only the attributes it chooses, the truth of a predicate, a per-context pseudonymous tag, and an epoch-fresh non-revocation fact—nothing else, and to no one, including the issuer. Within this framework we contribute the missing primitive that batch issuance and prior ZK systems lack: a nullifier that even the issuer cannot trace.

**An issuer-unlinkable blind nullifier.** A nullifier is a per-context tag that lets a verifier detect repeat use (one vote per election, one account per service) without identifying the holder. Existing constructions either reveal the holder on reuse (e-cash, zk-creds clone-resistance), are computed from a self-held key with no issuer-signed credential behind them (PLUME, Semaphore), or are privately verifiable so the issuer is a co-verifier (Privacy Pass/ARC). We instead have the *holder* commit a secret $s$ at issuance—$C=\mathsf{SHA256}(s\|r)$, which the issuer signs as an ordinary disclosure without ever seeing $s$—and derive the per-context nullifier $N=\mathsf{SHA256}(s\|\mathit{ctx})$ inside the proof, binding $N$ to the same $s$ the credential committed to. Because the issuer's only view of the seed is the hiding commitment $C$, it cannot recompute or recognize $N$: the nullifier is *issuer-untraceable* (Theorem~6). To our knowledge this is the first issuer-unlinkable nullifier bound to an unmodified, publicly verifiable standard credential, and—being SHA-256 throughout—it adds no cryptographic assumption beyond the base proof system.

**Contributions.**
- **(C1)** The first transparent, no-trusted-setup zero-knowledge construction over the **unmodified IETF SD-JWT VC** format—new circuits for its JSON/JWS/base64url/salted-hash structure—generalized to ISO mdoc through a shared seam (§4).
- **(C2)** An **issuer-unlinkable per-context blind nullifier** bound to a standard credential, with a security definition and proof of issuer-untraceability (§5), and a precise separation from PLUME, Semaphore, Privacy Pass/ARC, and e-cash (§8).
- **(C3)** A **single framework** unifying selective disclosure, attribute predicates, the blind nullifier, and signed-range non-membership revocation over *both* SD-JWT VC and mdoc (§4). (We adopt the signed-range revocation *mechanism* from longfellow and contribute its extension to SD-JWT VC and its integration.)
- **(C4)** An **implementation** on longfellow-zk and an evaluation showing the system runs with no issuer/device changes and no trusted setup, at practical cost (§7).

**Results.** On a commodity desktop, every configuration proves in under 2 s and verifies in under 0.85 s ($\approx$1.0 s / 0.45 s for mdoc), with $\approx$390 KB (SD-JWT VC) and $\approx$350 KB (mdoc) proofs. The issuer-untraceable blind nullifier costs under 5\% over a plain nullifier with no increase in proof size, and signed-range revocation adds a constant overhead independent of the revocation-list size. We also quantify, for the first time, the in-circuit cost of SD-JWT VC's text encoding: its base64url/JSON parsing roughly doubles the hash-circuit work relative to mdoc's CBOR.

---

## 작성 메모
- 첫 문단의 eIDAS/mDL 배포 주장에 1차 인용 추가(EU 규정 (EU) 2024/1183, AAMVA mDL). 현재 키 없음.
- "sixteen cryptographers" 수치는 §8과 일치(GitHub Discussion #211). 16명 확정.
- C3에서 revocation은 longfellow 메커니즘임을 괄호로 명시 → §6 리스크·§8과 일관(정직성).
- §1은 본문 확정 후 마지막으로 1회 더 압축 권장(특히 batch issuance 문단). 분량: PETS 기준 1~1.5p 적정.
- Abstract는 §7 수치 확정본 반영됨. 모바일 datapoint 추가 시 "commodity desktop" → 디바이스 명시로 갱신.
