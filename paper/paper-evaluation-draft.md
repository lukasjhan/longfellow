# §7 Evaluation — 영문 초안 (v1, 실측)

> 측정 하니스: `playground/tools/eval-bench.mjs` (REPS=7, warmup=1). 원시 결과: `playground/fixtures/eval-results.{json,csv}`. 모든 셀 **ACCEPT**.
> ⚠️ 실측은 **단일 머신 1대** 수치. 제출본은 모바일(iPhone/Pixel) 1개 + 데스크톱 1개 등 2환경으로 보강 권장(longfellow 논문이 그렇게 함).

---

## §7 Evaluation

### 7.1 Setup and methodology

We implement all circuits on longfellow-zk (C++) and measure on a single commodity desktop—an **AMD Ryzen 7 2700X (8 cores / 16 threads, 2018), 32 GB RAM**, Linux, clang-17 `-O2`. We report the **median of 7 runs** after one warm-up; reported proving and verification times **exclude the one-time circuit build** (timed separately; circuits are compiled once and cached). Because the proof system is transparent, **there is no setup phase to amortize or trust**. The prover and verifier are the only parties; no issuer or network interaction occurs at presentation time.

Each presentation comprises two MAC-linked proofs—a signature circuit over $\mathbb{F}_p$ (ECDSA) and a hash circuit over $\mathrm{GF}(2^{128})$ (SHA-256 structure); "proof (KB)" is the full transmitted bundle. We use a EUDI-style PID credential and disclose one attribute (`age_over_18`) for the feature rows, three (`given_name, age_over_18, height`) for the base row.

### 7.2 Results

**Table 2.** Per-feature cost on SD-JWT VC and ISO mdoc (median of 7 runs; prove/verify in ms; proof = transmitted bundle).

| Format | Feature | Prove (ms) | Verify (ms) | Proof (KB) | Hash-circuit inputs |
|---|---|--:|--:|--:|--:|
| SD-JWT VC | base (SD + signature) | 1961 | 796 | 391 | 195,386 |
| SD-JWT VC | + nullifier | 1844 | 704 | 390 | 189,046 |
| SD-JWT VC | + **blind** nullifier | 1917 | 817 | 389 | 193,790 |
| SD-JWT VC | + revocation | 1945 | 818 | 406 | 188,858 |
| ISO mdoc | + nullifier | 1003 | 432 | 345 | 95,590 |
| ISO mdoc | + **blind** nullifier | 1057 | 475 | 347 | 100,078 |
| ISO mdoc | + revocation | 1033 | 459 | 361 | 95,402 |

(Min–max/σ available in `eval-results.csv`; e.g. SD-JWT blind prove 1881–1937, σ=18 ms. One-time circuit build ≈0.5 s for SD-JWT, ≈0.25 s for mdoc.)

### 7.3 Analysis

**Practicality.** Every configuration proves in **under 2 s** and verifies in **under 0.85 s** on a six-year-old desktop CPU, single-threaded relative to mobile baselines, *with no trusted setup and no change to issuer infrastructure or the credential*. This is well within interactive presentation budgets.

**Issuer-untraceability is essentially free.** Comparing the apples-to-apples rows (both disclose one attribute), the **blind** nullifier adds only $+73$ ms ($+4\%$) over a plain nullifier on SD-JWT VC ($1844\!\to\!1917$) and $+54$ ms ($+5\%$) on mdoc ($1003\!\to\!1057$), with **no measurable change in proof size** ($\le 2$ KB). The commitment-and-opening that removes issuer traceability costs two extra SHA-256 blocks (the opening $C=\mathsf{SHA256}(s\|r)$ and the nullifier $\mathsf{SHA256}(s\|\mathit{ctx})$); against the credential's signature and disclosure hashing this is in the noise. The strongest privacy property in our framework is therefore obtained at negligible cost.

**SD-JWT VC vs. mdoc.** mdoc presentations are $\approx\!1.9\times$ faster to prove and verify than SD-JWT VC ($\approx\!1.0$ s vs. $\approx\!1.9$ s), tracking the hash-circuit size ($\approx\!95$k vs. $\approx\!190$k inputs). The gap is the in-circuit cost of SD-JWT VC's text encoding: base64url decoding and JSON disclosure parsing roughly double the SHA-256 work relative to mdoc's compact CBOR salted hashes. This quantifies, for the first time, the concrete ZK cost of the SD-JWT VC wire format.

**Revocation has constant, list-independent overhead.** Adding signed-range non-membership grows the signature circuit from 3,739 to 5,288 inputs (the extra in-circuit CRA ECDSA verification) and the bundle by $\approx\!15$ KB ($391\!\to\!406$ on SD-JWT, $347\!\to\!361$ on mdoc), while prove/verify move within noise. Crucially, this cost is **independent of the revocation-list size**: the holder proves membership in one CRA-signed gap regardless of how many identifiers are revoked.

**Proof size.** Bundles are $\approx\!390$ KB (SD-JWT VC) and $\approx\!350$ KB (mdoc), split into roughly equal $\approx\!195$ KB signature and hash halves. These are transparent (hash-based) proofs; they are larger than pairing-based SNARKs but require no trusted setup—the central trade we make.

### 7.4 Comparison to batch issuance

The deployed alternative, batch issuance, moves all cost to *issuance and storage*: to support $k$ verifier-unlinkable presentations the issuer mints and signs $k$ single-use credentials (each with fresh salts and key-binding keys) and the holder stores them, while each presentation is a cheap signature check. Our approach inverts this: a **single** credential supports an **unbounded** number of unlinkable presentations, each costing one $\approx\!1$–$2$ s proof and no issuer interaction. Beyond the cost profile, the two are not equivalent in privacy: batch issuance yields only *verifier*-unlinkability and leaves the issuer able to correlate, whereas our presentations are unlinkable to the issuer as well (Theorem 6). A precise issuer-side cost model ($k$ signatures + storage vs. one issuance) is given in [Appendix]; the qualitative point is that batch issuance trades recurring issuer/storage cost and weaker privacy for cheaper presentations, and is unsuitable when issuer-unlinkability is required.

### 7.5 Threats to validity

Measurements are from a single x86 desktop; mobile proving (the deployment target) will differ, and a camera-ready should add at least one mobile and one server-class datapoint (cf. longfellow's per-device tables). Proving time is dominated by the hash circuit, so it scales with the number and size of disclosed attributes; we fix a representative PID disclosure. Reported sizes are circuit *input* counts (a proxy for circuit size exposed by the prover), not raw gate counts. Numbers reflect the implementation as of 2026-05-31.

---

## 작성 메모
- Table 2의 mdoc **base** 행은 미측정(전용 base 바이너리가 split 세트에 없음). mdoc base ≈ mdoc+nullifier에서 nullifier 블록(작음) 제외 수준 → 필요시 longfellow_cli로 별도 측정해 보강.
- §7.4 batch issuance는 현재 **분석 모델**(발급자측 미측정). 정량 Table 3 원하면 발급자 N회 서명·저장 벤치를 추가 측정.
- 게이트 수(정식 constraint count)는 ninputs 대신 회로 컴파일러에서 추출 가능하면 보강(리뷰어가 ninputs보다 gate를 선호).
- 핵심 셀링 수치 3개(Abstract·Intro에 사용): **prove <2s / verify <0.85s, no trusted setup** · **blind nullifier +4–5%(거의 무료)** · **revocation은 리스트 크기 무관 상수(+15KB)**.
- 재현: `REPS=7 node tools/eval-bench.mjs` (fixtures 자동 재생성). 원시 `fixtures/eval-results.csv`.
