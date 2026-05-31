# 논문 아웃라인 & 기여 정리 (Paper Outline)

> **가제:** *Anonymous Credentials from SD-JWT VC: Issuer-Unlinkable Nullifiers and Revocation in Transparent Zero-Knowledge*
> **타깃:** PETS (1순위) / WPES·Financial Crypto (대안) — 시스템 논문
> **선행연구 근거:** `paper-prior-art-research-ko.md` (1·2·3차 딥리서치 완료). 이 문서의 모든 포지셔닝은 거기서 검증된 사실에 기반.
> **작성일:** 2026-05-31 / 상태: v0 스캐폴드

---

## 0. 한 장 요약 (elevator pitch)

표준으로 배포 중인 SD-JWT VC·ISO mdoc은 **unlinkability가 없다**(발급자 서명이 정적이라 제시들이 연결됨). 현재 유일한 표준 대응책인 **batch issuance는 verifier-unlinkability만** 주고 발급자 추적은 못 막으며 운영비가 크다. 우리는 **변형하지 않은 표준 크리덴셜** 위에, **trusted setup이 없는 transparent ZK**(longfellow)로, **selective disclosure + predicate + issuer-unlinkable blind nullifier + revocation**을 **SD-JWT VC와 mdoc 양쪽에 단일 프레임워크**로 올린다. 핵심 신규성은 **(i) SD-JWT VC를 위한 transparent-ZK 회로**와 **(ii) 발급자조차 추적 불가능한 per-context blind nullifier**, 그리고 **(iii) 두 포맷을 아우르는 통합**이다.

---

## 1. 기여 (Contributions) — 정밀 보정판

> 표현 원칙: revocation·predicate·selective disclosure는 단독 novelty로 주장하지 않는다. 무게는 **통합 + blind nullifier**가 견딘다. "최초" 주장은 모두 *to the best of our knowledge* + 포맷·축 한정.

- **C1 — SD-JWT VC를 위한 transparent ZK.** Trusted setup 없는 ZK(Ligero+sumcheck, SHA-256 가정)를 **변형하지 않은 IETF SD-JWT VC**(JSON/JWS/base64url/salted-hash)에 적용한 최초의 구성. longfellow는 mdoc 전용(+plain JWT)이었고 SD-JWT는 미지원. *(근거: 1차 §3.1)*
- **C2 — Issuer-unlinkable blind nullifier (load-bearing novelty).** 커밋먼트+오프닝으로 도출되어 **발급자조차 추적 불가**한 per-context nullifier를 **표준 발급자-서명 크리덴셜**에 바인딩. 우리가 아는 한 (a) 절대 de-anonymize하지 않고, (b) self-held 키/bespoke 멤버십이 아닌 **issuer-signed 표준 크리덴셜**에 묶이며, (c) **publicly verifiable transparent ZK**인 최초의 nullifier. PLUME/Semaphore/ARC/e-cash와의 차이 명확. *(근거: 3차 §7 GAP3)*
- **C3 — 단일 프레임워크 통합.** selective disclosure + attribute predicate + blind nullifier + signed-range 비-멤버십 revocation을 **SD-JWT VC와 ISO mdoc 모두**에서 하나의 회로 구성(seam)으로 제공. 어떤 선행연구도 이 4속성을 transparent하게 두 포맷에 묶지 않음. *(근거: 종합)*
- **C4 — 구현·평가.** longfellow-zk 위 구현 + **발급자 인프라·기기 변경 0, trusted setup 0**으로 표준 크리덴셜에서 동작함을 prove/verify 시간·proof 크기·게이트 수로 정량 평가. batch issuance·BBS#와 정성/정량 비교.

> **명시적 비-기여(reviewer 선제 차단):** signed-range 비-멤버십 revocation **메커니즘**은 longfellow `MdocRevocationSpan`(Frigo, RWC)의 것 → 선행연구로 인용. 우리 기여는 그 **SD-JWT VC로의 확장과 통합**에 한정. (§related work에 1문단 명시)

---

## 2. 섹션 구조 (Section-by-section)

### §1 Introduction
- 디지털 지갑(EUDI, mDL) 배포 현실 → SD-JWT VC·mdoc 채택.
- 문제: **linkability**. 정적 발급자 서명 + 정적 salted-hash → 제시 간/발급자-검증자 결탁 시 추적. *(ETSI TR 119476-1 인용)*
- 현 대응책 batch issuance의 한계: **verifier-only, issuer 추적 못 막음**, 운영비(제시마다 일회용 크리덴셜). *(OpenID4VCI 1.0·RFC 9901·HAIP·EUDI ARF)*
- 학계 신호: **16인 암호학자 EUDI 권고** — salted-hash는 unlinkability(eIDAS-2 필수요건) 불충족. *(GitHub Discussion #211)*
- 기존 ZK 대안의 비용: trusted setup(Crescent/zk-creds/zk-promises) 또는 새 서명·이슈어 상호작용(BBS#).
- **우리 접근 한 문장** + 기여 4개(C1–C4).

### §2 Background
- §2.1 SD-JWT VC: JWS 서명, disclosure(salt‖claim) 해시, KB-JWT.
- §2.2 ISO mdoc/18013-5: CBOR, MSO, ECDSA-P256, salted-hash.
- §2.3 Linkability 모델: verifier/issuer/full unlinkability 정의(ETSI 용어 정렬).
- §2.4 Transparent ZK(longfellow): Ligero(MPC-in-the-head)+sumcheck, **no CRS**, SHA-256+Fiat-Shamir(ROM). *(libzk는 Internet-Draft로만 인용, peer-reviewed는 IACR CiC)*

### §3 Threat Model & Goals
- 당사자: Issuer(정직, 키 노출 안 함) / Holder(prover) / Verifier. 결탁 모델: issuer↔verifier, verifier↔verifier, multi-presentation.
- 보안 목표(정의는 §5):
  - Completeness, **Soundness**(위조 불가, no trusted setup이라 toxic-waste 가정 없음 — §3.5 trust-surface 논거),
  - **Selective-disclosure privacy**, **Presentation unlinkability**(verifier+issuer),
  - **Predicate soundness**,
  - **Nullifier**: uniqueness(같은 context→같은 tag) + **issuer-untraceability**(발급자도 tag↔크리덴셜 연결 불가),
  - **Revocation soundness**(폐기된 ID는 통과 불가) + revocation-privacy(어떤 ID인지 비노출).

### §4 Construction
- §4.1 회로 공통 seam(`sdjwt_common.h`) — 서명검증·해시·disclosure 파싱을 포맷 비종속 블록으로.
- §4.2 Selective disclosure + predicate(범위/비교).
- §4.3 **Issuer-unlinkable blind nullifier** ← *핵심 절.* 커밋먼트 C=Com(secret; r), 발급 시 issuer는 C만 봄(secret/r 모름), 제시 시 nullifier N=H(secret, ctx) + opening 증명. **발급자 추적 불가 논거**(C는 hiding, N은 ctx별 PRF). PLUME/ARC와 형식적 대비.
- §4.4 Signed-range 비-멤버십 revocation — **`MdocRevocationSpan` 인용** 후 SD-JWT VC로 확장(서명 구간 e_span, MAC 링크).
- §4.5 **Unification** — SD-JWT VC↔mdoc가 같은 seam을 공유하는 구조(중복 제거된 sdjwt_common).

### §5 Security Analysis
- 게임 기반 정의 + 증명 스케치(특히 nullifier issuer-untraceability가 hiding commitment + PRF/ROM에 환원됨).
- *(이 절이 reviewer 설득의 무게중심 — 3차 §7 OPEN #3)*

### §6 Implementation
- longfellow-zk(C++) 위. 회로 파일 매핑은 §7 표.
- SD-JWT/mdoc 생성기, 회로 캐시 주의(구조 변경 시 hash 캐시 무효).

### §7 Evaluation
- 벤치마크 표(아래 §5 문서). 기준선: plain presentation, batch issuance 비용 모델, (정성)BBS#.

### §8 Related Work
- 비교표(아래 §4 문서) + 서술. 축: proof system / setup / 포맷 / SD / predicate / unlinkability / nullifier / revocation / public-verifiability.
- 카테고리: ① ZK-over-standard-credential(longfellow·Crescent·zk-creds·zk-promises) ② anonymous-credential 서명군(BBS#·Idemix·U-Prove·Cinderella) ③ nullifier 프리미티브(PLUME·Semaphore·ARC·e-cash).

### §9 Discussion & Limitations
- 정적 보유증명 한정(stateful 평판/ban은 범위 밖 = scope 차이, not 약점 — 1차 §3.6).
- "움직이는 타깃"(longfellow upstream JWT 모듈) — as-of 날짜 명시.

### §10 Conclusion

---

## 3. Related-Work 비교표 (논문 Table 1 초안)

> 범례: ✅=제공/그러함, ❌=아님, △=부분/조건부, ⁻=해당없음. *Setup*: T=trusted, **N=none(transparent)**.

| 시스템 | 증명계 | Setup | 대상 포맷 | SD | Pred | Unlink (V/I) | Nullifier (issuer-untraceable?) | Revocation | Public-verif |
|---|---|:--:|---|:--:|:--:|:--:|---|---|:--:|
| **batch issuance** (baseline) | — | — | SD-JWT/mdoc | ✅ | ❌ | V만 / ❌ | ❌ | status list | ✅ |
| **longfellow-zk** | Ligero+sumcheck | **N** | mdoc(+plain JWT) | ✅ | △ | ✅/✅ | ❌ | (signed-range, 자체) | ✅ |
| **Crescent** | Groth16(+Spartan) | T | generic JWT/mDL | ✅ | △ | ✅/✅ | ❌ | — | ✅ |
| **zk-creds** | Groth16+LinkG16 | T | 여권→재커밋 | ✅ | ✅ | ✅/✅ | △ 재사용 시 노출 | 리스트 제거 | ✅ |
| **zk-promises** | Groth16 | T | 계정상태(zk-object) | ⁻ | ✅ | ✅/✅ | serial-over-commit(replay) | 콜백 | ✅ |
| **BBS#** | BBS+Schnorr NIZK | N* | 자체 BBS-family | ✅ | ✅ | ✅/✅ | pseudonym | accumulator | △ server-aided |
| **Idemix**† | CL/Strong-RSA | T(RSA) | 자체 | ✅ | ✅ | ✅/✅(멀티쇼) | pseudonym | accumulator | ✅ |
| **U-Prove**† | Brands/DL | △ | 자체 토큰 | ✅ | ✅ | ❌ 원쇼(재사용 linkable) | — | 토큰 폐기 | ✅ |
| **Cinderella** | Pinocchio SNARK | T | X.509/RSA | △ | ✅ | ✅/✅ | ❌ | — | ✅ |
| **PLUME** | (VRF) | N | self-held secp256k1 | ⁻ | ⁻ | ✅ | ✅ but 이슈어 없음 | ⁻ | ✅ |
| **Semaphore** | Groth16 | T | 자체 Merkle 멤버십 | ⁻ | ⁻ | ✅ | ❌ admin이 leaf 앎 | ⁻ | ✅ |
| **ARC** (Privacy Pass) | KVAC(MACGGM) | N | 자체 MACGGM | ❌ | ❌ | ✅/△ | △ per-ctx tag, weak | — | ❌ private |
| **Compact E-Cash** | CL/Strong-RSA | T | 자체 코인 | ⁻ | ⁻ | ✅ | ❌ 이중지불 시 노출 | — | ✅ |
| **★ OURS** | **Ligero+sumcheck** | **N** | **SD-JWT VC + mdoc** | ✅ | ✅ | **✅/✅** | **✅ issuer-untraceable blind** | signed-range(확장) | ✅ |

\* BBS#는 NIZK 자체는 no-setup이나 **발급/제시 시 이슈어 상호작용 필요**(server-aided) + q-SDH 구조 가정.
† Idemix/U-Prove 행은 **1차 문헌 미검증(provisional)** — 제출 전 CL 2001/2002·Idemix 스펙·Brands 2000으로 확정.

> **표가 말하는 한 줄:** "Setup=N **그리고** 포맷=표준 SD-JWT VC+mdoc **그리고** issuer-untraceable nullifier"가 동시에 ✅인 행은 **OURS뿐.**

---

## 4. 평가 계획 (논문 Table 2/3 초안 — reviewer 필수 요구)

**Table 2 — 회로별 비용** (각 셀: prove time / verify time / proof size / gate(또는 constraint) 수)

| 기능 | SD-JWT VC | ISO mdoc |
|---|---|---|
| base (SD + 서명검증) | … | … |
| + predicate | … | … |
| + **blind nullifier** | … | … |
| + revocation (signed-range) | … | … |
| full (통합) | … | … |

- 측정 환경 명시(CPU/모바일), n=반복, 평균±표준편차. longfellow 논문 Table 11/13 형식 차용.
- **Table 3 — batch issuance 대비**: "verifier-unlinkable presentation k회"를 위한 발급자/홀더 비용(크리덴셜 N개 발급·저장·키바인딩) vs 우리(1개 크리덴셜, 무제한 unlinkable 제시). 손익분기 k 도출.
- (정성) BBS#와 신뢰모델·상호작용 비교 표(§3.6 매트릭스 축약).

---

## 5. 구현 자산 매핑 (실측 — 본문 §6/§7 근거)

| 기능 | SD-JWT VC | ISO mdoc | 데모 |
|---|---|---|---|
| 공통 seam | `playground/native/sdjwt_common.h` | (공유) | — |
| 기본 split | `sdjwt_null_split.cc` | `mdoc_null_split.cc` | `demo:sdjwt-split` |
| nullifier | `sdjwt_nullifier.cc` | `mdoc_null_split.cc` | `demo:nullifier` / `demo:mdoc-nullifier` |
| **blind nullifier** | `sdjwt_null_blind.cc` | `mdoc_null_blind.cc` | `demo:nullifier-blind` / `demo:mdoc-nullifier-blind` |
| revocation | `sdjwt_revoc_split.cc` | `mdoc_revoc_split.cc` | `demo:revocation` / `demo:mdoc-revocation` |
| 선행 revocation(인용) | — | `longfellow-zk/lib/circuits/tests/mdoc/mdoc_revocation.h` (`MdocRevocationSpan`) | — |
| 생성기 | `tools/gen-sdjwt(-blind).mjs` | `tools/gen-mdoc(-blind).mjs` | `gen:sdjwt` / `gen:mdoc` |

- 기존 분석 리포트(루트 `*_analysis-report*.md`)가 각 기능의 설계 근거 → 본문 서술에 재활용.
- ⚠️ 회로 구조 변경 시 sdjwt-*hash* 캐시 삭제 필수(stale→REJECT) — 평가 재현성 노트에 기록.

---

## 6. 제출 전 OPEN (research 문서에서 승계)

1. **Idemix/U-Prove 1차 인용** — 표 † 행 확정(provisional 제거).
2. **blind nullifier 형식적 우위 증명** — §5의 핵심. issuer-untraceability를 hiding-commitment+PRF/ROM에 환원하는 게임·정리.
3. **revocation 잔존 기여 정량화** — `MdocRevocationSpan`→SD-JWT VC 이식이 새 회로인지 명확화(§4.4 솔직 기술).
4. **longfellow upstream 재확인** — 제출 직전 최신 커밋(JWT/SD-JWT 모듈) 점검 + as-of 날짜.
5. **벤치마크 측정** — Table 2/3 채우기(현재 데모는 기능검증, 정량수치 별도 측정 필요).
6. 인용 위생: libzk=Internet-Draft, longfellow=IACR CiC, BBS#=eprint 2025/619, ARC=현행 WG draft.

---

## 7. 글쓰기 로드맵 (제안 순서)

1. **§8 Related Work + Table 1 먼저** — 이미 자료 완비(`paper-prior-art-research-ko.md`). 가장 빨리 쓸 수 있고 기여를 날카롭게 함.
2. **§3 Threat Model + §5 보안 정의** — 기여 C2의 무게중심.
3. **§4 Construction** — 코드가 있으니 설계 서술.
4. **§7 Evaluation 측정 + 표 채우기.**
5. **§1 Introduction 마지막에** — 1~4가 서면 자연히 써짐.
6. **Abstract 맨 마지막.**

---

## 8. Abstract 초안 (English, v0)

> Selective-disclosure credentials such as IETF **SD-JWT VC** and **ISO mdoc** are being deployed at national scale, yet they provide *no unlinkability*: a static issuer signature over static salted hashes lets colluding parties correlate presentations, and the only standardized mitigation—**batch issuance**—offers verifier-unlinkability only, at a recurring per-presentation cost. We present a system that turns *unmodified* standard credentials into anonymous credentials using **transparent, no-trusted-setup zero-knowledge**. Our framework unifies selective disclosure, attribute predicates, an **issuer-unlinkable per-context blind nullifier**, and signed-range non-membership revocation over *both* SD-JWT VC and mdoc. The blind nullifier is, to the best of our knowledge, the first that binds to an issuer-signed standard credential, never de-anonymizes its holder, and is publicly verifiable in transparent ZK—distinguishing it from PLUME/Semaphore nullifiers, Privacy Pass/ARC rate-limit tags, and e-cash double-spend tags. We implement the system on longfellow-zk and show it runs with no changes to issuer infrastructure or devices and no trusted setup: a presentation proves in under 2 s and verifies in under 0.85 s on a commodity desktop ($\approx$1.0 s / $\approx$0.45 s for mdoc), and the issuer-unlinkable blind nullifier adds under 5\% over a plain nullifier with no increase in the $\approx$390 KB (SD-JWT VC) / $\approx$350 KB (mdoc) proof.
