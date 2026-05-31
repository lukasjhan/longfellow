# 논문 선행연구 조사 (Prior-Art Research)

> **작업 제목(가제):** *Anonymous Credentials from SD-JWT VC using Transparent Zero-Knowledge (longfellow-zk)*
>
> **조사일:** 2026-05-31
> **방법:** 다중소스 웹서치(6 각도) → 24개 소스 페치 → 117개 주장 추출 → 25개 핵심 주장 3표 적대적 검증(2/3 refute 시 폐기) → 23개 확정·2개 폐기
> **상태:** 1차 완료. 남은 갭 3개는 2차 조사 예정(§7).

---

## 1. 한 줄 결론

**Transparent(무-trusted-setup) ZK를 IETF SD-JWT VC에 특화 적용하고, selective disclosure + predicate + issuer-unlinkable nullifier + signed-range 비-멤버십 revocation을 SD-JWT VC와 mdoc 양쪽에 단일 프레임워크로 통합한 발표 사례는 없다.** novelty 갭은 실재하며 방어 가능하다 — 단 "최초"를 막연히 쓰지 말고 아래 §5 문장처럼 정밀하게 좁혀야 한다.

> **2차 갱신(2026-05-31):** 갭은 생존하나 *개별 메커니즘은* 더 좁혀야 한다. (1) revocation의 signed-range 비-멤버십은 **longfellow 자체 프리미티브**(`MdocRevocationSpan`)라 새 메커니즘이 아님 → 인용+재포지셔닝 필수. (2) **BBS#**가 mdoc/SD-JWT 호환 full-unlinkability를 이미 주장하는 최강 경쟁자. (3) 가장 강한 잔존 novelty는 **표준 포맷 위 issuer-unlinkable blind nullifier**지만 아직 검증 부족(증거 부재 기반). 상세 §7.
>
> **3차 갱신(2026-05-31) — 핵심 novelty 확정 ✅:** GAP 3 해소. **"표준 포맷 위 issuer-unlinkable blind nullifier + transparent ZK" 조합은 선행연구에 없음**(PLUME=self-held 키·이슈어 없음 / Semaphore=Groth16·admin이 leaf 앎 / ARC=메커니즘 최근접이나 자체 MACGGM·private-verifiable / Compact E-Cash=이중지불 시 신원노출) → 우리 최강 셀링포인트 **생존**. 남은 미검증은 Idemix/U-Prove 1차 인용뿐.

---

## 2. 경쟁 지형 요약

| 시스템 | 증명계 | Setup | 대상 포맷 | Nullifier | Revocation | **안 한 것** |
|---|---|---|---|---|---|---|
| **longfellow-zk** (Google; Frigo & shelat) | sumcheck + Ligero (MPC-in-the-head), SHA-256만 | **Transparent** (no setup) | **mdoc 전용** (plain JWT '26.4 추가, SD-JWT 아님) | 없음 | "future ZK list-membership"만 언급 | SD-JWT VC, nullifier 미구현 |
| **Crescent** (MS Research) | **Groth16** (+ECDSA용 Spartan) | **Trusted (회로별)** | generic JWT + mDL | 없음 | — | SD-JWT VC 아님, transparent 아님 |
| **zk-creds** (S&P 2023) | Groth16 | Trusted | 전자여권(ICAO 9303) | **재사용 시 신원노출**식 | 발급리스트에서 제거 | 표준 VC 포맷, blind nullifier 아님 |
| **zk-promises** (USENIX Sec 2025) | Groth16 | Trusted | 범용 zk-object 상태 | 커밋먼트 위 serial number | 콜백 기반 | 크리덴셜 포맷 아님, transparent 아님 |
| **BBS#** (eIDAS-2 타깃, '25) | BBS-family + Schnorr NIZK (pairing-free, q-SDH) | None(NIZK)·단 **발급/제시 시 이슈어 상호작용 필요** | 자체 BBS-family 서명 (mdoc/SD-JWT "호환" 주장) | pseudonyms (issuer-unlinkable) | accumulator 멤버십/비-멤버십 | **변형 안 된 ECDSA 크리덴셜 위 transparent ZK 아님** |
| **Cinderella** (S&P 2016) | Pinocchio zk-SNARK (QAP, pairing) | **Trusted (policy별)** | **X.509 / RSA-PKCS#1** | 없음 | — | SD-JWT/mdoc/JWT 부재(포맷이 후대), transparent 아님 |
| **(우리 작업)** | **longfellow (transparent)** | **None** | **SD-JWT VC + mdoc** | **issuer-unlinkable blind** | signed-range 비-멤버십 ⚠️*메커니즘=longfellow `MdocRevocationSpan`* | — (기여 = **통합** + SD-JWT VC 확장) |

---

## 3. 시스템별 상세 (검증 완료)

### 3.1 longfellow-zk — 가장 직접적인 기반, 그러나 mdoc 전용
- **증명계:** MPC-in-the-head(Ligero) + sumcheck 기반 검증가능연산으로 `C(x,w)=0` 증명. **CRS/trusted setup 없음**, **SHA-256 충돌저항만** 가정(비대화화는 Fiat-Shamir → ROM 휴리스틱). *[confidence: high]*
- **대상 포맷:** 논문 PDF 전수조사 결과 `jwt/json/sd-jwt/base64` **0회** vs `mdoc/18013` **39회**. selective disclosure는 오직 mdoc salted-hash로만 논의. 라이브러리 README는 "ISO MDOC, JWT, W3C VC" 3종을 타깃으로 명시 — **SD-JWT VC는 부재**. 로컬 클론 grep: `sd-jwt/sd_jwt/sdjwt` **0건**. *[high]*
- **핵심 novelty(그들의):** 발급자 인프라·기기 변경 없이, 비표준 가정 없이 **레거시 ECDSA(P-256) 보유증명을 ZK로** 한 최초. ECDSA 증명 ~20ms, 전체 mdoc presentation 수백 ms(모바일). *[high]*
- **안 한 것:** nullifier **미구현**. 'nullifier'는 논문 전체에서 단 1회, CL 참고문헌 항목으로만 등장. 배치발급(유저당 mdoc 수천 개)을 "우리가 피하는 비싼 대안"으로 언급. revocation은 "future ZK list-membership"으로만. *[high]*
- **인용 주의:** `draft-google-cfrg-libzk-01`은 **개인 제출 Informational I-D, 현재 expired**. "standard/standards-track" 아님 → "Internet-Draft"로 인용.
- 소스: cic.iacr.org/p/3/1/7 · eprint.iacr.org/2024/2010 · github.com/google/longfellow-zk · ietf.org/archive/id/draft-google-cfrg-libzk-01.html

### 3.2 Crescent (MS Research) — 가장 가까운 경쟁자
- 저자: Christian Paquin, Guru-Vamsi Policharla, Greg Zaverucha. *[high]*
- **하는 일:** 기존 **generic JWT + mDL**에 unlinkability·selective disclosure 부여. **prepare/show 모델** — 1회성 무거운 `prove`(Groth16 증명 생성·저장) + 가벼운 `show`(re-randomized presentation). 한 번 prepare로 무제한 unlinkable presentation. *[high]*
- **증명계/Setup:** 메인은 **Groth16 → 회로별 trusted setup**(`zksetup`). ECDSA device-binding 서브프루버에만 transparent Spartan 사용(하이브리드). **전체 시스템은 non-transparent.** *[high]*
- ⚠️ **주의할 함정:** 샘플에 `jwt_sd` 스키마(자체 SD 메커니즘 over plain JWT)가 있음 — 그러나 **IETF SD-JWT VC salted-hash 표준이 아님**. 리뷰어가 "Crescent도 SD 하잖아"로 공격 가능 → 차이를 명시적으로 기술할 것.
- 소스: github.com/microsoft/crescent-credentials · MS Research 블로그 · eprint.iacr.org/2024/2013

### 3.3 zk-creds (Rosenberg, White, Garman, Miers; IEEE S&P 2023)
- 기존 신분증(특히 **NFC 전자여권 ICAO 9303**, DG1을 ZK 안에서 파싱)을 익명 크리덴셜로 변환. 발급자 협조 불필요. *[high]*
- ⭐ **패러다임 차이(가장 중요한 구분선):** 원본 서명을 매 제시마다 직접 검증하는 게 **아님**. 크리덴셜 = 새 커밋먼트 `cred := Com(nk, rk, attrs; r)`(nk=pseudonym key, rk=rate key)를 **Merkle tree(=issuance list)의 leaf로 재발급**하고, 제시(ShowCred) 때는 **리스트 멤버십 + 술어**를 증명. 원본 문서(여권 RSA 서명)는 **발급 시 1회만** zk-supporting-documentation으로 검증(리스트 진입 정당화). → longfellow/Crescent/우리(원본 서명 직접 보유증명)와 **다른 축**. *[high]*
- **인프라:** 발급자 서명키 불요 — **bulletin board(블록체인/투명로그)**가 issuance list 관리, 누구나 감사 가능. (대안: ECDSA/Schnorr/**FROST(threshold)** signature-issued 모드.) 멤버십은 **Merkle forest**(트리 숲의 OR-proof)로 증명시간 ~50%↓(143ms). 멤버십 증명(460ms)이 ShowCred의 지배 비용. *[high]*
- **증명계:** **Groth16(trusted setup, statement별 CRS)** + 독립 기여인 **blind Groth16/LinkG16**(숨은 공통입력 공유 commit-and-prove → 비싼 멤버십 증명을 재랜덤화해 여러 show에 재사용). BLS12-381, Poseidon. **§5.6에서 trusted setup을 명시적으로 인정** — MPC ceremony+subversion-resistant로 완화하나 **제거 못 함**(= "no trusted issuer ≠ no trusted setup"의 교과서적 사례, §3.5 보강). JWT/SD-JWT/mdoc **0건**. *[high]*
- **Nullifier/gadget:** 지속 pseudonym `PRF_nk(ctx)`, rate-limit `tok=PRF_rk(epoch‖ctr)`(ctr<N), **clonewars식 cloning resistance**(`tok1=PRF_rk(epoch‖ctr)`, `tok2=id+H(nonce)·PRF'_rk(...)` — 재사용 시 두 식 연립으로 **id 노출 후 리스트 제거**). 여권엔 비밀 시드(nk/rk)가 없어 cloning resistance 불가 → 재발급 필요. → issuer-unlinkable blind nullifier가 **아님**. **hidden issuer** 기능 존재(여러 발급자 리스트 concat)하나 **동일 포맷 가정** 한계 → 우리 차이를 "표준 SD-JWT/mdoc 위 commitment+opening blind nullifier"로 정밀 분리할 것. *[high]*
- **Revocation:** 리스트에서 leaf 제거(`T.Remove(cred)`), 발급 수에 로그 비용. holder 공개신원 알려진 경우(=private key revocation, 도난 크리덴셜 차단). *[high]*
- 소스: eprint.iacr.org/2022/878.pdf · cs.purdue.edu/homes/clg/files/zk-creds.pdf · github.com/rozbb/zkcreds-rs

### 3.4 zk-promises (Shih, Rosenberg, Kailad, Miers; USENIX Security 2025)
- ⭐ **패러다임:** 크리덴셜 보유증명이 아니라 **프로그래머블 상태(stateful) 익명 계정** = **zk-object 모델**. 크리덴셜 포맷 시스템이 아니라 "trusted 서버에 둘 상태를 클라에 아웃소싱"하는 프레임워크. *[high]*
- **메커니즘(5단계):** (1) object = 임의 상태 + **serial number(=nullifier)**. (2) commitment를 **object bulletin board**(append-only log, 중앙 또는 블록체인)에 저장, 소유자는 opening 보관. (3) 갱신 = **oblivious copy-on-write**: 새 커밋 `obj'`+ZK 증명 `{obj∈T, sn=obj.sn(구버전 serial 공개→replay 차단), Φ(obj,obj')(유효 메서드 전이)}`. (4) **callback**(이 논문의 핵심): 유저가 random ticket `tik∈{0,1}²⁵⁶` 발행 → 서비스가 BB에 `(tik,인자)` 게시(예: 평판 −3) → 유저가 주기 scan으로 적용; 인증 시 "최근 scan 완료"도 증명. caller 공개키 서명으로 진위 검증, 두 번째 board `bb_cb`는 non-membership+rollover 필요. (5) 속성: confidentiality/obliviousness/integrity/atomicity/**backward anonymity**(ban 후에도 익명). 서버 검증 <4ms. *[high]*
- **Nullifier:** 업데이트마다 구버전 serial number(=nullifier) 공개로 replay/double-spend 방지. 공개 게시판의 **커밋먼트 위 Merkle 멤버십**. → "커밋먼트 위 serial number" 패턴(replay 방지용)이지 issuer-unlinkable blind nullifier가 **아님**. *[high]*
- **증명계:** NIZK `Setup(P)→(srs_P, srs_V, τ)` = **SRS+trapdoor = trusted setup**(구현 Groth16, Poseidon). 서명형엔 **pubkey-rerandomizable 서명**(EdDSA/ECDSA: `(x,P)→(rx,rP)`). *[high]*
- 소스: usenix.org/system/files/usenixsecurity25-shih.pdf · eprint.iacr.org/2024/1260.pdf · github.com/moshih/zk-promises

---

## 3.5 Trusted setup 심층 — 신뢰 모델과 "누가 셋업하는가" (cross-cutting)

> 경쟁자 중 Crescent·zk-creds·zk-promises가 모두 Groth16(trusted setup)이라, 이 축이 우리 transparent 접근의 가장 강한 차별점. related work / motivation에 직접 사용.

### 3.5.1 trusted setup이란
짧은 SNARK(Groth16, PLONK)는 증명 전에 **공개 파라미터 SRS/CRS**가 존재해야 함. SRS는 **비밀 난수(τ, α, β, γ, δ …, "toxic waste")**로부터 생성되며, SRS는 공개하되 비밀은 **반드시 폐기**해야 함. "trusted" = "이 비밀이 정말 폐기됐음을 믿어야 한다"는 뜻.

- **toxic waste 유출 시:** witness(진짜 크리덴셜) 없이도 검증 통과하는 가짜 증명 **위조 가능 → soundness 붕괴**. 신원 시스템에선 "유령 크리덴셜"로 검증자 기만(예: 보유하지도 않은 면허·연령 증명).
- **단, zero-knowledge(프라이버시)는 일반적으로 유지** — 깨지는 건 위조방지(soundness)지 은닉성이 아님. 그래도 신원 시스템엔 치명적.

### 3.5.2 셋업 스펙트럼
| 종류 | 예시 | 신뢰 가정 | 재사용 |
|---|---|---|---|
| 회로별(per-circuit) | **Groth16** (Crescent·zk-creds·zk-promises) | 회로/스테이트먼트마다 세리머니 | 회로 바뀌면 다시 |
| 범용·업데이트가능 | PLONK, Marlin, Sonic (KZG) | 1회 세리머니 | 크기 한도 내 모든 회로, 사후 추가기여 가능 |
| **투명(transparent)** | **Ligero+sumcheck (longfellow)**, STARK, Bulletproofs | **없음** (공개 난수=해시/Fiat-Shamir만) | 세리머니 자체가 없음 |

### 3.5.3 핵심: 이슈어–홀더–검증자 모델에서 셋업은 누가?
**가장 중요한 함정 — 세 당사자 중 누구도 단독으로 하면 안 됨:**
- **홀더(=prover)가 하면** toxic waste로 직접 위조 → 최악.
- **이슈어가 단독으로 하면** 그 포맷을 신뢰하는 **모든 검증자**가 이슈어의 정직성에 인질. 이슈어가 가짜 증명을 찍거나 trapdoor를 흘리면 생태계 전체 붕괴.
- **검증자가 하면** 다른 검증자/홀더가 그를 신뢰해야 함.

**현실 모델(Groth16/Crescent):**
- 셋업은 **크리덴셜 포맷/스키마(회로 템플릿)당 1회**, 특정 이슈어-홀더 쌍이 아니라 **포맷 단위**로 수행 → 같은 포맷의 모든 이슈어·홀더·검증자가 공유.
- Crescent 아키텍처엔 세 역할과 **분리된 "setup service"**가 별도 존재(`zksetup` 실행, proving key→홀더 배포 / verification key→검증자 배포).
- 이상적으로는 **다자 MPC 세리머니(powers-of-tau류)**로 수행 — 이슈어·검증자·제3자 다수가 순차 기여하고 **1-of-N(한 명만 정직히 폐기)** 가정 충족 시 안전. 단일 당사자가 toxic waste를 쥐면 안 됨.
- 즉 답: **"중립적 제3자/표준화 컨소시엄, 또는 다자 세리머니"** — 신원 3자 중 누구도 단독으로 하지 않음(해선 안 됨).

**⚠️ 자주 하는 오해 — "SRS는 이슈어가 만든다"는 틀림:**
- SRS 생성은 **회로(R1CS)만 있으면** 됨. 회로는 공개 정보이고, 셋업 trapdoor(toxic waste)는 **그 자리서 새로 뽑은 난수**지 **이슈어의 서명 개인키가 아님**. 회로는 이슈어의 *공개키*만 검증함(public input 또는 회로에 박힘). → **이슈어는 SRS 생성의 critical path에 수학적으로 없음.** (공개키를 public input으로 두면 SRS는 이슈어-비특정 → 한 SRS로 여러 이슈어 키 커버 가능.)
- 정확한 명제: **"이슈어가 꼭 한다"가 아니라 "누군가는 반드시 한다"**. 그 누군가(이슈어/제3자/컨소시엄)가 누구든 **새 신뢰 루트**가 생긴다. 단일 이슈어 시나리오(예: 대학 졸업증명)에선 검증자가 이미 그 이슈어를 신뢰하므로 **이슈어가 떠맡는 게 자연스럽지만, 이는 배포 선택이지 요구사항이 아님.**
- **부트스트랩 의존성:** Crescent는 해당 크리덴셜 회로의 SRS가 존재하기 전엔 ZK 제시 불가(누군가 만들 때까지 대기). longfellow는 회로 스펙만 합의되면 즉시 동작 → 이 의존성 없음.
- **양 시스템 공통 주의:** "이슈어가 합의/행동할 게 없다"는 longfellow만의 장점이 **아님** — Crescent도 이슈어는 표준 서명만 하면 됨. 진짜 차이는 *발급자 행동*이 아니라 *홀더↔검증자 공유물의 성격*(회로뿐 vs 회로+신뢰해야 할 SRS).

> **신뢰 표면(trust surface) 비교 — 논문용:** longfellow에서 검증자가 신뢰하는 것은 **발급자 공개키뿐**(+SHA-256·ROM 표준 가정) = 평범한 SSI의 신뢰 루트와 동일. Groth16 계열은 여기에 **"어떤 당사자가 만든 SRS의 무결성"**이라는 신뢰 루트가 하나 더 얹힘. 회로 자체는 어느 쪽이든 prover↔verifier 간 공개 합의일 뿐 발급자 행위를 요구하지 않는다.

### 3.5.4 분산 SSI 생태계에서의 함정 → 우리 논거
- 독립 이슈어·검증자가 다수인 **개방형 SSI**에선 "모두가 동의하는 셋업 권위자"를 정하는 것 자체가 거버넌스 난제. 세리머니 무결성·toxic waste 폐기를 생태계 전체가 영구히 신뢰해야 함(감사·규제 부담).
- **longfellow(transparent)의 답: "셋업하는 사람이 없다."** 공유 파라미터는 표준 해시함수(SHA-256, 공개)뿐 — 비밀·세리머니·셋업 권위자 부재. 신뢰할 제3자 없이 이슈어가 기존 ECDSA 서명만 찍으면 즉시 동작.

> **논문용 문장:** *"Groth16 기반 시스템은 크리덴셜 포맷마다 신뢰된 셋업 권위자(또는 1-of-N MPC 세리머니)를 요구하며, 이는 다수의 독립 이슈어·검증자를 갖는 개방형 신원 생태계에서 거버넌스·감사 부담이 된다. transparent ZK는 셋업 권위자를 제거하여 — toxic waste도, 세리머니도, 신뢰할 제3자도 없이 — 이 부담 자체를 소거한다."*

---

## 3.6 배포/신뢰 비교 매트릭스 (cross-cutting) — "키·인프라 바꿔야 하나"

> §2 표는 증명계·포맷 중심. 이 표는 **암호키 변경 / 이슈어 인프라 / 추가 인프라 / phone-home / 신뢰 표면** 중심 — 리뷰어의 "왜 굳이 transparent인가" 질문에 직접 답하는 배포 관점.

| 척도 | **longfellow** | **Crescent** | **zk-creds** | **zk-promises** | **(우리)** |
|---|---|---|---|---|---|
| 이슈어 서명키/암호 변경 | ❌ 불요(기존 ECDSA-P256) | ❌ 불요(기존 RS256/ES256) | ❌ 불요(여권 RSA 부트스트랩) | △ 별개모델(SP는 rerand 서명) | ❌ 불요(기존 ECDSA/SD-JWT) |
| 발급 시 이슈어 협조·인프라 변경 | ❌ 전혀(ZK 몰라도 됨) | ❌ 불요 | ❌ 발급자 불요(BB가 발급) | ⚠️ SP가 시스템 전체 운영 | ❌ 불요 |
| 추가 인프라(append-only log/BB) | ❌ 없음 | ❌ 없음 | ✅ bulletin board | ✅✅ **2개 BB**+rollover | ❌ 없음 |
| **Trusted setup** | ❌ **없음(transparent)** | ✅ Groth16 회로별 | ✅ Groth16 statement/gadget별 | ✅ SRS+trapdoor(Groth16) | ❌ **없음** |
| 증명계 | Ligero+sumcheck | Groth16(+Spartan) | Groth16+LinkG16 | zkSNARK SRS(Groth16) | Ligero+sumcheck |
| 표준 크리덴셜 포맷 직접? | ✅ ISO mdoc | ✅ generic JWT+mDL | ❌ 여권→**재커밋** | ❌ 포맷 아님(계정상태) | ✅ **SD-JWT VC+mdoc** |
| 증명 패러다임 | 원본서명 직접 보유증명 | 원본서명(prepare→show) | 재커밋→리스트 멤버십 | 상태객체→멤버십+전이 | 원본서명 직접 |
| 제시 시 이슈어/서버 관여(phone-home) | ❌ 없음 | ❌ 없음 | ❌ 없음(BB root만) | ⚠️ scan·callback 지속 관여 | ❌ 없음 |
| 동적 상태(state) | 없음 | 없음 | 제한(rate/pseudonym) | ✅✅ Turing-complete+비동기 | 없음(정적 보유증명) |
| 신뢰 표면(검증자가 믿을 것) | **발급자 공개키뿐** | +SRS 무결성 | +SRS+BB 무결성 | +SRS+BB(들)+SP | **발급자 공개키뿐** |

**핵심 결론:**
1. **"올클린" = longfellow/우리뿐** — 키 무변경 + 발급자 협조 무 + 추가 인프라 무 + trusted setup 무 + 표준 포맷 직접 + phone-home 무. 나머지 셋은 모두 trusted setup 요구, zk-creds·zk-promises는 추가로 bulletin board 인프라까지.
2. **zk-creds/zk-promises는 "재커밋·상태머신" 패러다임** → 우리(원본 서명 직접)와 비교 대상이나 다른 축. "이들은 새 커밋/계정으로 재발급, 우리는 기존 SD-JWT/mdoc 서명에 직접"으로 선 그을 것.
3. **상태(state) 축은 zk-promises 우월** — 우리는 정적 보유증명이라 reputation/ban은 범위 밖. 약점이 아니라 **scope 차이**로 명시(우리=SSI presentation, 저들=stateful account).

---

## 4. 폐기된(refute된) 주장 — 사실 아님, 쓰지 말 것
- ❌ "longfellow 레포에 nullifier/revocation/SD 언급이 전혀 없다" → **0-3 폐기**. 레포에는 mdoc_revocation 등 관련 회로가 존재함(SD-JWT가 없을 뿐).
- ❌ "libzk 스펙 문서는 포맷-불가지론적이라 mdoc/ECDSA 언급이 전혀 없다" → **0-3 폐기**.

---

## 5. 우리가 주장할 정밀 novelty 문장

> We present the first system to apply **transparent (no-trusted-setup) zero-knowledge** to the **IETF SD-JWT VC** credential format (JSON/JWS/base64url/salted-hash), and to **unify selective disclosure, attribute predicates, issuer-unlinkable (commitment+opening) nullifiers, and signed-range non-membership revocation in a single framework spanning both SD-JWT VC and ISO mdoc.**

근거: 조사된 어떤 시스템도 이 네 속성을 *전부, transparent하게, 두 포맷에* 묶지 않음. longfellow=transparent지만 mdoc-only·nullifier 없음 / Crescent=JWT·mDL unlinkability지만 Groth16·trusted-setup·SD-JWT 아님 / zk-creds·zk-promises=nullifier 패턴이지만 Groth16·trusted-setup이고 표준 포맷 위 blind nullifier 아님 / BBS#=mdoc·SD-JWT 호환 full-unlinkability지만 BBS-family 서명+이슈어 상호작용 필요(변형 안 된 ECDSA 위 transparent ZK 아님).

> **2차 반영 — load-bearing novelty 재정의:** 위 문장에서 *가장 무게를 견디는* 부분은 (a) **변형 안 된 표준 SD-JWT VC + mdoc** 위에 (b) **transparent ZK로** (c) **issuer-unlinkable blind nullifier**까지 통합한 점이다. **revocation의 signed-range는 novelty 주장에서 빼고** longfellow `MdocRevocationSpan`을 선행연구로 인용한 뒤 "SD-JWT VC로의 확장 + 통합"으로만 기여를 잡을 것. predicate·selective disclosure도 단독으로는 novel 아님 → "통합"과 "blind nullifier"가 핵심 셀링포인트.

> **3차 확정 — blind nullifier 주장 문장(과장 없는 버전, 그대로 사용 가능):**
> *"We present, to the best of our knowledge, the first **issuer-unlinkable per-context blind nullifier** that is bound to an **unmodified standard credential (IETF SD-JWT VC / ISO mdoc)** and proven in a **transparent (no-trusted-setup) zero-knowledge** system. Unlike e-cash double-spend tags (Compact E-Cash) it **never de-anonymizes the holder**; unlike PLUME/Semaphore nullifiers it is bound to an **issuer-signed standard credential** rather than a self-held keypair or bespoke Merkle membership; and unlike Privacy Pass / ARC rate-limit tags it is **publicly verifiable in transparent ZK** rather than privately verifiable under a shared issuer secret."*

---

## 6. 출판 전 반드시 처리할 리스크
1. **움직이는 타깃:** longfellow upstream이 '26.4월 plain-JWT 회로 모듈(commit c849531) 추가. **SD-JWT는 아직 아님.** 제출 직전 최신 커밋 재확인 + novelty 주장에 날짜 명시("as of …").
2. **인용 정확성:** libzk I-D는 expired 개인제출 → "Internet-Draft"로만. longfellow는 peer-reviewed(IACR CiC)로 인용 가능.
3. **Crescent `jwt_sd` 구분:** Crescent의 SD는 자체 ZK 메커니즘 over plain JWT ≠ IETF SD-JWT 표준. 명시적으로 선 그을 것.
4. **⚠️ Revocation 메커니즘은 longfellow 자체 것:** signed-range 비-멤버십 = longfellow `MdocRevocationSpan`(Frigo가 '26-04-14 커밋, RWC "signed pairs of adjacent revocation IDs"). **반드시 선행연구로 인용**하고 우리 기여는 "SD-JWT VC로의 확장 + SD-JWT VC·mdoc 통합"으로 재포지셔닝. "새 메커니즘"이라 주장하면 즉시 반박당함. (우리 레포 `mdoc-revocation_analysis-report.md:12`도 이미 동일함을 인정.)
5. **BBS#가 가장 위협적 경쟁자:** mdoc/SD-JWT 호환 + full issuer-unlinkability를 이미 주장. 차별화 문단 필수 → "우리는 **변형 안 된 표준 ECDSA 서명 크리덴셜** 위 transparent ZK. BBS#는 BBS-family ZKP-서명 + **발급/제시 시 이슈어 상호작용** 필요(server-aided), q-SDH 구조적 가정." motivation/related-work에 명시.
6. **✅ GAP 3 검증 완료 — novelty 생존:** PLUME/Semaphore/ARC/Compact E-Cash 1차 소스 확인. "표준 포맷 위 issuer-unlinkable blind nullifier + transparent ZK" 미적용 확정. 단 (a) **ARC**(가장 근접)와 차별화 문단 필수 — ARC는 자체 MACGGM·**private-verifiable**(이슈어=검증자 공유키)이라 publicly-verifiable transparent ZK 아님. (b) 주장은 "to the best of our knowledge"로(§5 문장).
7. **Idemix/U-Prove 미검증:** 1·2·3차 모두 검증 클레임 0 → 교과서적 이해는 provisional. 논문에선 1차 문헌(CL 2001/2002, Idemix 스펙, Brands 2000 / MS U-Prove Crypto Spec) 직접 인용 후 사용, 사실로 단정 금지.

---

## 7. 딥리서치 결과 — 갭별 판정 (1·2·3차, 2026-05-31 완료)

**종합:** 세 갭 모두 novelty를 *포기*가 아니라 *좁혀야* 한다. 살아남는 핵심 = **"변형 안 된 표준 SD-JWT VC + mdoc 위에 transparent ZK로 selective disclosure + predicate + issuer-unlinkable blind nullifier + signed-range revocation을 단일 프레임워크로 통합."**

### GAP 1 — 경쟁 익명 크리덴셜 → **좁혀서 생존** ✅
- BBS/BBS+/**BBS#**/CL/Idemix/U-Prove/Cinderella 전부 **자체 포맷 또는 레거시 PKI**(Cinderella→X.509)에 묶임. 변형 안 된 SD-JWT/mdoc 위 transparent ZK 아님.
- **batch issuance**가 SD-JWT/mdoc의 유일한 배포/표준 unlinkability 수단 → **verifier unlinkability만**, issuer unlinkability는 안 됨. OpenID4VCI 1.0(`2025-09-16` final)·RFC 9901 §10.1·HAIP 1.0(`batch_credential_issuance`)·EUDI ARF에 명시. 비용 = presentation마다 일회용 크리덴셜 1개 소비(고유 salt + 키바인딩 키).
- **가장 위협적 → BBS#** (eprint 2025/619, NIST WPEC'24): pairing-free(MACBBS), P-256 SE 키 사용, mdoc/SD-JWT "호환" + full issuer-unlinkability + everlasting privacy. **단 BBS-family ZKP-서명 + 발급/제시 시 이슈어 상호작용(server-aided) 필요**, q-SDH 구조 가정 → *변형 안 된 ECDSA 크리덴셜 위 transparent ZK*가 우리 차별점.
- **모티베이션 자산:** 16명 학자(Camenisch·Lysyanskaya·shelat·Preneel·Tessaro·Troncoso 등)가 '24-06 EUDI Wallet에 BBS 채택 권고 + "salted-hash(SD-JWT/mdoc)는 unlinkability(eIDAS-2 필수요건) 불충족" 명시 → 우리 문제의식 정당화에 직접 인용.

### GAP 2 — Revocation → ⚠️ **메커니즘은 novel 아님, 반드시 좁힐 것**
- signed-range 비-멤버십 = **longfellow 자체 프리미티브.** Frigo-Shelat RWC "signed pairs of adjacent revocation IDs" + 클론 디스크에 **완성된 `MdocRevocationSpan` 클래스**(`longfellow-zk/lib/circuits/tests/mdoc/mdoc_revocation.h`, Frigo가 '26-04-14 커밋 c8495312). CRA 서명을 in-circuit ECDSA 검증 후 `l < rev_id < r` 단언. 우리 레포 리포트도 동일성 이미 인정.
- 경쟁(BBS#, FBK eprint 2025/549)은 **accumulator** 멤버십/비-멤버십 사용 → signed-range와는 별개. accumulator-on-표준포맷 자체도 novel 아님(2025/549에서 refute됨).
- **생존 가능 기여:** SD-JWT VC로의 적용 + SD-JWT VC·mdoc 통합. **"새 메커니즘" 주장 금지, `MdocRevocationSpan` 인용 필수.**

### GAP 3 — issuer-unlinkable blind nullifier → ✅ **생존 (3차 검증 완료)**
"issuer-untraceable per-context nullifier + 표준 포맷 바인딩 + transparent ZK" **3축을 동시에 만족하는 선행연구 없음** → **우리 최강 novelty 확정.** 후보별 탈락:

| 후보 | per-context nullifier | issuer-untraceable | 표준 포맷 바인딩 | transparent | 탈락 이유 |
|---|:---:|:---:|:---:|:---:|---|
| **PLUME** (ePrint 2022/1255) | ✅ `hash[m,pk]^sk` | N/A | ❌ self-held secp256k1 | ✅ | 발급자·크리덴셜 자체가 없음 |
| **Semaphore** | ✅ `hash(scope, sk)` | ❌ admin이 leaf 앎 | ❌ 자체 Merkle 멤버십 | ❌ Groth16 | 3축 모두 탈락 |
| **ARC** (Privacy Pass draft) | ✅ per-context tag | △ 주장하나 weak | ❌ 자체 MACGGM(KVAC) | ❌ **private-verifiable** | 메커니즘 최근접이나 자체포맷+이슈어=검증자 공유키 |
| **Compact E-Cash** (CHL05) | △ per-coin serial | ❌ 이중지불 시 신원노출 | ❌ 자체 CL 코인(Strong-RSA) | ❌ | de-anonymize on reuse, traceable 변형 존재 |
| **(우리)** | ✅ commitment+opening | ✅ 절대 비노출 | ✅ SD-JWT VC+mdoc | ✅ Ligero+sumcheck | — |

- **가장 위협적 = ARC** (Anonymous Rate-Limited Credentials). nullifier 메커니즘(per-context `tag=(m1+nonce)⁻¹·HashToGroup(ctx)` + issuer-Client unlinkability 주장)이 가장 가깝다. **그러나 두 축에서 다름:** (1) 자체 MACGGM 알지브레익-MAC 크리덴셜에만 바인딩(SD-JWT/mdoc 아님), (2) **keyed/privately verifiable** — Issuer=Origin이 같은 비밀키 보유, 스펙상 "tokens not publicly verifiable" → transparent **publicly**-verifiable ZK의 정반대. (강한 해석 "ARC=우리 blind nullifier"는 적대검증에서 **1-2 refute**됨.)
- **Compact E-Cash는 위협이 아니라 대조점:** serial number는 정직한 경우에만 unlinkable, **이중지불 시 `T=skU+R·t` 연립으로 `skU` 노출 → 신원 완전 공개**(+traceable 변형은 은행이 withdrawal 기록으로 전체 코인 추적). 우리 blind nullifier는 **절대 de-anonymize 안 함** → 정반대 = 좋은 대조 인용.
- PLUME/Semaphore: per-context nullifier는 맞지만 **self-held 키 / 자체 Merkle 멤버십**에 묶임(발급자 서명 크리덴셜 아님), Semaphore는 추가로 Groth16·admin이 leaf 앎.

### 남은 OPEN — 제출 전 마무리
1. ~~GAP 3 전용 검증~~ → ✅ **3차 완료**(위 표).
2. **Idemix/U-Prove 1차 인용(미검증):** 1·2·3차 모두 검증 클레임 0. 교과서적 이해(Idemix=CL/Strong-RSA·멀티쇼 unlinkable·자체포맷·accumulator revocation / U-Prove=Brands·DL·원쇼·재사용 시 linkable·자체포맷)는 **provisional** → 논문에선 **1차 문헌 직접 인용**(Camenisch-Lysyanskaya 2001/2002, Idemix 스펙, Brands 2000 / MS U-Prove Crypto Spec) 후 사용. 사실로 단정 금지.
3. **우리 blind nullifier의 형식적 우위:** 커밋먼트+오프닝이 zk-promises serial-over-commitment, BBS# pseudonym, ARC tag 대비 *형식적으로* 왜 더 강한 issuer-untraceability인지 정의·증명 스케치(가장 무게 견디는 보안 주장).
4. **revocation 잔존 novelty 정량화:** `MdocRevocationSpan`(mdoc)→SD-JWT VC 이식이 새 회로/구성인지 단순 포팅인지 — 메커니즘 양보 후 남는 엔지니어링·암호학적 기여 명확화.

---

## 8. 참고문헌 / 소스 (1차)
- Frigo & shelat, *Anonymous Credentials from ECDSA* — IACR CiC: https://cic.iacr.org/p/3/1/7 · ePrint 2024/2010: https://eprint.iacr.org/2024/2010
- IETF `draft-google-cfrg-libzk-01` (expired I-D): https://www.ietf.org/archive/id/draft-google-cfrg-libzk-01.html
- longfellow-zk 레포: https://github.com/google/longfellow-zk
- Crescent: https://github.com/microsoft/crescent-credentials · MSR blog · ePrint 2024/2013: https://eprint.iacr.org/2024/2013
- zk-creds: https://eprint.iacr.org/2022/878.pdf (IEEE S&P 2023)
- zk-promises: https://eprint.iacr.org/2024/1260.pdf · https://github.com/moshih/zk-promises (USENIX Sec 2025)
- (2차용) IETF Token Status List: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/ · Privacy Pass ARC: https://datatracker.ietf.org/doc/draft-yun-privacypass-arc/ · Semaphore glossary · anoncreds-v2-rs

### 2차 소스
- **BBS#** — eprint 2025/619: https://eprint.iacr.org/2025/619.pdf · NIST WPEC 2024 슬라이드(Jacques, "BBS# & eIDAS2"): https://csrc.nist.gov/csrc/media/presentations/2024/wpec2024-3b3/images-media/wpec2024-3b3-slides-antoine-jacques--BBS-sharp-eIDAS2.pdf · server-aided 분류 eprint 2025/513: https://eprint.iacr.org/2025/513
- **Cinderella** (Delignat-Lavaud et al., S&P 2016): https://www.microsoft.com/en-us/research/wp-content/uploads/2016/06/cinderella-1.pdf
- **ETSI TR 119476-1 V1.3.1** (unlinkability·batch issuance·longfellow revocation 분석): https://www.etsi.org/deliver/etsi_tr/119400_119499/11947601/01.03.01_60/tr_11947601v010301p.pdf
- **OpenID4VCI 1.0**: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html · **HAIP 1.0**: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html
- **16인 암호학자 EUDI 권고** (GitHub Discussion #211): https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/discussions/211
- **accumulator revocation for SD-JWT/mDOC** — FBK eprint 2025/549: https://eprint.iacr.org/2025/549.pdf
- **longfellow `MdocRevocationSpan`** (선행연구로 인용 필수): `longfellow-zk/lib/circuits/tests/mdoc/mdoc_revocation.h` (Frigo, commit c8495312, 2026-04-14)
### 3차 소스
- **PLUME** (ECDSA nullifier, Gupta & Gurkan) — ePrint 2022/1255: https://eprint.iacr.org/2022/1255 · ERC-7524: https://eips.ethereum.org/EIPS/eip-7524
- **Semaphore** (PSE) — glossary: https://docs.semaphore.pse.dev/glossary · contracts: https://docs.semaphore.pse.dev/technical-reference/contracts
- **ARC** (Privacy Pass Anonymous Rate-Limited Credentials) — protocol: https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-protocol.html · crypto draft: https://datatracker.ietf.org/doc/html/draft-yun-privacypass-crypto-arc-00
- **Compact E-Cash** (Camenisch-Hohenberger-Lysyanskaya, Eurocrypt 2005) — full: https://cs.brown.edu/people/alysyans/papers/chl05-full.pdf · ePrint 2005/060: https://eprint.iacr.org/2005/060
- (Idemix/U-Prove — 1차 인용 필요·본 조사 미검증) CL signatures: https://cs.brown.edu/people/alysyans/papers/cl04.pdf · MS U-Prove overview: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/U-Prove20Technology20Overview20V1.120Revision202.pdf
