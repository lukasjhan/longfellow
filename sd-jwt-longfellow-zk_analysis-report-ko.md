# SD-JWT-VC × Longfellow-ZK 분석 보고서

> 대상: `playground/` — Longfellow-ZK의 mdoc 선택공개 ZK 기법을 **SD-JWT-VC**에 이식한 구현
> 위치: `/home/unknown/longfellow/playground`
> 작성일: 2026-05-24 · 상태: 보안 리뷰 후 하드닝 진행 중
> 상위 라이브러리 분석은 [`longfellow-zk_analysis-report-ko.md`](longfellow-zk_analysis-report-ko.md) 참조

---

## 1. 한눈에 요약 (TL;DR)

Longfellow-ZK는 **mdoc(ISO 18013-5)** 에 대해서만 공개 API를 제공한다(JWT 회로는 실험용). 이
프로젝트는 그 **핵심 철학(JSON/CBOR을 회로에서 파싱하지 않고, 발급자가 서명한
다이제스트 집합에 대한 "멤버십"으로 선택공개를 환원)** 과 **2회로 + MAC 아키텍처**를
**SD-JWT-VC**로 그대로 이식한다.

- 증명 대상: 표준 SD-JWT-VC(`_sd` Disclosure 멤버십) + 유효기간(exp) + Key Binding +
  sd_hash 바인딩 + vct + **nonce/aud(freshness)** + N가변 다속성.
- 아키텍처: mdoc과 동일하게 **Fp256 서명 회로 + GF(2¹²⁸) 해시 회로**를 MAC으로 결속.
- 모든 값 타입(문자/숫자/불리언/날짜)을 파싱 없이 멤버십으로 처리.
- 성숙도: **실험/연구용**(공개 API 없음, 데모 CLI). 본 보고서 기준 두 건의 soundness
  하드닝(exp, nonce/aud)을 적용했고 남은 항목은 §9에 정리.

---

## 2. 무엇을 prove / verify 하나

**증명자(홀더)** 가 **검증자**에게 토큰 원문을 보이지 않고 "유효한 크레덴셜을 보유하며
그중 일부 속성이 특정 값이다"를 증명한다. 검증자는 **공개입력 + proof만** 보고
ACCEPT/REJECT를 결정한다(크레덴셜·서명·나머지 속성은 못 봄).

핵심: 회로는 JSON을 파싱하지 않는다. **`SHA(disclosure) ∈ payload._sd`(발급자 서명으로
보증된 집합에 대한 멤버십)** + 여러 **앵커 검사**로 명제를 환원한다.

### 2.1 공개 vs 비공개 (ZK 경계)

| 공개 (검증자가 보거나 고름) | 비공개 (witness, 숨김) |
|---|---|
| 발급자 공개키 `pkX·pkY` | 발급자 서명 (r,s) |
| `now` (검증 시각) | **exp 실제 값** (`now≤exp` 술어만 노출) |
| `vct` (기대 타입) | 홀더 KB 서명 |
| **`nonce`·`aud`** (검증자 챌린지) | 디바이스 키 `dpkx·dpky` |
| 공개할 `(claim 이름, 값)` × N | salt들, sd_hash |
| `e2` (KB 해시), MAC들 | **공개 안 한 다른 모든 claim/disclosure** |
| | payload 원문, presented 묶음, 토큰 전체 |

> "given_name=Erika"는 **공개**(선택공개의 본질). 숨기는 것은 서명·salt·디바이스키·
> **나머지 claim**·원문이다. exp는 값을 숨긴 채 `now≤exp` 술어만 증명한다.

### 2.2 회로가 증명하는 명제(전체)

1. 발급자 `(pkX,pkY)`가 payload `P`에 ES256 서명 — sig회로 `verify3(e)` + hash회로
   `SHA(header.payload)==e`, `e`는 MAC으로 두 회로 결속.
2. `P`에 `vct == <공개 vct>`.
3. `P`에 `exp`가 있고 `now ≤ exp`.
4. `P`의 `cnf.jwk == 디바이스키 (dpkx,dpky)`.
5. 홀더가 그 디바이스키로 KB-JWT에 ES256 서명, 그 해시가 `e2` (sig회로).
6. KB payload에 `nonce==<공개 nonce>`, `aud==<공개 aud>`.
7. KB payload의 `sd_hash == SHA(presented 묶음)`.
8. 공개 claim마다: `SHA(disclosure) ∈ P._sd`(멤버십) + disclosure가
   `[salt,<공개 이름>,<공개 값>]`로 디코드(구조) + disclosure ∈ presented(consent).

---

## 3. 아키텍처: 두 회로 + MAC (mdoc과 동일)

| | 서명 회로 | 해시 회로 |
|---|---|---|
| 체 | `Fp256Base` (P-256) | `f_128` = GF(2¹²⁸) |
| 담당 | 발급자 ES256 + 홀더 KB ES256 | SHA + exp + vct + cnf + sd_hash + nonce/aud + N×(멤버십·구조·consent) |
| 왜 분리 | ECDSA는 P-256 산술이 자연스러움 | SHA/비트연산은 이진체가 ~5배 저렴 |

두 회로는 공통값 `e / dpkx / dpky`에 대한 **MAC**으로 결속한다. 프루버는 commit 전에
자기 MAC 키 절반 `a_p`와 그 값들에 커밋하고, `a_v`는 **commit 이후 트랜스크립트에서
유도**되므로 두 회로에 서로 다른 값을 못 넣는다(Schwartz–Zippel, 위조확률 ≤ 2⁻¹²⁸).
`e2`는 양 회로 공개입력. (mdoc `mdoc_zk.cc`의 `generate_mac_key`/`compute_macs`와 동치.)

측정(3속성, split): prove ≈ 1.6–2.0s, 번들 ≈ 386KB(sig 194 + hash 192). monolithic
단일 Fp256(`sdjwt_full`)은 ≈ 13s로, 분리가 ~8배 빠르다.

---

## 4. 할 수 있는 것 / 없는 것

| ✅ 할 수 있다 | ❌ 못 한다 (한계) |
|---|---|
| N개 속성 선택공개(문자/숫자/불리언/날짜) | **값 술어/범위증명**: "age≥18"을 생년월일로 증명 불가. `age_over_18`은 발급자가 미리 넣은 불리언이라 되는 것 |
| 발급자 서명 유효성 증명(서명 숨김) | 값 비교/산술 — 회로는 **값 동등**만 |
| 홀더 바인딩(KB) 증명(키·서명 숨김) | **revocation/status** 확인 |
| `now≤exp` 증명(exp 값 숨김) | **nbf(not-before)** — exp 상한만 |
| vct·nonce·aud를 검증자 값과 대조 | **alg 민첩성** — ES256/P-256/SHA-256 하드코딩 |
| 나머지 claim·원문·salt·서명 숨김 | **익명 발급자** 불가 — 검증자는 pkX,pkY를 알아야 함 |
| 재생/audience 방지(nonce/aud 결속) | 여러 크레덴셜 교차 술어 |
| 고정 크기 proof(프라이버시 균일성) | **어떤 속성을 몇 개** 공개하는지는 노출(N별 회로 컴파일) |
| | nested 값은 통째로 공개(부분 선택공개 불가) |

### 4.1 검증자 표준 점검(5단계) 관점

검증자가 보통 하는 5가지를 **(A) 이 구현이 하는 것** vs **(B) ZK 원리상 가능하나 미구현** 으로 매핑:

| 검증 항목 | 이 구현 | ZK 원리상 | 비고 |
|---|---|---|---|
| 1. 이슈어 서명 | ✅ 완전 | ✅ | longfellow의 핵심. 서명을 숨긴 채 "이 pk로 검증되는 유효 서명 존재" 증명 |
| 2. 값 검증 (성인=true) | ⚠️ **동등(equality)만** | ✅ 술어/범위도 가능 | 아래 |
| 3. 만료 | ✅ `now ≤ exp` | ✅ | exp 값은 숨기고 술어만. **nbf** 미검사, 상한만 |
| 4. revoke | ❌ **없음** | ✅ 가능(인프라 필요) | 아래 |
| 5. 이슈어 신뢰 | ✅ (검증자가 pk 지정) | ✅ "신뢰목록 중 하나" 숨김도 가능 | 아래 / §8.2 |

- **값 검증** — *동등*("claim = 공개값")만 됨. `age_over_18=true`는 이슈어가 미리 그 불리언을 박아둬서 되는 것. 값에서 **유도/범위**(생년월일→"나이≥18")는 이 회로에 **없음**(단 range proof 자체는 ZK 친화적). (`now≤exp`는 그 claim 하나를 위한 전용 숫자비교지 일반 기능이 아님.)
- **revoke** — 회로에 status/revocation 검사 없음. ZK로 *가능*(예: SD-JWT-VC **Token Status List**: 인덱스를 숨기고 "내 상태=미취소" 증명, 또는 accumulator/Merkle 비멤버십) 하지만 신규 회로 + 검증자의 **최신 status list** 보유가 필요. revocation과 unlinkability는 본질적으로 상충(상태 인덱스를 노출하면 재링크됨).
- **이슈어 신뢰** — 검증자가 신뢰 이슈어의 pk를 공개입력으로 주고, 회로는 "그 pk로 서명됨"을 증명. 신뢰 판단은 out-of-band(검증자의 신뢰목록). *어느* 신뢰 이슈어인지 숨기는 것(신뢰 앵커 집합 멤버십)은 원리상 가능하나 미구현 — §8.2 참고.

---

## 5. mdoc(원본·검증됨)과 비교

| 항목 | mdoc (longfellow 원본) | SD-JWT-VC (이 작업) |
|---|---|---|
| 포맷 | ISO 18013-5 (CBOR) | SD-JWT-VC (JSON/base64url) |
| 공개 단위 | `IssuerSignedItem=[digestID,salt,id,value]` | `Disclosure=base64url([salt,name,value])` |
| 서명된 다이제스트 집합 | MSO `valueDigests` | payload `_sd` |
| 발급자 서명 | ECDSA P-256 over MSO | ECDSA P-256 over header.payload |
| 홀더 바인딩 | 디바이스 서명 **over 세션 transcript** (공개 `htr`) | KB-JWT 서명 + **nonce/aud 공개입력** |
| 재생 방지 | transcript(검증자 핸드오버)에 결속 | nonce/aud에 결속 (메커니즘만 다름) |
| 유효기간 | `validFrom ≤ now ≤ validUntil` | `now ≤ exp`만 (nbf 없음) |
| 타입 식별 | doctype | vct (인-서킷 검사) |
| 아키텍처 | 2회로(Fp256+GF2¹²⁸)+MAC | **동일(이식)** |
| 공개 API | 있음 (`run_mdoc_prover/verifier`) | 없음 (실험 CLI) |
| 성숙도 | 프로덕션·정밀 검토·외부 감사 | 연구·리뷰 후 하드닝 중 |

가장 큰 의미 차이: mdoc은 디바이스 서명을 **세션 transcript**(검증자 임시키 포함)에
묶어 세션 결속이 강하다. 이 구현은 nonce/aud로 같은 목표를 달성하되 결속 대상이
다르다(transcript 전체 vs nonce/aud 필드). 또 mdoc은 유효기간을 상·하한 모두 검사한다.

---

## 6. Free-index soundness (현재 상태)

회로는 호스트가 준 **private 인덱스**로 버퍼를 가리키고 그 자리 바이트만 검사한다.
인덱스마다 "엉뚱한 곳을 가리켜 거짓을 증명할 수 있는가?"의 **안전 근거**를 명시한다.

용어:
- **리터럴 앵커**: 검사 패턴에 JSON 키(예: `"vct":"`)가 포함돼, 그 위치가 진짜 필드일
  때만 통과 → 인덱스가 자명하게 고정된다.
- **값 앵커**: 추출 바이트가 다른 곳에서 보증된 값(MAC-linked dpk 등)과 같아야 통과.
- **해시 보증**: 추출 32바이트가 `SHA(witness)`와 같아야 통과 → 엉뚱하게 가리키면
  목표가 prover가 못 고르는 값이 되어 **SHA 역상/충돌을 깨야** 통과(불가능).

| 인덱스 | 가리키는 곳 | 안전 근거 | 의존 가정 | 안전? |
|---|---|---|---|:---:|
| `payload_ind/len` | preimage 내 payload 영역 | 간접 — vct/cnf/nonce가 `dec`에서 읽혀 강제 | vct 필수 검사 | ✅ |
| `exp_idx` | decoded payload | **리터럴** `"exp":` + 10자리 digit + 구분자 | 없음 | ✅ |
| `vct_idx` | decoded payload | **리터럴** 공개 패턴 `"vct":"…"` | 없음 | ✅ |
| `cnf_x_idx`·`cnf_y_idx` | decoded payload | **값** = MAC-linked `dpkx/dpky` 일치 | dpk 값 유일성 | ✅ |
| `nonce_idx`·`aud_idx` | KB payload | **리터럴** 공개 패턴 `"nonce":"…"`/`"aud":"…"` | 없음 | ✅ |
| `sd_idx` (슬롯별) | decoded payload(`_sd`) | **해시** base64decode(창)==`SHA(disclosure)` | SHA 역상/충돌 저항 | ✅ |
| `disc_shift` (슬롯별) | disclosure 평문 | 패턴 `","…",value]` (앞 `","`+뒤 `]`로 값 고정) | salt 랜덤성 | ✅ |
| `disc_in_pres` (슬롯별) | presented 묶음 | **값** = 멤버십 검증된 disclosure 바이트 일치 | 없음 | ✅ |
| `kb_pl_ind/len` | KB preimage | 간접 — nonce/aud/sd_hash가 `kbdec`에서 읽혀 강제 | nonce/aud 검사 | ✅ |
| `sd_hash_idx` | KB payload | **해시** 추출 32B == `SHA(presented)` | SHA 역상 저항 | ✅ |

**판정**: 모든 자유 인덱스가 안전하다. 다만 안전 근거는 두 부류다 — (a) 리터럴/값
앵커로 **자명하게** 고정되는 것, (b) `sd_idx`·`sd_hash_idx`처럼 **SHA 역상/충돌 저항에
의존**해 안전한 것(엉뚱한 위치를 가리키면 prover가 만족시킬 수 없게 됨), 그리고
`disc_shift`는 salt 랜덤성에 기댄다. 이들은 모두 표준적인 암호 가정이며 현재 구현에서
soundness를 깨지 않는다.

> ℹ️ 비교: 과거 `exp_idx`는 앵커도 자릿수 검증도 없이 사전식 비교만 해서, 엉뚱한 위치
> (letters > digits)를 가리키면 검사가 **쉬워져** 만료 우회가 가능했다(§7-#1). 위 `sd_idx`/
> `sd_hash_idx`는 정반대로 엉뚱하게 가리키면 **불가능**해지므로 안전하다 — "엉뚱한
> 인덱스가 검사를 쉽게 만드는가, 어렵게 만드는가"가 안전성의 갈림이다.

---

## 7. 보안 하드닝 이력

리뷰에서 발견·수정한 항목.

**#1 exp 유효기간 우회 (soundness 버그 → 수정)**
- 증상: `exp_idx`가 앵커 없는 witness이고 비교가 사전식(ASCII letters > digits)이라,
  악성 prover가 `exp_idx`를 letters 구간으로 가리키면 `now≤ed`가 항상 참 → **만료된
  토큰이 ACCEPT**. PoC로 실증(`EVIL_EXP=1`).
- 수정: `"exp":` 리터럴 앵커 + 10자리 digit + 구분자(`,`/`}`) 검증 후 `now≤exp`.
  세 회로 동일 적용, 회로 캐시 geo 태그 무효화. 적대적 회귀 테스트 고정
  (split 데모 `[3b]`, `EVIL_EXP` → REJECT).

**#2 KB freshness / audience (기능 미달 → 추가)**
- 증상: `e2`(KB 해시)만 토큰에서 재계산하고 nonce/aud를 검증자 챌린지와 대조하지
  않아 재생/audience 혼동을 막지 못함(mdoc은 디바이스 서명을 공개 transcript에 결속).
- 수정: nonce/aud를 공개입력으로 추가, KB payload에서 `"nonce":"`/`"aud":"` 리터럴
  앵커로 대조(vct와 동일). 세 회로 적용, 발급기 `KB_NONCE`/`KB_AUD` env 지원.
  split 데모 `[6]`: 신선 nonce ACCEPT / 재생 nonce REJECT 자동 검증. 이로써 sd_hash
  바인딩도 nonce와 함께 비로소 재생 방지 목적을 달성.

검증: 세 바이너리(hash/split/full) 모두 정상 ACCEPT, exp·nonce·aud 불일치 시 REJECT.
split/monolith 데모 전부 그린(valid / expired / adversarial-exp / tamper / big / freshness).

---

## 8. 위협모델 (현재 가정)

- **신뢰**: 발급자는 정직(올바른 disclosure에 서명). 검증자는 정직(코드대로 검증,
  공개입력을 올바로 선택). 공개키 pkX/pkY는 검증자가 사전에 신뢰.
- **적대자**: 증명자(홀더) — 거짓 명제를 정직한 검증자에게 통과시키려 시도. soundness는
  이 모델에서 성립해야 한다(§6, §7-#1이 바로 이 모델의 버그였음).
- **재생/중계자**: nonce/aud + KB 서명으로 방지. 검증자가 **세션마다 새 nonce**를 고른다는
  전제. nonce는 KB payload에 평문(숨길 필요 없는 값).
- **비추적성(unlinkability)**: 매 제시마다 새 proof. 단, 공개하는 속성 종류·개수(N)와
  공개 값 자체는 노출된다.

### 8.1 프라이버시 모델: 링크(linkability) 차단 vs 유추(inference)

이 ZKP가 겨냥하는 건 **unlinkability + 데이터 최소화**이지, 거친 속성의 **유추**를 막는 게 아니다.

- 진짜 링크 핸들은 **매번 똑같이 재등장하는 고유값** — 발급자 ECDSA 서명. ZK가 **이를 숨기고 매번 새 proof**를 만들어 제시들이 서로(또는 발급과) 엮이지 않게 한다.
- 반면 **이슈어 공개키(kid)는 여전히 공개입력으로 노출**된다. PID에선 이게 곧 **발급국 노출** — `age_over_18`만 증명하려는데 "이건 독일/그리스/… PID"가 새어나간다. 이는 **유추/disclosure** 문제로 링크 목표의 **스코프 밖**.
- 핵심: 이슈어 키 노출은 **그 키가 많은 사람이 공유하는 한** unlinkability를 깨지 않는다 — 국가 PID 키는 수백만 명이 공유하므로 *거친 그룹 속성*이지 개인별 상관자가 아니다. 이슈어-검증자 결탁도 어느 크레덴셜이 제시됐는지 못 집어낸다(서명이 숨겨져 있어).
- **단서 — 익명집합 크기**: 이는 이슈어 키 집합이 클 때만 성립. 키가 잘게 쪼개지면(지역·배치별, 혹은 로테이션이 잦아 `kid`가 "DE-2026-12주차" 수준) 이슈어 키가 **준식별자**로 변해 unlinkability가 깎인다. 즉 **키 로테이션 granularity가 곧 프라이버시 파라미터**(너무 자주 돌리면 익명집합 축소). 또 여러 거친 속성을 합치면 재식별될 수 있으나, 그건 유추 레이어이지 ZKP의 일이 아니다.

> 한 줄: 이 ZKP는 *"무엇을 보이나"*(최소화)와 *"제시들이 엮이나"*(unlinkability)를 푼다. *"누가 발급했나"*는 **안 가린다** — PID에선 그게 남는 국적 유추이고, **이슈어 키 익명집합이 큰 한** 링크 관점에선 허용된다.

### 8.2 멀티-이슈어 / 키 로테이션 (EUDI PID)

EUDI PID는 27개국+ 발급, 각국 다발급자 + 주기적 로테이션 → 시간에 따라 유효 이슈어 키가 수백 개. 실무 전략:

| 전략 | 27+ 키·로테이션 | 발급국 숨김 | 회로 비용 | 이 구현 |
|---|---|---|---|---|
| **A) Trusted List + 이슈어 공개** | 리스트로 흡수(키마다 유효기간) | ❌ 노출 | 낮음(서명 1) | ✅ |
| **B) 인증서 체인 → 루트** | **루트로 수렴(관리 최선)** | ❌ 노출 | 중(서명 2~3) | ❌ |
| **C) Trusted List 집합 멤버십 ZK** | 집합/루트 최신화 필요 | ✅ 숨김 | 높음(+Merkle) | ❌ |

- **A** 가 이 구현입니다: 검증자가 크레덴셜 `kid`/`x5c`로 EU **Trusted List**(LOTL, ETSI TS 119 612)에서 이슈어 키를 찾아 공개입력으로 제공. 로테이션은 "유효기간 붙은 키가 리스트에 늘어나는 것"일 뿐. **발급국이 노출**됨.
- **B** 는 인증서 체인(크레덴셜→이슈어 인증서→루트)을 **회로 안에서** 검증 → 검증자는 루트 몇 개만 신뢰, 로테이션은 "같은 루트 밑 새 인증서". 단 EUDI 신뢰는 **연합형**(27개 국가 trust anchor, 단일 EU 슈퍼루트 없음)이라 단일 루트가 보통 없음.
- **C** 는 "신뢰 앵커 *중 하나*가 서명"을 **어느 것인지 숨기고** 증명(Merkle/accumulator 멤버십, 루트가 공개입력). 프라이버시 방향이지만 신규 회로 + 트러스트리스트 루트의 **신선도** 필요. 연합형이라 국가 은닉은 ~27개 앵커 집합 멤버십이 필요(숨을 단일 루트가 없음).

근시일엔 **A + Trusted List**(로테이션=유효기간 처리)가 현실적이고 이 구현이 거기 해당. **C** 가 국가 은닉을 위한 미래 과제.

---

## 9. 남은 항목 / 한계

- **#3(본 문서)**: free-index 안전성 표 — 완료(§6). 모든 인덱스 ✅, 근거 명시.
- alg 고정(ES256/P-256/SHA-256), nbf 미검사, exp 10자리 가정.
- 호스트 파싱이 canonical JSON(공백 없음·특정 키, 첫 매칭)을 가정 — 실서비스 토큰
  포맷 변형 견고성은 별도 과제.
- revocation/status, W3C VC, 공개 API/Node 바인딩, 단일 번들 직렬화 정리는 미구현.
- 데모 nonce는 "검증자가 골라 발급기에 전달" 형태(실제론 verifier→holder 챌린지 왕복).

---

## 10. 파일 맵 (`playground/`)

| 파일 | 역할 |
|---|---|
| `native/sdjwt_split.cc` | ⭐ **flagship** — 2회로(Fp256 sig + GF2¹²⁸ hash) + MAC, present+verify |
| `native/sdjwt_full.cc` | monolithic 단일 Fp256 회로(동일 명제, 느리지만 단순) |
| `native/sdjwt_hash.cc` | 해시 회로 단독 테스트 바이너리(split과 회로·캐시 공유) |
| `native/sdjwt_sig.cc` | 서명 회로 단독 |
| `native/sdjwt_zk.cc` | M3 프로토타입(exp+멤버십+구조, 컴파일러 백엔드) |
| `native/sdjwt_eval.cc` | M2/M4 평문 eval 하니스(ZK 전 로직 검증) |
| `native/jwt_cli.cc` | longfellow 실험용 JWT substring 회로 구동(문자열 속성만) |
| `tools/gen-sdjwt.mjs` | 실제 ES256 SD-JWT-VC 발급기(`KB_NONCE`/`KB_AUD`/`BIG` env) |
| `src/decode-sdjwt.js` | 의존성 없는 평문 레퍼런스 검증기(회로가 할 일의 명세) |
| `src/demo-sdjwt-split.js` | split 데모(valid/expired/adversarial/tamper/big/freshness) |
| `src/demo-sdjwt-zk.js` | monolith 데모 |
| `SDJWT_PLAN.md` | 설계 문서(Approach C, 마일스톤 M1~M9) |

회로 용량(고정, 초과 시 명확한 에러): `kMaxSHA=32`(payload 2KB), `KBB=6`, `PB=40`(presented
2.5KB), `MAXB=4`(disclosure 256B), `MAXPAT=160`, `MAXVCT=128`, `MAXNONCE=64`, `MAXAUD=128`,
`LOGM=12`. 컴파일된 회로는 geometry 태그로 zstd 캐시(`circuits-cache/`).

---

## 11. 빌드 · 실행

```bash
cd playground
pnpm run build:native        # C++ 라이브러리 + 바이너리 빌드(최초 1회)
pnpm run demo:sdjwt-split    # ⭐ 2회로 데모: issue→present→verify + 음성 테스트들
pnpm run demo:sdjwt-zk       # monolith 데모

# 직접 호출: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud>
native/sdjwt_split fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "given_name,age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example
```

---

## 12. 결론

이 프로젝트는 Longfellow-ZK의 **mdoc 선택공개 ZK 철학(멤버십 환원)과 2회로+MAC
아키텍처**를 **표준 SD-JWT-VC**로 충실히 이식했다. 모든 값 타입 + 유효기간 + Key
Binding + sd_hash + **nonce/aud freshness** + 다속성을 파싱 없이 처리하며, mdoc과 동일한
분리 아키텍처로 prove를 ~8배 단축한다.

리뷰 결과 발견된 exp soundness 버그와 KB freshness 미달을 수정했고(§7), 모든 자유
인덱스의 안전 근거를 명시했다(§6). 암호 코어(멤버십·MAC 분리)는 longfellow에서
차용한 것이고, 본 작업의 신규성은 **`_sd` 구조로의 건전한 적응 + 구조적 disclosure
동등 + exp/vct/nonce/aud 앵커 검사**다. 현재는 mdoc 패리티에 근접하나, alg 민첩성·
nbf·revocation·공개 API는 미구현으로 남아 있다.
