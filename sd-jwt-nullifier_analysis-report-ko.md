# SD-JWT-VC 가명 Nullifier (CI/DI) 분석 보고서

> 대상: `playground/` — SD-JWT-VC 선택공개 ZK를 **가명 크리덴셜**로 만드는 연구 확장. **nullifier**(한국 CI/DI의 ZK 대응물).
> 위치: `/home/unknown/longfellow/playground`
> 작성일: 2026-05-24 · 상태: 프로토타입, soundness 감사 완료
> 기반: 이 문서는 크레덴셜 증명의 **확장**입니다 — 공유 기반(`_sd` 멤버십, 전체 SD-JWT-VC 증명, 2회로 split, §6 free-index 감사)은 [`sd-jwt-longfellow-zk_analysis-report-ko.md`](sd-jwt-longfellow-zk_analysis-report-ko.md) 참조.

---

## 1. 개요

**nullifier**는 1인당 secret(+scope)에서 유도되는 결정적 값으로, **신원과 연결 불가**하면서 **(secret, scope)당 유일**합니다 — 검증자는 "scope 내 1인 1개"를 탐지하되 그가 누구인지는 모름. 이는 한국 **CI/DI**의 역할 그 자체인데, 중앙 본인확인기관이 발급해 주는 대신 **홀더가 직접 계산하고 영지식으로 증명**합니다.

프로토타입: `native/sdjwt_nullifier.cc`(monolith), `native/sdjwt_null_split.cc`(2회로 split); 데모 `pnpm run demo:nullifier`; 발급기 `tools/gen-sdjwt.mjs`가 `pseudonym_secret` 추가.

## 2. CI/DI 대응

| 한국 본인확인 | nullifier 형태 | 성질 |
|---|---|---|
| **CI**(연계정보) | **global** `PRF(secret)` | 모든 서비스 같은 값 → 서비스 간 연결(의도) |
| **DI**(중복확인정보) | **scoped** `PRF(secret, scope)` | 서비스별 값 → 서비스 간 비연결, 같은 서비스 내 중복탐지 |

scope = 도메인 분리자(서비스/검증자 id, 선거 id, 에폭): 넣으면 DI, 빼면 CI.

**CI/DI 대비 개선.** CI/DI는 본인확인기관이 계산하고 **매핑을 보유**합니다. 여기선 홀더가 자기 secret으로 nullifier를 계산하고 *"이 nullifier가 발급자가 커밋한 secret에서 올바로 유도됐다"* 를 ZK로 증명 → 중앙이 신원↔가명 매핑을 안 들어도 되고, (scoped의 경우) 서비스 간 비연결이 **정책이 아니라 암호학적으로** 강제됩니다.

> scope 주의: 이 작업이 푸는 건 **링크 차단(unlinkability)** (정적 핸들인 발급자 서명을 숨기고 매번 새 proof)이지 **유추(inference)** 가 아닙니다. 발급자 공개키는 크레덴셜 증명에서 여전히 노출 — 기반 보고서 §8.1 참조.

## 3. 구성

발급자가 1인당 `pseudonym_secret`을 `_sd` claim으로 박음 → **발급자 커밋**(홀더가 못 고름). 검증자가 정한 `context`에 대해 회로가 ZK로 증명:

```
nullifier == SHA256( secret ‖ SHA256(context) )
```

- **공개**: `nullifier`, `context_hash = SHA256(context)` (검증자가 합의된 scope 문자열에서 계산, 공개 검증 가능).
- **숨김(witness)**: `secret` — `_sd` 멤버십으로 발급자 서명집합에 속함을 증명한 뒤 그 값을 nullifier 해시에 투입.

발급자 커밋 체인(Sybil 저항의 근거, §6-S2): `SHA(secret_disclosure) ∈ _sd` ⊂ 서명 payload, `SHA(payload)=e`, `e`는 발급자 ECDSA로 검증(split에선 서명회로에 MAC 결속). → secret은 발급자가 실제 서명한 크레덴셜에 묶임.

## 4. 속성 (`demo:nullifier`로 검증)

- 같은 `(secret, context)` → **같은** nullifier — 중복/Sybil 탐지(= scope 내 DI).
- 다른 `context` → **다른** nullifier — scope 간 비연결.
- 빈 `context` → 전역 단일 값(= CI).
- **위조** nullifier(결정값 외 임의값) → **REJECT** — scope당 하나.

## 5. 아키텍처 & 성능

nullifier SHA를 split의 **GF(2¹²⁸) 해시 회로**에 둠(이진체 SHA가 저렴), 서명 회로 불변.

| | monolith (`sdjwt_nullifier`) | split (`sdjwt_null_split`) |
|---|---|---|
| prove | ~13초 (end-to-end) | **~1.6초** + verify ~0.7초 |
| proof / 번들 | ~816KB | **~387KB** |

같은 `(secret, context)`에 양쪽 **동일** nullifier. S3 수정 후 메시지 96B → `NULLB=2` 블록.

## 6. Soundness 감사

위협모델: 악성 증명자가 (S1) scope당 2개 이상 생성, (S2) 미커밋 secret 사용, (S3) 다른 scope 충돌을 못 하게 + (P) 프라이버시.

| # | 속성 | 판정 |
|---|---|---|
| S1 | 결정성(scope당 nullifier 하나) | ✅ **보장** — SHA preimage 전체 바인딩(secret+context_hash+표준패딩) + `null_nb` 고정; secret 추출 위치가 base64url/hex가 앵커문자 `"`/`,`를 배제해 **유일 강제**(확률 아님) |
| S2 | secret 발급자 커밋 | ✅ `_sd` 멤버십 → 서명 payload → ECDSA 체인(§3) |
| S3 | scope 분리 | ✅ 수정 후(아래) |
| P | 발급자 비추적 | ⚠️ 한계(§7) |

**[S3] 발견·수정.** 초기엔 `context`를 고정 64B로 잘라/패딩 → 앞 64B 공유 scope가 **충돌**(실측: `A×64` 와 `A×64+X` 가 같은 nullifier `bb3169d7…`). **수정:** raw context 대신 `SHA256(context)`를 바인딩(길이 무관), `CTXLEN 64→32`, `NULLB 3→2`. 재측정: `878af16f…` vs `4accdf0c…` — 서로 다름.

### 6.1 Free-index 감사 (nullifier 전용)

nullifier 회로는 크레덴셜 인덱스(기반 보고서 §6)를 재사용하고 아래를 추가 — 별개 회로라 여기서 감사:

| 인덱스 | 가리키는 곳 | 안전 근거 | 판정 |
|---|---|---|---|
| `sec_sd_idx` | secret의 `_sd` 항목 | `base64decode(창) == SHA(secret_disclosure)` → SHA 역상/충돌 (`sd_idx`와 동일) | ✅ (해시) |
| `sec_shift` | 디스클로저 내 secret 값 오프셋 | `","pseudonym_secret","` 리터럴 앵커; base64url/hex가 `"`·`,` 배제해 **유일 강제** | ✅ 보장 |
| `sec_len` | 디코드된 디스클로저 길이 | 틀리면 앵커/멤버십 실패 | ✅ |

> `null_nb`는 `== NULLB`로 강제, `null_pre`는 `secret ‖ context_hash ‖ 표준패딩`에 전부 바인딩 → nullifier SHA 입력이 상수(자유 witness 없음). `context_hash`는 witness가 아닌 공개입력.

## 7. 한계 / 신뢰가정 (회로로 못 막음)

- **발급자가 역추적/연결 가능 (P).** 발급자가 `secret`을 알아 임의 scope nullifier 계산 → 사용자를 scope 간·신원과 연결 가능. CI/DI와 동일 신뢰모델(기관이 앎). **블라인드 발급**(발급자가 모른 채 commitment 서명)이 이를 제거 — **구현 완료, §10 참조**.
- **Sybil = 1인 1 secret.** Sybil 저항은 발급자가 **1인당 `pseudonym_secret` 하나**(재발급 포함)를 발급한다는 불변식만큼만 강함. 회로가 강제 못 함 — 발급자 정책(CI/DI와 동일).
- **고정 길이 secret.** `pseudonym_secret`은 고정 64-hex; 발급자가 준수해야 함.
- **mdoc — 구현 완료.** longfellow 공개 mdoc API로는 숨긴-secret nullifier 불가(속성 공개=값 노출)라 커스텀 회로가 필요했고, 이제 그 회로가 존재 — [`mdoc-nullifier_analysis-report-ko.md`](mdoc-nullifier_analysis-report-ko.md) 참조.

## 8. 파일 / 실행

| 파일 | 역할 |
|---|---|
| `native/sdjwt_nullifier.cc` | monolith(단일 Fp256) — 전체 SD-JWT-VC 증명 + nullifier |
| `native/sdjwt_null_split.cc` | 2회로 split — nullifier SHA를 GF(2¹²⁸) 해시 회로에(빠름) |
| `tools/gen-sdjwt.mjs` | `pseudonym_secret`(64-hex)를 `_sd` claim으로 발급 |
| `src/demo-nullifier.js` | `pnpm run demo:nullifier` (기본 split; `MONO=1`은 monolith) |

```bash
# 직접 호출: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud> <context>
native/sdjwt_null_split fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example "shop-A"
```

## 9. 미래 과제

- **블라인드 발급** → 발급자 비추적 갭(P) 닫기 — ✅ **완료, §10 참조**.
- **mdoc nullifier**(커스텀 CBOR 회로) — ✅ 완료, [`mdoc-nullifier_analysis-report-ko.md`](mdoc-nullifier_analysis-report-ko.md) 참조.
- 검증자측 **context 바인딩**: 월렛이 trust-anchor 서명 JWT의 `context`를 검증(데모는 string으로 전달).
- 블라인드 발급의 **발급-시점 well-formedness 증명**(발급자가 단일·올바른 형태의 커밋먼트만 서명하도록) — §10.6 참조.
- rate-limiting / 일회용 변형(cf. Semaphore, RLN, Worldcoin).

---

## 10. 발전 — 블라인드 발급 (발급자 역추적 제거)

위 섹션들은 secret 자체(`pseudonym_secret`)를 크레덴셜에 박으므로 **발급자가 secret을 알고** 임의 scope의 nullifier를 계산할 수 있습니다(한계 **P**, §7). 이 섹션은 **발급자가 secret을 절대 모르도록** 구성을 발전시켜 P를 닫습니다 — §4의 모든 속성과 §6의 Sybil 결속은 그대로 유지하면서.

프로토타입: `native/sdjwt_null_blind.cc`; 데모 `pnpm run demo:nullifier-blind`; 발급기 `tools/gen-sdjwt-blind.mjs`. 기존 파일은 무수정.

### 10.1 아이디어: 공개 말고 커밋

발급자가 secret을 고르는 대신, **홀더**가 `secret`(32B)과 블라인딩 `blind`(32B)를 생성해 커밋:

```
C = SHA256( secret ‖ blind )        // 숨김(hiding) + 결속(binding) 커밋먼트
```

발급자는 `pseudonym_commitment = base64url(C)`를 `_sd` claim으로 **C만** 서명. `secret`/`blind`는 본 적 없으므로 어떤 scope에 대해서도 `SHA256(secret ‖ SHA256(context))`를 계산할 수 없습니다. (`blind`가 secret 엔트로피와 무관하게 hiding을 보장; binding은 SHA 충돌저항.) 홀더 전용 비밀(`secret ‖ blind`)은 홀더 측(`fixtures/holder-secret.txt`)에만 두고, 증명자는 `HOLDER_SECRET`로 읽음.

### 10.2 회로가 증명하는 것 (GF(2¹²⁸) 해시 회로에 추가)

검증자가 정한 `context`에 대해, **`secret`/`blind`를 숨긴 채** 단일 ZK 증명으로:

1. **멤버십** — `SHA(commitment_disclosure) ∈ payload._sd` (C는 발급자 커밋). *§3 재사용.*
2. **디코드** — 리터럴 앵커 `","pseudonym_commitment","` 뒤 43자 base64url 값을 추출·디코드 → `Cbytes`(32B). *기존 디코더 재사용.*
3. **오프닝(신규)** — `open_digest = SHA256(secret ‖ blind)` **그리고** `open_digest == Cbytes`. 증명자가 발급자-커밋 `C`를 여는 `(secret, blind)`를 보유함을 증명.
4. **nullifier** — `nullifier = SHA256(secret ‖ context_hash)`, 전체 바인딩(표준 패딩, `null_nb` 고정). *§3 재사용.*

**같은 `secret` wire**가 (3)과 (4)에 모두 투입 → 발급자 커밋먼트에 묶인 값이 곧 가명에 쓰인 값. 순수 신규 회로 = **SHA 1블록(오프닝) + base64url 디코드 + 동등성 assert**; 나머지(멤버십·구조·서명·MAC 결속)는 §3/split 그대로.

### 10.3 속성 (`demo:nullifier-blind`로 검증)

§4 전부 + 결정적인 blind 속성:

| 단계 | 검사 | 결과 |
|---|---|---|
| 같은 `(secret, context)` | 동일 nullifier | ✅ DI 중복탐지 |
| 다른 `context` | 다른 nullifier | ✅ 비연결 |
| 빈 `context` | 전역 단일 값 | ✅ CI |
| `EVIL_NULL`(위조 nullifier) | 증명 불가 | ✅ REJECT |
| **`EVIL_SECRET`**(C를 못 여는 secret) | **`eval_circuit failed`** | ✅ **REJECT** |
| `TAMPER`(MAC 1비트) | 양쪽 회로 거부 | ✅ REJECT |

`EVIL_SECRET`가 신규: 공개 커밋먼트 `C`는 알지만 secret을 모르는 자는 증명 불가 — (3)의 **오프닝**이 secret을 강제. 즉 정당한 홀더만 증명하는데, **발급자는 secret을 끝내 모름**.

### 10.4 성능 (실측, 속성 1개 + nullifier)

| | sig (Fp256) | hash (GF(2¹²⁸)) |
|---|---|---|
| ninputs | ~3.7k | ~185.8k |
| proof | ~194KB | ~194KB |

end-to-end: **prove ≈ 1.8초, verify ≈ 0.77초, 번들 ≈ 389KB**. 비-blind split(§5) 대비 오프닝이 싼 이진체에 SHA 1블록만 더해 비용은 사실상 동일. 캐시 `circuits-cache/sdjwt-nullblind-hash-<geo>.bin`, transcript 라벨 `"sdjwt-blind"`.

### 10.5 Soundness

§6과 동일 위협모델. 블라인딩 후 각 속성이 유지되는 방식:

| # | 속성 | 판정(blind) |
|---|---|---|
| S1 | 결정성(scope당 nullifier 하나) | ✅ 불변 — `null_pre` 전체 바인딩, `null_nb` 고정(§6) |
| S2 | secret이 발급자에 고정됨 | ✅ 이제 **커밋먼트** 경유: `SHA(commitment_disclosure) ∈ _sd` → 서명 payload → ECDSA, **추가로** 오프닝 `C == SHA(secret‖blind)`가 숨긴 secret을 그 서명된 `C`에 결속(다른 secret이면 `C`와 SHA 충돌 필요) |
| S3 | scope 분리 | ✅ 불변 — `SHA256(context)` 바인딩 |
| **P** | **발급자 비추적** | ✅ **이제 달성** — 발급자는 `C`(hiding)만 봤으므로 어떤 scope nullifier도 계산 불가 |

> **Sybil은 여전히 발급자 정책 필요.** secret을 숨긴다고 "1인 1개"가 약해지지 **않습니다**: 그 불변식은 발급 게이트(KYC + 실신원당 크레덴셜 1개)에서 오고, 발급자가 secret을 보는지와 무관. 홀더가 자기 secret을 고르는 건 비밀번호를 스스로 정하는 것과 같아 새 신원을 주지 않음 — 크레덴셜은 인증된 그 사람에게 여전히 한 번만 발급됨.

Free-index 감사(신규/변경 인덱스; `secret`/`blind`는 free index가 아닌 직접 witness):

| 인덱스 | 가리키는 곳 | 안전 근거 | 판정 |
|---|---|---|---|
| `com_sd_idx` | 커밋먼트의 `_sd` 항목 | `base64decode(창) == SHA(commitment_disclosure)` → SHA 역상/충돌 | ✅ (해시) |
| `com_shift` | 커밋먼트 값 오프셋 | `","pseudonym_commitment","` 리터럴 앵커; base64url이 `"`/`,` 배제 → 유일 강제 | ✅ 보장 |
| `com_len` | 디코드된 디스클로저 길이 | 틀리면 앵커/멤버십 실패 | ✅ |

> `secret`/`blind`는 오프닝(`SHA(secret‖blind)==C`)과 nullifier(`SHA(secret‖ctx_hash)==nullifier`)로 고정된 private 입력 wire; 잘못 가리킬 인덱스가 없고, 같은 `secret` wire가 양쪽에 투입됨.

### 10.6 블라인드 발급이 못 푸는 것

- **발급-시점 well-formedness (데모 단순화).** 실제 발급자는 발급 시 홀더가 `C`가 *단일 secret에 대한 올바른 형태의 커밋먼트*임을 증명하도록 요구해야 함 — 안 그러면 홀더가 쓰레기/여러 secret을 커밋할 수 있음. 데모 발급자는 홀더의 `C`를 신뢰; 이 발급-시점 증명은 별도 프로토콜 단계(제출 회로 아님). 위 제출 ZK는 완전 구현.
- **자격증명 공유.** 홀더가 `(크레덴셜, secret, blind)`를 자발적으로 넘기는 건 범위 밖(device binding/KB로 완화; 모든 크레덴셜 시스템·CI/DI 공통).
- **발급자 1인 1개 정책.** §7처럼 Sybil 저항은 발급자가 실신원당 크레덴셜 하나를 발급하는 데 여전히 의존.
- **유추(inference).** 발급자 공개키(PID면 발급국)는 크레덴셜 증명에서 여전히 노출(기반 보고서 §8.1).

### 10.7 파일 / 실행

| 파일 | 역할 |
|---|---|
| `native/sdjwt_null_blind.cc` | blind 변형 — 커밋먼트 멤버십 + 오프닝 + nullifier (GF(2¹²⁸) 해시 회로) |
| `tools/gen-sdjwt-blind.mjs` | 홀더가 `C=SHA(secret‖blind)` 커밋; 발급자는 `pseudonym_commitment`만 서명 |
| `src/demo-nullifier-blind.js` | `pnpm run demo:nullifier-blind` (발급 → DI → scoping → CI → 위조/오secret/tamper 거부) |
| `fixtures/holder-secret.txt` | 홀더 전용 `secret_hex ‖ blind_hex` (발급자에 전송 안 됨) |

```bash
# 직접 호출: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud> <context>
#   홀더 secret은 HOLDER_SECRET(= secret_hex ‖ blind_hex)로 읽음
HOLDER_SECRET=fixtures/holder-secret.txt \
native/sdjwt_null_blind fixtures/sdjwt-blind.txt fixtures/issuer-jwk-blind.json 1700000000 \
  "age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example "shop-A"
# env: EVIL_NULL=1 (위조 nullifier), EVIL_SECRET=1 (secret이 C를 못 엶), TAMPER=1 (MAC 깨기)
```
