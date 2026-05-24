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

- **발급자가 역추적/연결 가능 (P).** 발급자가 `secret`을 알아 임의 scope nullifier 계산 → 사용자를 scope 간·신원과 연결 가능. CI/DI와 동일 신뢰모델(기관이 앎). **블라인드 발급**(발급자가 모른 채 commitment 서명)이 이를 제거 — 최대 미래 과제.
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

- **블라인드 발급** → 발급자 비추적 갭(P) 닫기.
- **mdoc nullifier**(커스텀 CBOR 회로) — ✅ 완료, [`mdoc-nullifier_analysis-report-ko.md`](mdoc-nullifier_analysis-report-ko.md) 참조.
- 검증자측 **context 바인딩**: 월렛이 trust-anchor 서명 JWT의 `context`를 검증(데모는 string으로 전달).
- rate-limiting / 일회용 변형(cf. Semaphore, RLN, Worldcoin).
