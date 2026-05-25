# mdoc (ISO 18013-5) 가명 Nullifier — 분석 보고서

> 대상: `playground/` — **실제 mdoc** ZK 제시(longfellow 2회로 prover) 위에 **가명 nullifier**(한국 CI/DI의 ZK 대응물)를 추가한 연구 확장.
> 위치: `/home/unknown/longfellow/playground`
> 날짜: 2026-05-24 · 상태: 프로토타입, 동작 + soundness 감사 완료
> 기반: 본 문서는 mdoc 자격증명 증명의 **확장**입니다. CI/DI 의미, nullifier 구성 철학, soundness 위협모델은 SD-JWT 판인 [`sd-jwt-nullifier_analysis-report-ko.md`](sd-jwt-nullifier_analysis-report-ko.md)에 한 번만 정리돼 있고, 바탕 longfellow mdoc 회로는 [`longfellow-zk_analysis-report-ko.md`](longfellow-zk_analysis-report-ko.md)에 있습니다. 여기서는 **mdoc 고유**의 내용만 다룹니다.

---

## 1. 개요

**nullifier**는 1인당 비밀(secret)과 scope에서 결정적으로 도출되는 값으로, **신원과 연결 불가**이면서 **(secret, scope)마다 유일**합니다. 검증자는 누구인지는 전혀 모른 채 "scope 안에서 1인 1회"를 강제할 수 있습니다 — 한국의 **CI/DI** 그 자체지만, 발급기관이 주는 대신 **보유자가 계산하고 영지식으로 증명**합니다 (CI/DI 매핑 전체는 [`sd-jwt-nullifier_analysis-report-ko.md`](sd-jwt-nullifier_analysis-report-ko.md) §1–2 그대로 적용).

SD-JWT nullifier 보고서는 **"mdoc 미구현"**을 한계이자 향후 과제로 남겼습니다. longfellow의 공개 mdoc API는 속성 *공개(disclosure)*만 지원해(값이 드러남) hidden-secret nullifier에는 커스텀 회로가 필요하기 때문입니다. **본 보고서가 그 회로입니다.**

프로토타입: `native/mdoc_null_split.cc`; 데모 `pnpm run demo:mdoc-nullifier`; 발급기는 `tools/gen-mdoc.mjs`(`@lukas.j.han/mdoc` 사용)로 `pseudonym_secret`을 일반 mdoc 속성으로 삽입.

## 2. 구성

MAC로 결속된 2회로 — 표준 longfellow mdoc split을 **그대로 재사용**하고 블록 하나만 추가:

| 회로 | 필드 | 내용 |
|---|---|---|
| **sig** | Fp256 | `MdocSignature::assert_signatures` — MSO 해시 `e`에 대한 발급자 ECDSA, 세션 transcript 해시에 대한 디바이스 ECDSA. *불변.* |
| **hash** | GF(2¹²⁸) | `MdocHash::assert_valid_hash_mdoc` — SHA(MSO), validFrom/Until, deviceKey, valueDigests 멤버십, 공개 속성. *불변.* **+ 전용 nullifier 블록(본 작업).** |

두 회로는 공통값 `(e, dpkx, dpky)`에 대한 MAC로 결속됩니다: 공유 커밋 키 절반 `a_p`, 커밋 후 transcript에서 뽑는 `a_v`, macs는 양쪽에서 공개. 번들 = `[6 macs][hash proof][sig proof]`. Fiat–Shamir transcript는 세션 transcript로 시드. (`mdoc_zk.cc` / `sdjwt_null_split.cc`와 동일.)

검증자가 고른 `context`에 대해 hash 회로가 추가로 영지식 증명:

```
nullifier == SHA256( secret(64 B) ‖ SHA256(context) )
```

- **공개**: `nullifier`, `context_hash = SHA256(context)`.
- **비공개(witness)**: `secret` — 64바이트 `pseudonym_secret` 값, 회로 안에서만 추출되고 절대 공개 안 됨.

### 2.1 왜 *전용 블록*인가 (속성 경로가 아니라)

자연스러운 발상 — `pseudonym_secret`을 `MdocHash`의 속성 하나로 넣되 값만 비공개로 두고 nullifier에 먹이기 — 는 **들어가지 않습니다**. 그 이유가 핵심 mdoc 고유 발견입니다:

`@lukas.j.han/mdoc`는 `pseudonym_secret`을 64-hex 문자 값으로 발급하므로 그 `IssuerSignedItem`이 **~174 B**:

```
D8 18 58 AA  A4                              ; tag24, bstr(170), map(4)
  68 "digestID" 1A xxxxxxxx                  ; digestID
  66 "random"  58 20 <32 bytes>             ; 32바이트 random
  71 "elementIdentifier" 70 "pseudonym_secret"
  6C "elementValue"      78 40 <64 hex>      ; 비밀값
```

`MdocHash`의 속성 경로는 **2 SHA블록** item 버퍼(`attrb_[128]`, `attr_sha_[2]`), `OpenedAttribute.v1[64]` 값 필드, 그리고 *elementIdentifier + elementValue ≤ 56 B* 라는 문서화된 제약을 하드코딩합니다. 174바이트 item(3 SHA블록) + 66바이트 값 필드는 **셋 다 초과**합니다. 그래서 secret은 공개-속성 기계에 태울 수 없습니다.

대신 nullifier는 **자체 3블록 item 버퍼**(`SECB = 3`, 192 B)를 씁니다 — 검증된 SD-JWT split nullifier 설계를 그대로. 이 방식은 **longfellow submodule 무수정, 발급기 무수정**이며 256-bit secret을 유지합니다.

### 2.2 nullifier 블록 (`assert_nullifier`)

1. **멤버십.** `SHA(sec_item) = mm`. `mm`이 **서명된 MSO** valueDigests 안에 32바이트 CBOR 바이트열(`58 20 …`)로 존재함을 증명: `assert_valid_hash_mdoc`가 이미 `e`에 SHA-결속한 MSO 버퍼 `w.in_ + 5 + 2`를 `sec_mso`만큼 시프트, `58 20` 태그 확인, 32바이트를 `mm`과 비교. (`MdocHash`의 속성 MSO-멤버십을 3블록 item용으로 복제; MSO 길이/`check_index`는 재구성하고 컴파일러가 dedup.)
2. **추출.** `sec_item`을 `sec_anchor`만큼 시프트해 50바이트 리터럴 CBOR 앵커

   ```
   71 "elementIdentifier" 70 "pseudonym_secret" 6C "elementValue" 78 40
   ```

   를 확인한 뒤 다음 **64바이트**를 비밀값으로 읽음 — **회로 안에서만, 절대 미공개**. 앵커가 속성 정체(`pseudonym_secret`)와 값 길이(`78 40` = text(64))를 동시에 고정.
3. **Nullifier.** `nullifier = SHA( secret(64) ‖ SHA(context)(32) )`. 96바이트 preimage 전체(값, context 해시, `0x80` 패딩, 0 채움, 길이)와 `null_nb`를 고정 → `(secret, context)`마다 결정적.

발급자-커밋 체인(Sybil 저항): `SHA(sec_item) ∈ valueDigests` ⊂ MSO, `SHA(MSO) = e`, `e`는 sig 회로에서 발급자 ECDSA로 검증(MAC 결속). 따라서 secret은 발급자가 실제 서명한 자격증명에 결속됩니다.

## 3. 성질 (`demo:mdoc-nullifier`로 검증)

- 같은 `(secret, context)` → **같은** nullifier — 중복/Sybil 탐지(= scope 내 DI).
- 다른 `context` → **다른** nullifier — scope 간 비연결.
- 위조 nullifier(`EVIL_NULL`) → **증명 불가**(witness가 `nullifier == SHA(secret ‖ SHA(context))`를 만족 못 함) — scope당 nullifier 하나.
- mac 변조(`TAMPER`) → **양쪽 회로 거부** — 두 회로에 걸친 `e/dpkx/dpky` MAC 결속이 실제로 작동.

## 4. 아키텍처 & 성능

`fixtures/mdoc.bin`(공개 속성 1개 `age_over_18`) 실측:

| | sig (Fp256) | hash (GF(2¹²⁸)) |
|---|---|---|
| ninputs | ~3.7 k | ~95.6 k |
| proof | ~195 KB | ~151 KB |

전체: **prove ≈ 0.95 s, verify ≈ 0.43 s, bundle ≈ 345 KB**. nullifier SHA는 이진체 hash 회로에 둠(거기서 SHA가 저렴); 서명 회로는 무수정. secret item은 `SECB = 3` 블록, nullifier 메시지는 96 B → `NULLB = 2` 블록.

## 5. Soundness 감사

위협모델(SD-JWT판 §6과 동일): 악의적 prover가 (S1) scope당 nullifier 2개 이상 생성, (S2) 비커밋 secret 사용, (S3) 다른 scope 충돌을 못 하게 하고, (P) 프라이버시.

| # | 성질 | 판정 |
|---|---|---|
| S1 | 결정성(scope당 nullifier 하나) | ✅ **보장** — 96바이트 SHA preimage 전체 바인딩 + `null_nb` 고정; 추출 offset `sec_anchor`는 **유일하게 강제**(`"pseudonym_secret"`·`"elementValue"`·`78 40`을 담은 50바이트 앵커는 hex 값 안에 나타날 수 없고 한 item에서 두 번 매칭 불가) |
| S2 | secret이 발급자-커밋 | ✅ `SHA(sec_item) ∈ valueDigests` → `SHA(MSO)=e` → 발급자 ECDSA (§2.2); 다른 `sec_item`은 서명된 digest와 SHA 충돌이 필요 |
| S3 | scope 분리 | ✅ `SHA256(context)`를 바인딩(길이무관), SD-JWT의 S3 수정 계승; `CTXLEN = 32` |
| P | 발급자 비추적성 | ⚠️ 제한적 (§6) |

### 5.1 free-index 감사 (mdoc nullifier 고유)

본 블록은 호스트 제공 인덱스 2개를 추가하며, 둘 다 틀린 값이면 실패하도록 제약됩니다:

| 인덱스 | 가리키는 곳 | 안전 근거 | 판정 |
|---|---|---|---|
| `sec_mso` | MSO 내 item의 32바이트 digest | `< len(MSO)` 범위검사; 창이 `58 20`으로 시작하고 이어지는 32바이트가 `SHA(sec_item)`과 같아야 함 — 즉 실제 서명된 digest | ✅ (서명 + 해시) |
| `sec_anchor` | `sec_item` 내 앵커 offset | 50바이트 리터럴 `71 elementIdentifier 70 pseudonym_secret 6C elementValue 78 40`이 매칭돼야 함; **유일하게 강제**(item당 해당 필드 하나, hex 값 바이트가 앵커 재현 불가) | ✅ 보장 |

> `null_nb`는 `== NULLB`로 단언되고 `null_pre`는 `secret ‖ SHA(context) ‖ 정규 패딩`에 완전히 바인딩되므로 nullifier SHA 입력은 상수(자유 witness 없음). `context_hash`는 공개입력. `sec_nb`는 `== SECB`로 고정.

## 6. 한계 / 신뢰 가정 (회로로 해결 불가)

SD-JWT nullifier와 동일 모델(해당 보고서 §7 참조):

- **발급자가 비익명화/연결 가능 (P).** 발급자는 `secret`을 알아 임의 scope의 nullifier를 계산할 수 있음. CI/DI와 같은 신뢰모델. **블라인드 발급**(발급자가 학습하지 않는 secret의 커밋에 서명)이 이를 제거 — **구현 완료, §9 참조**.
- **Sybil = 1인 1 secret.** 발급자가 "재발급 포함 1인당 `pseudonym_secret` 하나" 정책을 지키는 만큼만 강함. 회로로 강제 불가(CI/DI와 동일).
- **고정 포맷.** `pseudonym_secret`은 고정 64-hex 값이고 그 `IssuerSignedItem`은 `SECB = 3` SHA블록에 맞아야 하며 `elementIdentifier`가 `elementValue` 바로 앞이어야 함(연속-앵커 가정). `@lukas.j.han/mdoc`는 모두 충족; 순서/패딩이 다른 발급기는 앵커/`SECB` 조정 필요.
- **디바이스 결속.** 본 증명은 충실한 mdoc 제시(세션 transcript에 대한 디바이스 서명 검증)라 transcript 간 재생 불가; 다만 비연결성은 여전히 발급자 공개키를 드러냄(기반 보고서 참조).

## 7. 파일 / 실행

| 파일 | 역할 |
|---|---|
| `native/mdoc_null_split.cc` | 2회로 mdoc present/verify(`MdocSignature` + `MdocHash`) + nullifier 블록 |
| `tools/gen-mdoc.mjs` | `@lukas.j.han/mdoc`로 `pseudonym_secret`(64-hex) 포함 실제 mdoc 발급 |
| `src/demo-mdoc-nullifier.js` | `pnpm run demo:mdoc-nullifier` (발급 → 결정성 → scoping → 위조거부) |

```bash
# 직접 호출: <mdoc.bin> <issuer.json> <transcript.bin> <now> <attr_id> <attr_hex> <context>
native/mdoc_null_split fixtures/mdoc.bin fixtures/mdoc-issuer.json \
  fixtures/mdoc-transcript.bin 2026-06-01T00:00:00Z age_over_18 f5 context-A
# env: EVIL_NULL=1 (위조 nullifier → 증명불가), TAMPER=1 (MAC 결속 파괴 → 거부)
```

## 8. 향후 과제

- **블라인드 발급** → 발급자 추적성 격차(P) 해소 — ✅ **완료, §9 참조**.
- **길이 무관 / 다중 secret** — 앵커 + `SECB`를 다른 발급기 인코딩으로 일반화.
- 검증자측 **context 결속** — `context`를 평문 문자열 대신 trust-anchor 서명 구조로 전달.
- 블라인드 발급의 **발급-시점 well-formedness 증명**(발급자가 단일·올바른 커밋먼트만 서명) — §9.5 참조.
- 횟수제한 / 1회용 변형 (Semaphore, RLN 참조).

---

## 9. 발전 — 블라인드 발급 (발급자 역추적 제거)

§1–8은 secret을 크레덴셜에 박으므로 **발급자가 secret을 알고** 임의 scope nullifier를 계산할 수 있음(한계 **P**, §6). 이 섹션은 **발급자가 secret을 절대 모르도록** 발전시켜 P를 닫음. CI/DI 대응, 커밋먼트 아이디어, Sybil/soundness 논증은 SD-JWT판과 공유 — [`sd-jwt-nullifier_analysis-report-ko.md`](sd-jwt-nullifier_analysis-report-ko.md) §10 참조; 이 섹션은 **mdoc 고유**만 다룸.

프로토타입: `native/mdoc_null_blind.cc`; 데모 `pnpm run demo:mdoc-nullifier-blind`; 발급기 `tools/gen-mdoc-blind.mjs`. §1–8 파일은 무수정.

### 9.1 CBOR 바이트 스트링 커밋먼트

홀더가 `secret`(32B)+`blind`(32B)를 생성해 `C = SHA256(secret ‖ blind)`를 커밋. 발급자는 `pseudonym_commitment = C`만 서명하고, `@lukas.j.han/mdoc`는 이를 **CBOR 바이트 스트링**(`58 20 <32B>`)으로 발급(실증 확인). 이는 *SD-JWT보다 깔끔*함: SD-JWT는 커밋먼트가 base64url이라 회로에서 디코드해야 하지만, 여기선 32 raw 바이트가 서명된 item에 그대로 들어가 디코드가 불필요. 앵커는

```
71 "elementIdentifier" 74 "pseudonym_commitment" 6C "elementValue" 58 20   (54B)
```

뒤에 32바이트 커밋먼트가 따름. `secret`/`blind`는 홀더 측(`mdoc-holder-secret.txt`)에만 있고, 증명자는 `HOLDER_SECRET`로 읽음.

### 9.2 `assert_nullifier` 변경점 (§2.2 대비)

(1) MSO-preimage + 인덱스 범위검사, (2) 멤버십 `SHA(item) ∈ MSO valueDigests`는 **불변** — 이제 *커밋먼트* item이 발급자 서명임을 증명. 나머지:

3. **추출** — 54바이트 앵커를 앞으로 shift·assert 후 다음 32바이트를 `C`로 취함; 이를 SHA 비트순(`MdocHash`의 `mm`과 동일 reversal)으로 `v256 cm` 구성.
4. **오프닝(신규)** — `open_pre = secret ‖ blind ‖ 패딩`을 바인딩하고 `SHA(open_pre) == cm`을 단일 `assert_message_hash`로 assert(기대 다이제스트가 곧 추출된 커밋먼트라 별도 witness/비교 불필요). 발급자-커밋 `C` 뒤의 `(secret, blind)`를 안다는 증명.
5. **nullifier** — `SHA(secret ‖ context_hash)`, 전체 바인딩; (4)와 (5)가 **같은 `secret` wire** 공유.

§2.2 대비 순수 신규 = **SHA 1블록(오프닝) + 더 넓은 앵커**; secret은 item에서 추출하는 대신 숨긴 witness(32B)가 됨.

### 9.3 속성 (`demo:mdoc-nullifier-blind`로 검증)

§3 + 결정적인 blind 속성:

| 단계 | 검사 | 결과 |
|---|---|---|
| 같은 `(secret, context)` | 동일 nullifier | ✅ DI 중복탐지 |
| 다른 `context` | 다른 nullifier | ✅ 비연결 |
| `EVIL_NULL`(위조 nullifier) | 증명 불가 | ✅ REJECT |
| **`EVIL_SECRET`**(C를 못 여는 secret) | **`eval_circuit failed`**(hash 회로) | ✅ **REJECT** |
| `TAMPER`(MAC 1비트) | 양쪽 회로 거부 | ✅ REJECT |

### 9.4 성능 (실측, 공개속성 1 + blind nullifier)

| | sig (Fp256) | hash (GF(2¹²⁸)) |
|---|---|---|
| ninputs | ~3.7k | ~100k |
| proof | ~195KB | ~151KB |

end-to-end: **prove ≈ 1.1초, verify ≈ 0.5초, 번들 ≈ 346KB** — §4와 사실상 동일(오프닝이 싼 이진체에 SHA 1블록 추가). 캐시 `circuits-cache/mdoc-nullblind-hash-<geo>.bin`; sig 회로(및 캐시)는 §1–8과 공유·무변경.

### 9.5 Soundness

위협모델·판정은 SD-JWT blind판([`sd-jwt-nullifier_analysis-report-ko.md`](sd-jwt-nullifier_analysis-report-ko.md) §10.5)과 동일: S1(결정성)·S3(scope) 불변; **S2**는 이제 *커밋먼트* 경유로 secret 고정(`SHA(commitment item) ∈ valueDigests → SHA(MSO)=e → 발급자 ECDSA`, **추가로** 오프닝 `SHA(secret‖blind)==C`); **P**는 이제 달성 — 발급자는 `C`(hiding)만 봤으므로 어떤 nullifier도 계산 불가. Sybil은 여전히 발급자 1인-1개 정책(§6)에 의존(블라인딩과 독립).

Free-index 감사: `sec_mso`·`sec_anchor`는 §5.1과 동일(앵커가 이제 `58 20`로 끝나는 54B; 리터럴 앵커가 오프셋을 유일 강제, 32 값바이트는 hash-attestation이 아니라 오프닝 `SHA(secret‖blind)==C`로 고정). `secret`/`blind`는 직접 숨긴 witness(잘못 가리킬 인덱스 없음), 오프닝·nullifier 공유.

> 발급-시점 well-formedness(발급자가 `C`가 단일·올바른 커밋먼트임을 증명 요구)는 별도 프로토콜 단계로 데모에선 단순화 — SD-JWT판(§10.6)과 동일.

### 9.6 파일 / 실행

| 파일 | 역할 |
|---|---|
| `native/mdoc_null_blind.cc` | blind 변형 — 커밋먼트 멤버십 + 오프닝 + nullifier (MdocHash 회로) |
| `tools/gen-mdoc-blind.mjs` | 홀더가 `C` 커밋; 발급자는 `pseudonym_commitment`(바이트 스트링)만 서명 |
| `src/demo-mdoc-nullifier-blind.js` | `pnpm run demo:mdoc-nullifier-blind` |
| `fixtures/mdoc-holder-secret.txt` | 홀더 전용 `secret_hex ‖ blind_hex` (발급자에 전송 안 됨) |

```bash
# 직접 호출 (홀더 secret을 HOLDER_SECRET = secret_hex ‖ blind_hex 로 읽음):
HOLDER_SECRET=fixtures/mdoc-holder-secret.txt \
native/mdoc_null_blind fixtures/mdoc-blind.bin fixtures/mdoc-blind-issuer.json \
  fixtures/mdoc-blind-transcript.bin 2026-06-01T00:00:00Z age_over_18 f5 context-A
# env: EVIL_NULL=1 (위조 nullifier), EVIL_SECRET=1 (secret이 C를 못 엶), TAMPER=1 (MAC 깨기)
```
