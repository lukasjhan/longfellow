# SD-JWT-VC 영지식 회로 설계 (Approach C: Disclosure/`_sd` 멤버십)

목표: longfellow의 실험용 JWT(substring) 회로를 넘어, **mdoc급**의 SD-JWT-VC ZK를
구현한다 — 모든 값 타입(문자열/날짜/불리언/숫자/중첩) + **유효기간(exp)** + Key
Binding + 표준 선택공개.

## 왜 파싱이 아니라 멤버십인가

mdoc도 SD-JWT도 **JSON/CBOR를 회로에서 파싱하지 않는다.** 둘 다 **클레임마다
salt+해시**해 서명된 다이제스트 집합에 넣고, 증명은 그 **멤버십**으로 한다.

| | mdoc | SD-JWT-VC |
|---|---|---|
| 클레임 단위 | `IssuerSignedItem=[digestID,salt,id,value]` (CBOR) | `Disclosure=base64url([salt,name,value])` |
| 서명된 다이제스트 집합 | MSO `valueDigests` | payload `_sd` |
| 증명 | SHA(item)∈valueDigests + (id,value) 일치 | SHA(disclosure)∈`_sd` + (name,value) 일치 |

→ 값이 무엇이든(불리언 `true`, 숫자 `175`) **해시 단위 안에 통째로** 들어가므로
substring의 prefix 모호성(`18`⊂`180`)이 원천 소거된다. (레퍼런스 구현:
`src/decode-sdjwt.js`, 데이터: `tools/gen-sdjwt.mjs` → `fixtures/`.)

## 회로가 증명할 명제

공개 입력: 발급자 `pkX,pkY`, KB 해시 `e2`, `now`, 그리고 요청 disclosure마다
`(claimName, claimValueJSON)`.
비공개 witness: 발급자 JWT 서명, payload preimage, 각 요청 disclosure 문자열과 salt,
그리고 위치 인덱스들.

1. **발급자 서명**: `ECDSA.verify3(pkX,pkY, e=SHA256(header.payload), jwt_sig)`
2. **Key Binding**: `ECDSA.verify3(dpkX,dpkY, e2, kb_sig)` (홀더 키 `cnf.jwk`)
3. **유효기간**: payload에서 `"exp":<digits>` 추출 → 정수화 → `now ≤ exp`
4. **각 disclosure**:
   a. `digest = SHA256(ascii(disclosure))`
   b. **멤버십**: `_sd`의 어떤 항목을 base64url-디코드한 32B == `digest` (그 항목 위치는
      서명된 payload 안 → 발급자 서명으로 보증)
   c. **구조 일치**: `disclosure`를 base64url-디코드 → `["<salt>","<name>",<value>]` 가
      요청한 `(name,value)`와 일치 (salt는 길이 가변 witness, value는 닫는 `]`까지 매칭)

## longfellow 재사용 / 신규

| 블록 | 재사용? | 출처 |
|---|---|---|
| ECDSA verify3 (×2) | ✅ | `circuits/ecdsa/verify_circuit.h` (jwt.h가 사용) |
| FlatSHA256 (header.payload, 그리고 disclosure 해시) | ✅ | `circuits/sha/flatsha256_circuit.h` |
| base64url 디코드 | ✅ | `circuits/tests/base64/decode.h` (jwt.h가 사용) |
| Routing/shift (인덱스로 정렬) | ✅ | `circuits/logic/routing.h` |
| 바이트 동등/`vlt`/`assert_implies` | ✅ | `circuits/logic/logic.h` |
| **`_sd` 멤버십** (SHA==base64decode(entry)) | 🆕 | mdoc `MdocHash`의 digest-멤버십이 개념 동일 |
| **구조적 disclosure 동등** (가변 salt) | 🆕 | jwt.h `assert_string_eq` 확장 |
| **exp 정수 파싱 + 비교** | 🆕 | digit→값 누적(×10) + `vlt` |

## Witness (prover 제공) 핵심

- payload 위치/길이 (preimage 내)
- 요청 disclosure마다: disclosure 바이트, salt 길이, `_sd` 내 매칭 항목의 인덱스,
  disclosure를 base64-디코드한 평문 내 name/value 오프셋
- exp 숫자의 위치/자릿수

## 마일스톤 (점진·검증가능)

- **M1 ✅**: 실제 SD-JWT-VC 발급기 + 의존성 없는 레퍼런스 검증기 + 설계.
  `tools/gen-sdjwt.mjs`, `src/decode-sdjwt.js`, `fixtures/`.
- **M2 ✅** (eval): exp 비교 서브회로 + EvaluationBackend 하니스. `native/sdjwt_eval.cc`.
- **M4-core ✅** (eval): SHA(disclosure) in-circuit + `_sd` 멤버십(base64 디코드+비교),
  정상 accept/위조 reject.
- **4a ✅** (eval): disclosure 구조 추출 `["salt","name",value]` (가변 salt) — 문자열/불리언/숫자.
- **4b ✅** (eval): **실제 fixture 통합** — payload에서 exp·`_sd` 엔트리 인덱스 탐색 후
  exp+멤버십+구조추출 end-to-end PASS (불리언 포함). `pnpm run eval:sdjwt`.
- **M5 (남음)**: ECDSA 프론트엔드(발급자+KB, 이미 jwt.h/jwt_cli에서 검증) 결합 →
  CompilerBackend 컴파일 → 실제 ZK prove/verify → witness 빌더 → `sdjwt_cli`+Node 데모.
- **M6 (남음)**: 회로 캐시, 문서.

> 현재 상태: **신규 암호 로직(exp·SHA·멤버십·구조)이 실제 데이터로 전부 eval 검증됨.**
> 남은 M5는 새 암호 발명이 아니라 "검증된 로직 + 기존 ECDSA를 한 회로로 컴파일해
> 실제 ZK 증명·Node 연동" 통합 작업(가장 큰 단일 단계).

## 리스크 / 공수

- 가장 무거운 작업(수일~수주). 회로 DSL·soundness 검토 필요.
- 위험 지점: (a) base64 길이/정렬 경계, (b) 가변 salt 길이 처리, (c) exp 자릿수 경계,
  (d) disclosure SHA의 블록 수(길이) → 회로 크기.
- 완화: mdoc/jwt 기존 회로를 참조틀로, M2(평문 witness+eval)로 ZK 전에 로직 검증.

## 열린 결정

- KB의 `e2`(KB 메시지 해시) 산출 방식: 현재 longfellow처럼 외부 제공 vs 회로 내 계산.
- disclosure 최대 길이/개수 상한(회로 크기와 직결).
- `_sd` 항목 개수 상한(멤버십 탐색 범위).
