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
- **M3 ✅** (실제 ZK): exp(M3a) + `_sd` 멤버십(M3b) + 구조 추출(M3c)을 CompilerBackend로
  컴파일 → ZkProver/ZkVerifier로 prove/verify ACCEPT (~1.4s, proof ~239KB). `native/sdjwt_zk.cc`.
  불리언 `age_over_18:true`까지 ZK 동작. (SHA witness를 회로 입력으로 선언/충전.)
- **M5 ✅** (실제 ZK, full): 발급자 ES256 서명(VerifyWitness3 직접) + header.payload SHA +
  payload base64 디코드 + exp + `_sd` 멤버십 + 구조 추출을 **하나의 회로**로 컴파일,
  실제 SD-JWT-VC fixture에서 ZK prove/verify. `native/sdjwt_full.cc`, `pnpm run demo:sdjwt-zk`.
  - 증명: "발급자 서명 유효 + 만료 안 됨 + age_over_18 ∈ _sd = **true(불리언)**" (서명·다른
    클레임·salt 비공개). ACCEPT (proof ~408KB, ninputs ~31k, ~10s). 만료 시 REJECT.
  - **갓 발급한 새 토큰에서도 동작** → witness 빌더가 임의 실제 토큰을 파싱.
  - KB(홀더 바인딩)는 제외(이미 jwt_cli에서 동작; 추가는 기계적). cnf 포맷 의존 회피 위해
    JWTWitness 대신 VerifyWitness3 직접 사용.
- **M6a ✅** (실제 ZK): **다속성 동시공개** — NATTR(=3) disclosure 슬롯, (name,value)를
  공개 입력 패턴으로. given_name(문자열)+age_over_18(불리언)+height(숫자)를 한 ZK proof로.
- **M6b ✅** (실제 ZK): **Key Binding** — 홀더 KB 서명 검증 + dpk를 payload의 cnf.jwk에
  바인딩(cnf.x/y를 회로 내 base64 디코드해 dpk 비트와 비교). e2는 공개 입력.
  발급기(gen-sdjwt)가 kbjwt 생성. `pnpm run demo:sdjwt-zk`.
  → 한 ZK proof에 **발급자 서명 + KB + exp + 3속성 멤버십** 전부 ACCEPT(~461KB, ~13s), 만료 REJECT.
- **M6c ✅** (실제 ZK): **sd_hash 바인딩 (정석/in-circuit)** — KB가 서명한 `sd_hash`가
  실제 제시 묶음과 일치함을 회로가 검증. 체인: KB서명→e2→kb_pre(SHA==e2)→payload에서
  sd_hash 추출→`SHA(presented)==sd_hash`→공개 disclosure들이 presented에 포함.
  → "공개한 disclosure ⊆ 홀더가 서명한 제시 묶음" 강제. ACCEPT(proof ~572KB, ~27s), 만료 REJECT.
- **M6d ✅** (실제 ZK): mdoc 대비 갭 마감.
  - **vct 검증**: payload의 `"vct":"<type>"`를 공개 입력 패턴과 대조 (잘못된 vct → REJECT 확인).
  - **다속성 N 가변**: NATTR을 런타임 파라미터로(벡터). 2·3·4속성 모두 동작. claims는 argv로 지정.
  - **회로 캐싱**: CircuitWriter/Reader로 컴파일된 회로를 N별 zstd 압축 캐시
    (`circuits-cache/sdjwt-<N>attr.bin`, 145MB→~3MB). 재실행 시 **컴파일 ~23s → 로드 ~0.4s**.
- **M6e (남음/선택)**: 2체 분리(GF2¹²⁸ 해시) 최적화, W3C VC, 공개 API화.

> 현재 상태: **mdoc 패리티 이상 달성** — SD-JWT-VC 선택공개 ZK가 실제 토큰에서 end-to-end
> 동작. 모든 값 타입(불리언/숫자/날짜) + 유효기간(exp) + Key Binding + **sd_hash 바인딩** +
> 다속성 동시공개를, 파싱 없이 `_sd` 멤버십으로.

## 리스크 / 공수

- 가장 무거운 작업(수일~수주). 회로 DSL·soundness 검토 필요.
- 위험 지점: (a) base64 길이/정렬 경계, (b) 가변 salt 길이 처리, (c) exp 자릿수 경계,
  (d) disclosure SHA의 블록 수(길이) → 회로 크기.
- 완화: mdoc/jwt 기존 회로를 참조틀로, M2(평문 witness+eval)로 ZK 전에 로직 검증.

## 열린 결정

- KB의 `e2`(KB 메시지 해시) 산출 방식: 현재 longfellow처럼 외부 제공 vs 회로 내 계산.
- disclosure 최대 길이/개수 상한(회로 크기와 직결).
- `_sd` 항목 개수 상한(멤버십 탐색 범위).
