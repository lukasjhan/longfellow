# Longfellow ZK Playground (Node.js)

`google/longfellow-zk`(C++ 영지식 라이브러리)를 **Node.js에서 호출**해, mdoc를
**issue(발급) → present(ZK 증명) → verify(검증)** 하는 플레이그라운드입니다.

```
Node.js ──spawn──▶ longfellow_cli (C++)  ──▶ longfellow-zk C API
        ◀── JSON ──┘
```

- 연동 방식: **CLI 서브프로세스** (네이티브 애드온/ABI 불필요, 가장 단순)
- 자격증명 포맷: **mdoc (ISO 18013-5 mDL)** ✅
  - ※ longfellow는 JWT/W3C VC용 **공개 API가 없습니다**(실험 회로만 존재). 그래서 이 플레이그라운드는 mdoc 전용입니다.
- 증명 대상 예시: **`age_over_18 = true`** (이름·생년월일·서명은 비공개)

---

## ⚠️ 꼭 알아둘 점: longfellow는 mdoc를 "발급"하지 않습니다

longfellow는 **이미 ECDSA로 서명된 mdoc**에 대해 **ZK present/verify만** 수행합니다.
따라서 이 플레이그라운드의 "issue" 단계는 longfellow에 **내장된 예제 mdoc**(이미
발급·서명되어 있음)를 꺼내 쓰는 것으로 시뮬레이션합니다. 실제 발급(새 ECDSA mdoc
생성)은 별도 라이브러리(`@auth0/mdl` 등)의 몫이며, 이는 다음 단계 과제입니다
(아래 "다음 단계" 참고).

---

## 사전 요구사항

- Node.js 18+ (테스트: v24), `pnpm` (또는 npm)
- C++ 빌드: `cmake`, `clang-17`, 시스템 `openssl`/`zstd`/`zlib` 개발 헤더

> **툴체인 주의**: 이 머신의 기본 `clang++`(Swift 툴체인)는 `libstdc++`를 찾지
> 못합니다. `native/build.sh`가 시스템 `clang-17`을 `--gcc-install-dir`로 감싸는
> 래퍼(`../.toolchain/clang++w`)를 자동 생성해 우회합니다. GCC 경로가 다르면
> `GCC_INSTALL_DIR` 환경변수로 지정하세요.

---

## 빌드 & 실행

```bash
cd playground

# 1) C++ 라이브러리 + CLI 빌드 (최초 1회, 수 분 소요)
pnpm run build:native        # == bash native/build.sh

# 2) N별 회로 사전 생성·캐시 (최초 1회, N=1~4 약 1분)
pnpm run circuits            # circuits/circuit-<N>attr.bin + manifest.json

# 3) 전체 흐름 데모 (issue → setup → present → verify → tamper-reject)
pnpm run demo                # 캐시 사용 시 ~2초
```

> 회로는 mdoc과 무관하게 **속성 개수 N에만** 의존하므로 한 번 만들어 재사용합니다.
> `pnpm run circuits`로 N=1~4를 `circuits/`에 캐시해두면, 이후 present/verify는
> 매번 ~14초 생성 없이 캐시를 골라 씁니다(데모 전체 ~2초). 회로를 미리 안 만들어도
> 데모가 필요할 때 자동 생성·캐시합니다(`ensureCircuit`).

**다속성 동시 증명** (예제 #3 = Sprind-Funke, 5속성 보유):

```bash
pnpm run demo:multi                                  # family_name + age_over_18 (기본)
node src/demo-multi.js 3 family_name,height,age_over_18   # 혼합 타입 3속성
```
mdoc에서 각 속성의 **raw CBOR 값을 그대로 추출**해 `--attrs N` 회로로 한 번에
공개하고, 한 속성 값만 위조하면 거부되는 것까지 보여줍니다.

**SD-JWT(+KB) 영지식 증명** (longfellow의 실험용 JWT 회로):

```bash
pnpm run demo:jwt                                  # given_name=Erika (예제0)
node src/demo-jwt.js 1 family_name Mustermann      # 다른 토큰/속성
```
실제 SD-JWT-VC + Key Binding 토큰(ES256 서명)에서 **`"id":"value"` 문자열 속성**을
영지식 공개합니다. 검증자는 **토큰 원문 없이** pk·e2·attr만으로 검증합니다.

> ⚠️ JWT 회로는 longfellow의 **실험용**(`circuits/tests/jwt`)이며 공개 API가 없어,
> `native/jwt_cli.cc`가 회로를 직접 빌드해 ZK를 구동합니다. mdoc과 달리 **문자열
> 속성만** 증명 가능(`age_over_18:true` 같은 불리언/숫자는 불가). 회로 캐시도 없어
> prove/verify가 매번 회로를 빌드합니다(각 ~5초).

#### ✅ mdoc급 SD-JWT-VC 선택공개 ZK (Approach C)

위 substring 한계를 넘어, **표준 SD-JWT-VC의 `_sd` Disclosure 멤버십**으로 **모든
값 타입 + 유효기간(exp) + vct + Key Binding + sd_hash 바인딩 + 다속성(N가변)**을
지원하는 실제 ZK 회로를 구현했습니다(설계: [`SDJWT_PLAN-ko.md`](SDJWT_PLAN-ko.md)).

```bash
pnpm run gen:sdjwt       # 실제 ES256 SD-JWT-VC 발급 → fixtures/ (deps: node_modules 심볼릭링크)
pnpm run decode:sdjwt    # 의존성 없이 disclosure 해시 ∈ _sd 검증 (회로가 할 일의 평문 레퍼런스)
pnpm run eval:sdjwt      # 신규 서브회로(exp·SHA·멤버십·구조) eval 검증
pnpm run demo:sdjwt-zk   # ⭐ 실제 ZK: issue → present → verify (age_over_18=true), 만료 시 REJECT
```

`demo:sdjwt-zk`는 **발급자 ES256 서명 + 홀더 Key Binding + sd_hash 바인딩 + vct +
`now≤exp` + 3속성(given_name·age_over_18·height = 문자열·불리언·숫자) ∈ `_sd`** 를
**하나의 ZK 증명**으로 prove/verify합니다(서명·다른 클레임·salt·디바이스키 비공개).
substring 방식이 못 하던 **불리언/숫자/날짜**가 `_sd` 멤버십 덕에 전부 안전합니다(파싱 불필요).

공개 속성 개수·종류는 런타임 가변이고(회로는 N별로 컴파일), 컴파일된 회로는
zstd 압축 캐시(`circuits-cache/sdjwt-<N>attr.bin`)되어 재실행 시 컴파일(~23s)을 건너뜁니다:

```bash
# 직접 호출: <fixture> <issuer-jwk> <now> <쉼표구분 claims> <vct>
native/sdjwt_full fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "given_name,age_over_18" "https://credentials.example/pid"
```

> 핵심: mdoc도 SD-JWT도 "클레임별 salt+해시 → 서명된 다이제스트 집합 멤버십"으로
> 선택공개. 회로 빌딩블록(ECDSA·SHA·base64)은 longfellow 재사용, 신규는 멤버십·구조·exp.
> Key Binding은 홀더 서명을 검증하고 디바이스키를 payload의 cnf.jwk에 바인딩하며,
> **sd_hash 바인딩**(정석)으로 `SHA(제시 묶음)==KB의 sd_hash` 를 회로가 검증해
> "공개한 disclosure ⊆ 홀더가 서명한 제시 묶음"을 강제합니다(disclosure 짜깁기 방지).

#### ⚡ 2회로 + MAC 분리 (mdoc과 동일 아키텍처)

위 `sdjwt_full`은 **단일 Fp256 회로**(소수체)라 SHA가 비쌉니다. mdoc처럼 작업을
**두 회로로 분리**하면 훨씬 빠릅니다 — SHA/해시는 이진체 **GF(2¹²⁸)**가 Fp256보다
~5배 저렴하기 때문입니다(`native/sha_bench.cc`로 직접 측정).

- **서명 회로(Fp256)** `native/sdjwt_sig.cc`: 발급자 ES256 + 홀더 KB ES256.
- **해시 회로(GF2¹²⁸)** `native/sdjwt_hash.cc`: SHA + exp + vct + cnf + sd_hash +
  N×(`_sd` 멤버십·구조·consent) 전체.
- **결속** `native/sdjwt_split.cc`: 공통값 e/dpkx/dpky를 **MAC로 묶음**. `a_v`(MAC 키
  절반)를 **commit 이후 트랜스크립트에서 유도**하므로 증명자가 두 회로에 다른 값을 못
  넣습니다(건전). e2는 양 회로 공개입력.

```bash
pnpm run demo:sdjwt-split             # ⭐ Node 데모: issue → 2회로 present+verify → 만료/변조/큰토큰
pnpm run gen:sdjwt-big                # 13속성 PID급 큰 크레덴셜 발급(fixtures/sdjwt-big.txt)
native/sha_bench                      # Fp256 vs GF(2^128) SHA 회로크기·시간 벤치
native/sdjwt_split                    # 2회로 present+verify (3속성), 둘 다 ACCEPT
TAMPER=1 native/sdjwt_split           # mac 1비트 변조 → 양 회로 REJECT (링크 강제 증명)
```

측정(3속성): **prove(both) ~1.6s, 번들 386KB** (sig 194KB + hash 192KB). 단일
`sdjwt_full`(~13s, end-to-end)과 비교해 **약 8배 단축**. 회로 캐시도 318MB→6.5MB(단일)
대비 164KB+1.7MB(분리)로 작습니다.

**용량은 고정(모든 ZK의 본질)이되 넉넉히** — `kMaxSHA=32`(payload 2KB)·`PB=40`(presented
2.5KB)·`MAXB=4`(disclosure 256B) 등 mdoc 수준으로 잡았고, 토큰이 이를 넘으면 호스트가
버퍼 오버플로 대신 **명확한 에러**를 냅니다(예: `... > kMaxSHA=32 (2048B)`, mdoc의
`MDOC_PROVER_TAGGED_MSO_TOO_BIG`에 해당). 13속성 큰 토큰도 동작합니다(데모 [5]단계).

단계별 실행도 가능합니다(상태는 `artifacts/`에 저장):

```bash
pnpm run issue      # 예제 mdoc 로드 + ZK 회로 생성(캐시)
pnpm run present    # ZK 증명 생성 → artifacts/proof.bin
pnpm run verify     # 증명 검증 (ACCEPT면 exit 0)

# 다른 예제 mdoc 사용 (0~23):  node src/playground.js issue 3
# C++ 상세 로그 보기:          DEBUG=1 pnpm run demo
```

### mdoc 안에 무엇이 들어있나 보기 (`decode`)

발급자가 서명해 넣은 속성(= ZK로 공개 가능한 후보)을 확인합니다(의존성 없는
CBOR 디코더 내장):

```bash
pnpm run decode                       # artifacts/mdoc.bin 디코드
node src/decode-mdoc.js /path/x.bin   # 임의 mdoc 파일
```

출력에는 issuer-signed 속성(id=값), MSO의 valueDigests 개수·유효기간,
deviceKey 유무가 표시됩니다. 핵심: **MSO digest 수 ≥ 실제 들어있는
IssuerSignedItem 수** 일 수 있고, ZK 증명은 **preimage(IssuerSignedItem)가
존재하는 속성만** 가능합니다.

### 예상 출력 (요지)

```
[1] ISSUE   issuer pkx, doctype=org.iso.18013.5.1.mDL, mdoc=1452 bytes
[2] SETUP   circuit v7, hash 8d079211…, 307873 bytes  (~14s, 1회성)
[3] PRESENT proof 360KB in ~1.1s
[4] VERIFY  ACCEPT ✅  (~0.6s)
[5] VERIFY  TAMPERED → REJECT ✅
```

| 단계 | 1회성? | 대략 소요(이 머신) |
|---|---|---|
| 회로 생성 `gencircuit` | 예(캐시) | ~14 s |
| 증명 `present` | 매 제시 | ~1.1 s |
| 검증 `verify` | 매 검증 | ~0.6 s |

---

## 구조

```
playground/
├── native/
│   ├── longfellow_cli.cc   # longfellow C API를 감싼 CLI (export-example/gencircuit/prove/verify)
│   ├── build.sh            # 라이브러리+CLI 빌드 스크립트
│   └── longfellow_cli      # (빌드 산출물)
├── src/
│   ├── longfellow.js       # Node 래퍼: CLI를 spawn하고 JSON 결과 파싱
│   ├── demo.js             # 전체 자동 데모
│   └── playground.js       # 단계별 CLI (issue/present/verify)
├── artifacts/              # mdoc.bin, transcript.bin, circuit.bin, proof.bin, *.json
└── package.json
```

### 동작 원리 (요약)

1. **Issue** — `longfellow_cli export-example`이 내장 예제(`mdoc_examples.h`)의
   mdoc·세션 transcript·발급자 공개키를 파일로 덤프 → "발급된 자격증명".
2. **Setup** — `gencircuit`이 속성 개수에 맞는 ZK 회로를 생성/압축하고
   `ZkSpec`(system, circuit_hash)를 반환. 한 번만 만들어 캐시.
3. **Present** — `prove`가 `run_mdoc_prover`를 호출. 내부적으로 **두 회로**(P-256
   상의 ECDSA 서명 회로 + GF(2^128) 상의 SHA/CBOR 해시 회로)에 대해 암호화된
   sumcheck + Ligero 증명을 만들고 MAC으로 결속.
4. **Verify** — `verify`가 `run_mdoc_verifier`로 두 증명을 모두 검사. 둘 다
   통과해야 ACCEPT.

상세 분석은 상위 폴더의 [`../longfellow-zk_analysis-report-ko.md`](../longfellow-zk_analysis-report-ko.md) 참고.

---

## 다음 단계 (확장 아이디어)

**원래 mdoc 데모 이후 완료된 것:**

- ✅ **실제 발급 연동** — `@lukas.j.han/mdoc`로 실제 mdoc 발급+제시(`pnpm run gen:mdoc`),
  실제 ES256 SD-JWT-VC 발급(`pnpm run gen:sdjwt`). 둘 다 longfellow가 end-to-end로 수용
  (PD 불필요; 전체 issuerSigned + 빈 deviceNS + ES256 deviceSignature + raw SessionTranscript).
- ✅ **SD-JWT-VC 선택공개 ZK** — 단일 회로(`sdjwt_full`) + 2회로 MAC 결속 split(`sdjwt_split`).
  위 SD-JWT 섹션 참고.
- ✅ **다속성 증명** — SD-JWT 데모는 기본 3속성 공개(+`pnpm run gen:sdjwt-big`로 13속성
  PID급 자격증명); mdoc CLI는 `gencircuit --attrs N` + `--attr` 여러 개 지원(예제 index 3
  Sprind-Funke는 `family_name` 등 다속성 포함).
- ✅ **가명 nullifier (CI/DI 대응)** — 두 포맷 모두: `pnpm run demo:nullifier`(SD-JWT),
  `pnpm run demo:mdoc-nullifier`(실제 mdoc). 발급자가 `pseudonym_secret`을 커밋하고, 회로가
  secret을 숨긴 채 `nullifier = SHA(secret ‖ SHA(context))`를 증명. 보고서:
  [`sd-jwt-nullifier_analysis-report-ko.md`](../sd-jwt-nullifier_analysis-report-ko.md),
  [`mdoc-nullifier_analysis-report-ko.md`](../mdoc-nullifier_analysis-report-ko.md)
  (블라인드 발급·임의 필드순서 일반화 등 각 future work는 보고서 §8에).
- ✅ **프라이버시 보존 폐기 (서명된 구간 비-멤버십)** — 두 포맷 모두:
  `pnpm run demo:revocation`(SD-JWT), `pnpm run demo:mdoc-revocation`(실제 mdoc).
  발급자가 `revocation_id`를 커밋(그 `_sd` 다이제스트 / mdoc valueDigests 항목 = `rev_id`)하고,
  폐기기관이 인접 폐기 id 사이 빈 구간 `epoch‖l‖r`을 서명, 회로가 `l < rev_id < r`을 ZK로 증명 —
  **목록 크기와 무관한 상수 크기** 비-폐기 증명이며 `rev_id`도 어떤 크리덴셜인지도 노출 안 함.
  `e_span`을 4번째 MAC-link 값으로 추가. soundness 검증: `REVOKED`/`BADSIG`/`STALE`/`TAMPER` 모두 거부.
  보고서: [`sd-jwt-revocation_analysis-report-ko.md`](../sd-jwt-revocation_analysis-report-ko.md),
  [`mdoc-revocation_analysis-report-ko.md`](../mdoc-revocation_analysis-report-ko.md).

**남은 것:**

- **N-API 전환**: 프로세스 기동 오버헤드를 없애려면 `longfellow_cli.cc`의 로직을
  node-addon-api로 감싸 in-process 호출로 교체.
- **HTTP API화**: `research-eudi-module`처럼 NestJS 엔드포인트(`/present`,
  `/verify`)로 노출.
