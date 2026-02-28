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

#### 진행 중: mdoc급 SD-JWT-VC (Approach C)

위 substring 한계를 넘어, **표준 SD-JWT-VC의 `_sd` Disclosure 멤버십**으로 모든
타입 + 유효기간(exp) + Key Binding을 지원하는 회로를 설계 중입니다. 설계·마일스톤은
[`SDJWT_PLAN.md`](SDJWT_PLAN.md). 현재 M1(데이터·레퍼런스) 완료:

```bash
pnpm run gen:sdjwt      # 실제 ES256 SD-JWT-VC 발급 → fixtures/ (deps 필요: node_modules 심볼릭링크)
pnpm run decode:sdjwt   # 의존성 없이 disclosure 해시가 _sd에 있는지 검증 (회로가 할 일의 레퍼런스)
```
→ 문자열/날짜/불리언/숫자 모두 `_sd` 멤버십으로 검증됨을 확인(파싱 불필요).

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

상세 분석은 상위 폴더의 [`../longfellow-zk_분석보고서.md`](../longfellow-zk_분석보고서.md) 참고.

---

## 다음 단계 (확장 아이디어)

- **실제 발급 연동**: `@auth0/mdl` 등으로 새 ECDSA mdoc를 발급한 뒤 longfellow로
  present/verify. CBOR/MSO/deviceKey/transcript 구조가 longfellow 파서 기대와
  맞아야 하므로 호환성 검증이 필요(프루버가 에러코드 반환 시 단서).
- **다속성 증명**: `gencircuit --attrs 2`(또는 그 이상) + `--attr` 여러 개. 예제
  index 3(Sprind-Funke)은 `family_name` 등 다속성 포함.
- **N-API 전환**: 프로세스 기동 오버헤드를 없애려면 `longfellow_cli.cc`의 로직을
  node-addon-api로 감싸 in-process 호출로 교체.
- **HTTP API화**: `research-eudi-module`처럼 NestJS 엔드포인트(`/present`,
  `/verify`)로 노출.
