# Longfellow ZK — 분석 & Node.js 플레이그라운드

[google/longfellow-zk](https://github.com/google/longfellow-zk)(구글의 영지식
신원증명 C++ 라이브러리)를 **분석**하고, 이를 **Node.js에서 호출**해 mdoc를
**issue(발급) → present(ZK 증명) → verify(검증)** 하는 **플레이그라운드**를
구축한 작업 저장소입니다.

> 한 줄 요약: 레거시 **ECDSA(P-256)** 로 서명된 mdoc(ISO 18013-5 mDL)에 대해,
> 발급자 인프라를 바꾸지 않고 **"age_over_18" 같은 속성만 영지식으로 선택 공개**
> 하는 것을 Node에서 실제로 동작시켰습니다.

---

## 디렉토리 구조

```
longfellow/
├── README.md                    # (이 파일) 전체 개요·재현법
├── longfellow-zk_분석보고서.md   # 소스코드 심층 분석 (한글, 12장)
├── longfellow-zk/               # 업스트림 클론 (git에서 제외, 아래 "재현" 참고)
├── playground/                  # ⭐ Node.js 플레이그라운드 (issue→present→verify)
│   ├── native/longfellow_cli.cc #   longfellow C API 래퍼 CLI
│   ├── native/build.sh          #   라이브러리+CLI 빌드 스크립트
│   ├── src/longfellow.js        #   Node 래퍼 (CLI spawn + JSON 파싱)
│   ├── src/demo.js              #   전체 자동 데모
│   ├── src/playground.js        #   단계별 CLI
│   └── README.md                #   플레이그라운드 상세 문서
├── references/                  # 관련 논문 (PDF는 git 제외, references/README.md에 링크)
├── build/                       # cmake 빌드 산출물 (git 제외)
└── .toolchain/                  # clang 래퍼 (자동 생성, git 제외)
```

---

## 1. longfellow-zk 란?

기존 신원 표준(ISO **mdoc/mDL**, JWT, W3C VC)을 **바꾸지 않고** 영지식증명(ZK)을
입히기 위한 C++ 라이브러리. 핵심 난제인 **"ECDSA 서명된 자격증명을 서명 노출 없이
ZK로 증명"** 을 두 빌딩블록으로 해결합니다.

- **(암호화된) Sumcheck 프로토콜** — 산술회로 `C(x,w)=0` 의 올바른 계산을 증명
- **Ligero 논증** — **신뢰 셋업 없이**, 충돌저항 해시(SHA-256)만 가정하는 커밋먼트

가장 중요한 설계: mdoc 검증을 **두 회로**로 나눠 각 체에서 최적 구현하고 MAC으로 결속.
- `Fp256` 위의 **ECDSA 서명 회로** (`circuits/ecdsa/`)
- `GF(2^128)` 위의 **SHA-256 + CBOR 해시 회로** (`circuits/sha/`, `cbor_parser_v2/`)

> 📖 **자세한 동작 원리·코드 분석은 [`longfellow-zk_분석보고서.md`](longfellow-zk_분석보고서.md) 참고.**

### 지원 포맷 현황 (코드 기준)

| 포맷 | 공개 C API | 플레이그라운드 ZK |
|---|---|---|
| **mdoc (ISO 18013-5)** | ✅ 있음 | ✅ present/verify (`demo`, `demo:multi`) — 전 타입 |
| **SD-JWT (substring)** | ⚠️ 실험 회로 | ✅ 문자열 속성 (`demo:jwt`) — longfellow JWT 회로 하니스 |
| **SD-JWT-VC (`_sd` 멤버십)** | ❌ (직접 구현) | ✅ **전 타입 + exp + vct + Key Binding + sd_hash 바인딩 + 다속성(N가변) + 회로캐시** (`demo:sdjwt-zk`) — Approach C 신규 회로 |
| W3C VC | ❌ 없음 | 미지원 |

> 플레이그라운드는 세 가지 ZK 경로가 동작합니다:
> - **mdoc** — 완전 지원(공개 API), 모든 타입.
> - **SD-JWT(substring)** — longfellow 실험 회로, 문자열만.
> - **SD-JWT-VC(`_sd` 멤버십, Approach C)** — 우리가 직접 구현한 회로로 **불리언·숫자·날짜
>   + 유효기간(exp) + Key Binding + 다속성 동시공개** 까지 mdoc 패리티 이상. 발급자 서명 +
>   홀더 KB + 3속성을 한 ZK proof로. `pnpm run demo:sdjwt-zk`. (설계: `playground/SDJWT_PLAN.md`)

⚠️ longfellow는 mdoc를 **발급하지 않습니다.** 이미 ECDSA 서명된 mdoc에 대해
**present/verify만** 합니다(발급은 별도 라이브러리 몫).

---

## 2. Node.js 플레이그라운드

`Node → longfellow_cli(C++) → longfellow C API` (CLI 서브프로세스 방식 —
네이티브 애드온/ABI 불필요, 가장 단순).

```bash
cd playground
pnpm run build:native     # 최초 1회: C++ 라이브러리 + CLI 빌드 (수 분)
pnpm run circuits         # 최초 1회: N별 회로 사전 생성·캐시 (N=1~4, 약 1분)
pnpm run demo             # issue → setup → present → verify → 변조거부 시연 (~2초)
pnpm run demo:multi       # 다속성(예제3) 동시 증명
```

단계별 실행 (상태는 `playground/artifacts/`에 저장):
```bash
pnpm run issue     # 예제 mdoc 로드 + ZK 회로 생성(캐시)
pnpm run present   # ZK 증명 생성 → artifacts/proof.bin
pnpm run verify    # 증명 검증 (ACCEPT면 exit 0)
```

> 플레이그라운드 상세는 [`playground/README.md`](playground/README.md) 참고.

### 동작 결과 (실측, 이 머신)

| 단계 | 결과 | 소요 |
|---|---|---|
| 회로 생성 `gencircuit` (1회/캐시) | hash `8d079211…` (레지스트리 일치) | ~14 s |
| **present (ZK 증명)** | proof ~360 KB | **~1.1 s** |
| **verify (정상)** | ACCEPT ✅ | **~0.6 s** |
| verify (변조 proof) | REJECT ✅ | — |
| verify (값 위조: f4≠f5) | REJECT ✅ | — |

→ 논문의 "모바일 ~1.2초" prove 성능과 일치하고, **변조·거짓 클레임이 모두 거부**됨을 확인.

---

## 3. 재현 방법 (처음부터)

```bash
cd /home/unknown/longfellow

# 1) 업스트림 클론 (git에서 제외되어 있으므로 직접 클론)
git clone --depth 1 https://github.com/google/longfellow-zk.git

# 2) 플레이그라운드 빌드 & 실행
cd playground
pnpm install        # (현재는 의존성 없음 — 향후 확장 대비)
pnpm run build:native
pnpm run demo
```

### ⚠️ 빌드 툴체인 주의 (비자명)

이 머신의 기본 `clang++`(Swift 툴체인)는 `libstdc++`를 찾지 못합니다.
`playground/native/build.sh`가 시스템 `clang-17`을
`--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11`로 감싸는 래퍼
(`.toolchain/clang++w`)를 자동 생성해 우회합니다. GCC 경로가 다르면
`GCC_INSTALL_DIR` 환경변수로 지정하세요.

의존성: `cmake`, `clang-17`, 시스템 `openssl`/`zstd`/`zlib` 개발 헤더, Node 18+.

---

## 4. 다음 단계 (확장 아이디어)

1. **실제 발급 연동** — `@auth0/mdl` 등으로 새 ECDSA mdoc를 발급한 뒤 longfellow로
   present/verify (CBOR/MSO/deviceKey/transcript 구조 호환성 검증 필요).
2. **다속성 증명** — `gencircuit --attrs 2+` + `--attr` 여러 개 (예제 index 3 = Sprind-Funke, `family_name` 등 포함).
3. **N-API 전환** — 프로세스 기동 오버헤드 제거(in-process 호출).
4. **HTTP API화** — `research-eudi-module`처럼 NestJS 엔드포인트(`/present`, `/verify`) 노출.

---

## 5. 참고 자료

- 원논문 *Anonymous credentials from ECDSA* (Frigo & shelat, Google): https://eprint.iacr.org/2024/2010
- *Ligero* (커밋먼트/논증 토대): https://eprint.iacr.org/2022/1608
- IETF draft: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
- 공식 문서(보안감사 포함): https://google.github.io/longfellow-zk/
- 자세한 목록: [`references/README.md`](references/README.md)
