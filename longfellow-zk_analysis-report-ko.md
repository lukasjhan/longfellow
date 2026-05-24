# Longfellow-ZK 소스코드 분석 보고서

> 분석 대상: `google/longfellow-zk` (커밋 `c849531`, 2026-05-23 기준 main)
> 분석 위치: `/home/unknown/longfellow/longfellow-zk`
> 작성일: 2026-05-23

---

## 1. 한눈에 보는 요약 (TL;DR)

**Longfellow**는 구글이 공개한, **기존 신원 표준(ISO mdoc/mDL, JWT, W3C VC)을 바꾸지 않고도 영지식증명(ZK)을 입히기 위한 C++ 라이브러리**다. 핵심 난제는 "이미 전 세계에 배포된 **ECDSA 서명**된 자격증명을, 서명을 노출하지 않고 ZK로 증명하는 것"이며, 이를 위해 두 개의 검증된 빌딩블록을 조합한다.

- **Sumcheck 프로토콜**(영지식 변형) — 산술회로 `C(x,w)=0` 의 올바른 계산을 증명하는 대화형 증명(IP)
- **Ligero 논증 시스템** — 신뢰 셋업(trusted setup)이 필요 없고, 충돌저항 해시(SHA-256)만 가정하는 커밋먼트 + ZK 논증

전체 시스템은 **신뢰 셋업이 없고**, **충돌저항 해시 외의 복잡한 가정이 없으며**, ECDSA 증명 ~60ms / mdoc 전체 제시 플로우 ~1.2초(모바일) 성능을 목표로 한다.

- 이름 유래: 구글 케임브리지 오피스 앞 **Longfellow Bridge**
- 논문: [Anonymous credentials from ECDSA (ePrint 2024/2010)](https://eprint.iacr.org/2024/2010), Matteo Frigo & abhi shelat (Google)
- 표준화: [IETF draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)

---

## 2. 해결하려는 문제

기존 익명 자격증명(anonymous credential) 스킴(BBS+, CL 서명 등)은 **새로운 암호 가정과 새로운 서명 방식**을 요구한다. 즉, 발급자(정부·기관) 인프라를 전부 바꿔야 한다. 현실의 모바일 운전면허증(mDL), 전자여권 등은 거의 모두 **ECDSA(P-256)** 로 서명되어 있으므로, 이 레거시를 그대로 둔 채 프라이버시를 추가하는 것이 관건이다.

Longfellow의 접근: **"ECDSA 서명 검증 알고리즘 자체"를 산술회로로 표현**하고, "나는 이 공개키로 검증되는 유효한 서명을 알고 있고, 그 안의 특정 속성(예: age≥18)이 성립한다"는 것을 ZK로 증명한다. 검증자는 서명·이름·생년월일을 보지 못하고 **"증명이 통과했다"** 는 사실만 얻는다. 또한 매번 새로운 증명이 생성되어 추적(linkability)도 방지된다.

---

## 3. 전체 아키텍처

### 3.1 5단계 프로토콜 (개념)

`docs/specs/libzk.md:328` 의 Overview 절이 전체 흐름을 정의한다.

1. **커밋**: 프루버가 모든 witness 값(= 사적 입력 + 일회용 패드)에 커밋한다.
2. **암호화된 sumcheck**: 프루버가 witness로 sumcheck를 실행하되, 결과 다항식/클레임을 **일회용 패드로 한 원소씩 빼서(암호화)** 검증자에게 보낸다. 검증자는 패드를 모르므로 직접 검증 불가.
3. **제약 생성**: 프루버·검증자 양쪽이 공개 입력 + 암호화된 증명으로부터 **선형/이차 제약(linear/quadratic constraints)** 들을 만든다. "이 제약들이 만족되면 sumcheck 검증자가 accept했을 것"이라는 형태.
4. **Ligero 증명**: 프루버가 커밋먼트와 witness로 3단계 제약이 만족됨을 증명한다.
5. **검증**: 검증자가 4단계 증명 + 3단계 제약으로 최종 검증한다.

> 2~3단계를 "sumcheck", 4~5단계를 "commitment scheme"이라 부른다. 커밋먼트는 Ligero 대신 다른 것으로 교체 가능하도록 모듈화되어 있다.

이 설계의 핵심 통찰(`lib/zk/zk_prover.h:38`):
> sumcheck **검증자**는 본질적으로 "degree-2/3 다항식의 평가 확인 + 레이어당 곱셈 1회"만 하므로, 이 단순한 검증 로직을 Ligero가 증명하는 제약으로 환원할 수 있다. (Hyrax 논문의 관찰과 유사하나, Hyrax는 타원곡선 기반, 여기서는 Ligero 사용.)

### 3.2 디렉토리 구조 (`lib/`)

| 디렉토리 | 역할 |
|---|---|
| `algebra/` | 유한체 산술 — `Fp256`(P-256 base field), `f_128`=GF(2^128), FFT/NTT, CRT, 보간, convolution |
| `gf2k/` | GF(2^128) 전용 구현 (additive FFT 기반 extend) |
| `ec/` | 타원곡선 — `p256.h`, `p256k1.h` (P-256, secp256k1) |
| `sumcheck/` | 레이어드 회로 sumcheck 프루버/검증자, quad 표현 |
| `ligero/` | Ligero 커밋·증명·검증, 파라미터 |
| `merkle/` | Ligero 커밋먼트의 머클트리 (배치 inclusion proof) |
| `zk/` | 위 둘을 묶는 상위 ZK 래퍼 (`ZkProver`, `ZkVerifier`, `ZkProof`) |
| `circuits/` | 회로 빌딩블록 (ECDSA, SHA-256, CBOR, MAC, mdoc, 컴파일러, logic) |
| `random/` | Fiat-Shamir transcript(랜덤 오라클), 보안 RNG |
| `arrays/` | `Dense`/`DenseFiller` 등 witness 컨테이너 |
| `cbor/`, `proto/`, `util/` | CBOR 직렬화, proto, 로깅·패닉 유틸 |

---

## 4. 핵심 동작 원리 (암호 계층)

### 4.1 Sumcheck (영지식 변형) — `docs/specs/sumcheck.md`, `lib/sumcheck/`

**레이어드 회로 모델**: 회로는 `NL`개 레이어로 구성되고, 레이어 `j`는 입력 와이어 `V[j+1]`로부터 출력 와이어 `V[j]`를 계산한다. `V[0]`이 최종 출력이며, **모든 출력 와이어가 0이면 정리(theorem)가 참**으로 간주된다 (`sumcheck.md:124`).

각 레이어의 계산은 **quad**(3차원 희소배열)로 표현된다:
```
V[j][g] = Σ_{l,r} Q[j][g,l,r] · V[j+1][l] · V[j+1][r]
```
즉 모든 게이트가 "입력 와이어 두 개의 곱들에 상수를 곱해 더한" 형태 (`sumcheck.md:130`).

**In-circuit assertion 최적화** (`sumcheck.md:149`): 출력=0 검사를 출력 레이어까지 복사하면 오버헤드가 크므로, 레이어마다 `Q`(일반 계산)와 `Z`(0이어야 하는 이차식) 두 quad를 두고, 랜덤 `beta`로 `QZ = Q + beta·Z` 결합해 한 번에 검사한다. 두 quad는 disjoint하고 `Z`는 binary라서 `(g,l,r,v)` 4-튜플 하나로 압축 표현 가능(`v=0`이면 Z, `v≠0`이면 Q).

**암호화/지연검증** (`sumcheck.md:224`): sumcheck가 만드는 다항식·클레임을 검증자에게 평문으로 주지 않고, **일회용 패드를 빼서** 보낸다. 검증자는 직접 검증하는 대신, 사적 입력·패드 값에 대한 **선형/이차 제약**으로 변환해 Ligero로 지연 검증한다.

**다항식 표현 최적화** (`sumcheck.md:198`): 모든 라운드 다항식은 **차수 2**이며, 세 점 `P0=0, P1=1, P2`의 평가로 표현한다. `p(P0)+p(P1)=직전 클레임`이라는 항등식 때문에 **`p(P0)`와 `p(P2)`만 전송**하고 `p(P1)`은 재구성한다. → 코드에서 `fill_pad`가 `k!=1`일 때만 패드를 생성하는 "P(1) optimization"으로 나타난다 (`lib/zk/zk_prover.h:156`, `:168`).

> P2 선택: 표수>2 체에서는 `P2=2`, GF(2^128)에서는 `inj(2)` (`sumcheck.md:205`).

### 4.2 Ligero 커밋먼트 & 논증 — `docs/specs/ligero.md`, `lib/ligero/`

Ligero[Ames-Hazay-Ishai-Venkitasubramaniam, ePrint 2022/1608]는 **신뢰 셋업 없는** sublinear 논증이다. Longfellow는 임의 회로 증명용이 아니라, **위 sumcheck 검증자가 만든 선형/이차 제약을 직접 증명**하는 용도로 사용한다.

**커밋먼트 구조** (`ligero.md:180`):
- witness 벡터 `W`를 **2D tableau 행렬 `T[NROW][NCOL]`** 로 배치한다. 각 행은 `[랜덤 패드 NREQ | witness값 WR | 다항식 평가 ...]`. 행에 랜덤 패드를 섞어 **영지식성**을 얻는다.
- 처음 3행은 ZK용 랜덤 행(저차 테스트용, 선형 테스트용, 이차 테스트용).
- 각 행에 Reed-Solomon `extend`(저차 인코딩)를 적용.
- **머클트리는 행이 아니라 "열(column)"에 대해** 구성한다(`ligero.md:234`). 커밋먼트 = 머클루트.

**서브필드 최적화** (`ligero.md:220`): 한 행의 witness가 모두 서브필드(GF(2^16))에 속하면 랜덤도 서브필드에서 뽑아 직렬화 크기를 16비트로 줄인다. → `ZkProver::commit`의 `subfield_boundary` 처리(`lib/zk/zk_prover.h:85`).

**증명 3종** (`ligero.md:314`):
1. **저차 테스트(low-degree test)**: 검증자 챌린지 `u`로 행들의 선형결합을 받아 RS 코드워드인지 확인.
2. **선형 제약 테스트(dot proof)**: `A·W = b` 형태를, 랜덤결합 `alpha_l`로 한 방에 확인.
3. **이차 제약 테스트(quadratic proof)**: `W[x]·W[y]=W[z]` 제약들을, witness를 복사한 `Qx,Qy,Qz` 행으로 만들어 "복사가 맞다"는 선형 제약 + "Qz=Qx⊗Qy"라는 곱 확인으로 환원.

마지막에 검증자가 `NREQ`개 열을 무작위로 열어(open) 위 모든 메시지와의 정합성을 확인한다. **머클 inclusion proof는 배치 압축**(형제노드 중복 제거)으로 보낸다 (`ligero.md:46`).

기본 파라미터(`lib/circuits/mdoc/mdoc_zk.h:33`):
- v6 이하: `rate=4`, `NREQ=128` → 86비트+ 통계적 보안
- v7 이상: `rate=7`, `NREQ=132` → ~109비트 통계적 보안

### 4.3 Fiat-Shamir (비대화화) — `docs/specs/libzk.md:136`, `lib/random/`

대화형 IP를 **단일 메시지**로 만들기 위해 Fiat-Shamir 변환을 쓴다. transcript 객체가 충돌저항 해시 `H`(SHA-256)로 프루버 메시지를 누적하고, 거기서 검증자 챌린지를 파생한다. 메시지마다 **타입·길이**를 함께 넣어 각 쿼리가 고유 transcript에 매핑되게 한다(`libzk.md:143`). 또한 랜덤 오라클의 회로 깊이/게이트 수를 대상 회로 `C`보다 크게 잡아 correlation-intractability 공격을 회피하는 베스트프랙티스를 따른다(`libzk.md:141`).

### 4.4 유한체 & FFT — `lib/algebra/`, `lib/gf2k/`

- **`Fp256Base`**: P-256 base field (서명/ECDSA 회로용).
- **`f_128` = GF(2^128)**: `GF(2)[x]/(x^128+x^7+x^2+x+1)`, `x`가 곱셈군 생성원 (해시/SHA 회로용). 서브필드 GF(2^16)로 직렬화 절감(`libzk.md:107`).
- **extend (RS 인코딩)**: 소수체에서는 보간/NTT/Nussbaumer convolution; GF(2^k)에서는 **Lin et al.의 additive FFT**(novel polynomial basis)로 효율 구현 (`libzk.md:96`).
- `f2_p256` + `FftExtConvolutionFactory`: P-256 위 RS 팩토리를 위한 확장체/FFT (`mdoc_zk.cc:474`).

---

## 5. 회로 계층 (`lib/circuits/`)

ZK가 실제로 증명하는 "정리"는 모두 산술회로다. Longfellow는 mdoc 검증에 필요한 모든 연산을 회로로 구현했다.

### 5.1 회로 컴파일러 — `circuits/compiler/`
고수준 산술 연산을 sumcheck 호환 **QuadCircuit**으로 컴파일한다(`compiler.h`의 `QuadCircuit`). 각 게이트는 `Σ(w_left·w_right·const)` 형태. 최적화: 상수 폴딩, 공통부분식 제거(CSE), 선형항 최적화, 레이어 깊이 최소화 스케줄링. 출력 메타로 `depth/nwires/nquad_terms` 등을 보고.

### 5.2 논리·비트 연산 — `circuits/logic/`
필드 위 비트/벡터 연산을 추상화(`logic.h`의 `Logic`). 핵심 타입:
- `EltW`(필드원소 와이어), `BitW`(비트 와이어, `c0 + c1·x` 변환기저로 XOR 등을 효율화), `bitvec<N>`(= `v8/v32/v64/v128/v256`).
- 연산: `add/sub/mul/axpy`, 비트논리 `land/lor/lxor/lnot`, 시프트/로테이트 `shl/shr/ror/rol`, 벡터 `vappend/vextract/veq/vlt`(범위검사).
- `bit_plucker.h`(필드원소→비트 추출/패킹), `bit_adder.h`(mod 2^32 덧셈, SHA용), `counter.h`(CBOR 누적 스캔).

### 5.3 ECDSA 검증 회로 — `circuits/ecdsa/`
P-256 ECDSA 검증을 **3중 스칼라곱** 형태로 구현(`verify_circuit.h`의 `VerifyCircuit`, `verify_witness.h`의 `VerifyWitness3`). 검증식 `g·e + pk·r + R·(-s) = 항등원` 형태로 묶고:
- **사전계산 테이블**: `{g, pk, R}`의 8가지 조합점을 미리 두고 스칼라 3비트씩으로 점 하나를 선택.
- **중간점 witness 제공**: 각 반복 중간 결과를 witness로 줘 회로 깊이 축소.
- **완전 덧셈 공식**(예외 없는 Weierstrass 덧셈).
- `r,s ≠ 0` 및 `r,s < order` 범위 검사.

### 5.4 SHA-256 회로 — `circuits/sha/`
SHA-256을 "평탄화"한 산술회로(`flatsha256_circuit.h`의 `FlatSHA256Circuit`). 64라운드 전부를 회로로 펼치되, 메시지 스케줄 `W[16..63]`과 각 라운드 상태를 witness로 받아 검증. 라운드 함수(`T1,T2`, Ch/Maj/Σ)와 mod 2^32 덧셈(`BitAdder`)을 회로화. 비트 패킹으로 입력 크기↓(깊이↑) 트레이드오프.

### 5.5 CBOR 파서 회로 — `circuits/cbor_parser/`, `cbor_parser_v2/`
mdoc는 **CBOR**로 인코딩되므로, 회로 안에서 CBOR를 파싱해 "특정 속성이 어디 있는지/값이 무엇인지"를 입증한다. v1은 segmented scan(누적길이) 기반, **v2는 `UnaryPlucker` 기반으로 불필요한 스캔을 제거**해 효율 개선. 각 바이트 위치에서 헤더(타입·길이)를 해석하고 요소 경계를 추적한다.

### 5.6 MAC 회로 — `circuits/mac/`
GF(2^128) 위 256비트 메시지의 MAC을 검증(`mac_circuit.h`). 형식 `mac[i] = (a_p[i] + a_v)·x[i]`. `a_p`는 프루버가 커밋한 키, **`a_v`는 검증자 랜덤**. 위조 성공확률 ≤ 2^-128. 용도는 **두 회로(서명·해시)를 잇는 접착제**(아래 6장).

### 5.7 mdoc 통합 회로 — `circuits/mdoc/`
위 블록들을 묶어 mdoc 전체 검증을 회로화한다.
- `mdoc_signature.h`: 발급자(MSO)·디바이스 ECDSA 서명 검증.
- `mdoc_hash.h`: mdoc 해시 계산 + 요청 속성의 해시가 MSO의 attribute digest 맵에 존재하는지 확인. **age_over_18** 류 증명이 여기서 일어난다.
- `mdoc_witness.h`(`ParsedMdoc`, `FullAttribute`): mdoc 파싱·witness 채우기.
- `zk_spec.cc`: 지원 회로 버전 레지스트리(시스템명, 회로해시, 속성개수, rate/nreq 파라미터).
- `circuit_maker.cc` / `mdoc_generate_circuit.cc`: 회로를 한 번 생성해 캐시(압축 바이트)로 저장 → 프루버/검증자가 재사용.

---

## 6. 핵심 설계: "두 개의 회로 + MAC 접착" (구현 분석)

`lib/circuits/mdoc/mdoc_zk.cc`의 `run_mdoc_prover`(`:394`)/`run_mdoc_verifier`(`:538`)를 보면, **서로 다른 두 체 위에서 두 개의 독립 회로가 동시에 증명**되고 MAC으로 묶이는 것이 가장 중요한 아키텍처다.

| | 서명 회로 (signature) | 해시 회로 (hash) |
|---|---|---|
| 체(field) | `Fp256Base` (P-256) | `f_128` (GF(2^128)) |
| 담당 | ECDSA 서명 검증 | SHA-256 해시 + CBOR 속성 추출 |
| 왜 분리? | ECDSA는 P-256 산술이 자연스러움 | 해시/비트연산은 GF(2^128)에서 훨씬 저렴 |

**왜 MAC이 필요한가?** 두 회로가 "같은 메시지 해시 `e`/같은 디바이스 키"를 다루는지 보장해야 한다. 한쪽은 Fp256, 다른쪽은 GF(2^128)이라 직접 같은 값을 공유할 수 없으므로, **공통값(common)에 대한 MAC을 양쪽 회로에 넣어 일치**시킨다.

구현 흐름(프루버, `mdoc_zk.cc:419`~`535`):
1. 캐시된 압축 회로 바이트를 `decompress` 후 `CircuitReader`로 `c_sig`(P256), `c_hash`(GF2_128) 두 회로 파싱.
2. `fill_witness`로 두 회로의 witness(`W_sig`, `W_hash`)를 채움 — mdoc 파싱·서명·해시·속성 추출 결과.
3. `ZkProver.commit`으로 두 회로의 witness+패드에 각각 커밋(`:487`,`:488`).
4. **커밋 후** transcript에서 검증자 챌린지 `av = generate_mac_key(tp)`를 뽑고, 공통값의 MAC `compute_macs`를 계산해 두 witness에 주입(`update_macs`, `:500`~`:504`). ← 두 회로를 잇는 단계.
5. `ZkProver.prove`로 hash·sig 각각 증명 생성(`:506`,`:511`).
6. 직렬화: `[6개 MAC] [hash proof] [sig proof]`(`:517`~`:524`).

검증자(`mdoc_zk.cc:608`~`690`)는 대칭적으로: MAC 6개 읽기 → 두 proof 파싱 → `recv_commitment` → 동일하게 `av` 파생 → `fill_public_inputs`로 공개입력 구성(여기서 pk, transcript, 요청속성, now, docType, MAC들이 들어감) → `hash_v.verify` && `sig_v.verify`. **둘 다 통과해야** 성공.

`ZkProver::prove`(`lib/zk/zk_prover.h:102`) 내부가 4장의 5단계를 그대로 수행:
- `eval_circuit`로 모든 와이어 계산 후 출력이 모두 0인지 확인(`:117`).
- `super::prove(...)`로 **암호화된 sumcheck** 실행.
- `verifier_constraints`로 선형/이차 제약 행렬 `A`, 벡터 `b` 생성(`:134`).
- `lp_->prove(...)`로 **Ligero 증명** 생성(`:144`).

---

## 7. 공개 C API (통합 지점)

`lib/circuits/mdoc/mdoc_zk.h`가 외부(예: Android gmscore, Google Wallet)에서 호출할 C 인터페이스를 정의:

- `generate_circuit(zk_spec, &cb, &clen)` — 속성 개수에 맞는 회로를 생성·압축. 한 번 만들어 캐시.
- `run_mdoc_prover(circuit, mdoc, pkx,pky, transcript, attrs[], now, &prf, &len, zk_spec)` — 증명 생성. `now`가 validFrom/validUntil 범위를 벗어나면 실패.
- `run_mdoc_verifier(circuit, pkx,pky, transcript, attrs[], now, proof, len, docType, zk_spec)` — 검증.
- `RequestedAttribute{namespace, id, cbor_value}` — 검증자가 요구하는 속성(값은 raw CBOR 바이트). 예: `{"age_over_18", ...}`, `{"family_name","Mustermann"}`, `{"birth_date","1971-09-01"(태그 0xD9 03EC 6A)}` (`mdoc_zk.h:150`).
- `ZkSpecStruct` — 시스템명("longfellow-libzk-v*")·회로해시·속성개수·버전·블록 파라미터를 묶은 버전 협상 구조체. 프루버/검증자가 사전에 버전을 협상(`mdoc_zk.h:114`). 현재 `kNumZkSpecs=12`개 스펙 하드코딩.

---

## 8. 성능 · 보안 고려사항

**성능**(논문/공식 자료 기준)
- ECDSA ZK 증명 생성: ~60ms
- ISO mdoc 제시 플로우 전체 ZK 증명: ~1.2초 (모바일, 자격증명 크기에 따라 변동)
- 회로 규모(예시): ECDSA 검증 회로 깊이 7 / 와이어 ~21k / 곱셈 ~14k, SHA-256 깊이 7 / 와이어 ~38k.

**보안 가정/특성**
- **신뢰 셋업 없음(no trusted setup), CRS 없음** — SNARK류 다수를 의도적으로 배제(`libzk.md:42`).
- **충돌저항 해시(SHA-256)만 가정** — 그 외 복잡한 가정 없음.
- Fiat-Shamir 건전성: round-by-round soundness + 랜덤오라클의 correlation-intractability에 의존(`libzk.md:139`).
- 통계적 보안: 파라미터(rate, NREQ)로 조절 — v7에서 ~109비트.
- **독립 보안감사 2건** 진행 중 (학계·업계 패널, 공식 문서 Reviews 페이지에 보고서 공개).

**버전 호환성**: 회로 게이트가 바뀌면 새 회로해시를 `zk_spec`에 추가하고, witness 레이아웃이 바뀌면 버전 분기 코드를 추가해야 함(`circuits/mdoc/README.md`).

---

## 9. 표준화 · 생태계

- **IETF**: CFRG에서 `draft-google-cfrg-libzk`("libzk: A C++ Library for Zero-Knowledge Proofs")로 사양화 중. `docs/specs/`가 그 워킹 파일.
- **유럽(EUDI)**: Dyne.org 재단이 유럽판(dyne/longfellow-zk)을 유지, EUDI ARF·연령확인 솔루션에 활용.
- **Google Wallet**: 정부발급 디지털 ID 기반 온라인 연령확인에 적용 계획.
- **OpenWallet Foundation Multipaz** 등 디지털 자격증명 SDK 생태계와 연동.

---

## 10. 빌드 · 실행 방법

의존성: `clang, cmake, openssl, zstd, googletest, googlebenchmark` (README 참조).

```bash
# 의존성 (Ubuntu/Debian)
sudo apt install -y clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev

# 빌드
CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release --install-prefix ${PWD}/install
cd clang-build-release && make -j 16 && ctest -j 16

# 벤치마크 예시
./algebra/fft_test --benchmark_filter='BM_*'
./circuits/sha/flatsha256_circuit_test --benchmark_filter=BM_ShaZK_fp2_128
```
> `.devcontainer`가 있어 GitHub Codespaces에서 즉시 빌드/벤치 가능(VM이라 성능치는 더 낮을 수 있음).

---

## 11. 관련 논문 · 자료 (저장 위치: `../references/`)

| 자료 | 설명 | 비고 |
|---|---|---|
| **Anonymous credentials from ECDSA** (ePrint 2024/2010) | Longfellow의 원논문. Frigo & shelat (Google). sumcheck+Ligero로 ECDSA ZK | `references/2024-2010_Anonymous-credentials-from-ECDSA.pdf` |
| **Ligero** (ePrint 2022/1608) | 신뢰 셋업 없는 sublinear 논증. 커밋먼트+ZK 토대 | `references/2022-1608_Ligero.pdf` |
| **Novel polynomial basis / Additive FFT** (arXiv 1404.3458) | GF(2^k) extend 효율 구현의 기반 (Lin, Chung, Han 2014) | `references/1404.3458_Additive-FFT_Lin-et-al.pdf` |
| IETF draft-google-cfrg-libzk | 사양 초안 | `longfellow-zk/docs/specs/` (로컬 워킹 카피) |
| Fiat-Shamir from Simpler Assumptions (ePrint 2018/1004) | FS 건전성 이론적 근거 | 링크 참조 |
| 공식 문서 | https://google.github.io/longfellow-zk/ | Reviews(보안감사) 포함 |

---

## 12. 결론

Longfellow-ZK는 "**레거시 ECDSA 신원 인프라를 그대로 두고 프라이버시(선택적 공개·비추적성)를 얹는다**"는 실용적 목표를, **신뢰 셋업 없이 해시 가정만으로** 달성하는 엔지니어링 결정체다. 설계의 정수는:

1. **모듈 분리** — (암호화된)sumcheck IP + Ligero 커밋먼트, 커밋먼트 교체 가능.
2. **검증자 환원** — 복잡한 ZK 대신 "sumcheck 검증자 로직"이라는 단순 제약을 Ligero로 증명.
3. **두 회로 + MAC** — ECDSA는 P-256 체, 해시/비트연산은 GF(2^128) 체로 각각 최적 구현하고 MAC으로 결속.
4. **회로 캐싱·버전협상** — 회로를 한 번 만들어 압축 캐시, `ZkSpec`로 버전 협상.

hopae가 다루는 SD-JWT VC / mdoc / 디지털 지갑 맥락에서, 이 라이브러리는 **"발급자 변경 없이 ZK 선택적 공개를 추가"** 하려는 시나리오의 직접적 참조 구현이다.
