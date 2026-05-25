# 익명 1인1표 투표 — 시나리오 보고서

> 대상: `playground/` — **블라인드 가명 nullifier**(mdoc·SD-JWT-VC 양쪽) 위에 구축한 end-to-end 투표 시나리오.
> 위치: `/home/unknown/longfellow/playground`
> 작성일: 2026-05-25 · 상태: 동작 데모
> 기반: 블라인드 nullifier 작업 위에 올림 — [`mdoc-nullifier_analysis-report-ko.md`](mdoc-nullifier_analysis-report-ko.md) §9, [`sd-jwt-nullifier_analysis-report-ko.md`](sd-jwt-nullifier_analysis-report-ko.md) §10. CI/DI·nullifier 구성과 블라인드 발급 soundness는 거기에 있고, 이 보고서는 그걸 **사용하는 시나리오**를 다룸.

---

## 1. 시나리오

유권자가 투표소에 가서 **익명으로** 자격을 증명한다 — **성인**이고 **이 지역 거주자**이며 **이번 선거에서 아직 투표 안 함** — 그리고 투표한다. 구체적으로, 월렛이 단일 영지식 증명으로 보인다:

- `age_over_18 == true` — 자격(성인)
- `resident_city == "Seoul"` — 자격(이 지역 거주)
- 이 선거 scope의 **DI nullifier** = `SHA256(secret ‖ SHA256(election_id))`

그 외엔 아무것도 안 드러냄 — 이름·생년월일·발급자 서명·secret·다른 claim 전부 숨김. 선거관리위원회(EC)는 본 nullifier 집합을 관리: **첫** 투표는 nullifier 등록 후 집계, **두 번째** 투표는 **같은** nullifier가 나와 거부 → **1인 1표**, 신원은 끝까지 노출 안 됨.

고전적 자격증명 검사보다 강한 두 성질:
- **블라인드 발급** — 발급자가 `C = SHA256(secret ‖ blind)`만 커밋하고 *secret을 학습 안 함* → 발급자/EC조차 어떤 scope의 nullifier도 계산 불가 (CI/DI와 달리 중앙 비익명화 없음).
- **선거별 scope** — 다른 선거는 다른 nullifier context → 유권자는 **선거 간 비연결**.

---

## 2. 요구사항 → 어디서 강제되나

시나리오엔 5개 요구가 있고, 일부는 **영지식(회로)**, 일부는 평범한 **앱 로직**이다 — 이 구분이 핵심.

| # | 요구사항 | 강제 주체 | 영지식? |
|---|---|---|:---:|
| A | 성인 (`age_over_18==true`) | 자격증명 속성, 진본 증명 | ✅ 회로 |
| B | 거주지 (`resident_city=="Seoul"`) | 자격증명 속성, 진본 증명 | ✅ 회로 |
| C | 선거 scope DI nullifier | `SHA(secret ‖ SHA(election_id))` | ✅ 회로 |
| D | 1인 1표 (재투표 거부) | EC의 **본 nullifier 집합** | ❌ 앱 |
| E | 선관위만 요청 가능 (3자 거부) | 월렛이 **서명된 요청** 검증 (RP 인증) | ❌ 앱 |

> A/B/C가 ZK — 월렛이 *증명*하고 EC는 위조·비익명화 불가. D/E는 OID4VP와 똑같은 평범한 앱 로직: 검증자가 상태(본 nullifier)를 유지하고, 서명된 요청으로 월렛에 자기 신원을 인증. ZK는 만능 접착제가 아니다 — *무엇이 공개되는지*를 보안하고, *누가 요청하는지*·*이미 무엇을 봤는지*는 주변 프로토콜이 보안한다.

---

## 3. 플로우

```
발급자 ──(블라인드)──▶ 월렛          EC 보유: 본-nullifier 집합 + 서명키
   C 커밋, secret은                       │
   끝내 모름                              │ 1) 서명된 제시요청 (nonce, 지역, election_id)
                                          ▼
   월렛 ── 요청 서명을 신뢰리스트(=EC 키)로 검증 ──▶ OK? 아니면 REJECT
        │
        │ 2) ZK 제시: age_over_18=true + resident_city=Seoul + nullifier(election)
        ▼
   EC ── 증명 검증 ──▶ 진본? ── nullifier ∈ 본것? ──▶ REJECT (재투표)
                                     └ 신규 ─▶ 등록 + 집계
```

---

## 4. 두 구현

| | mdoc (`scenario-voting.js`) | SD-JWT-VC (`scenario-voting-sdjwt.js`) |
|---|---|---|
| 자격증명 | 실제 ISO 18013-5 mdoc (`mdoc_null_blind`) | 실제 SD-JWT-VC (`sdjwt_null_blind`) |
| 자격 속성 | `RequestedAttribute` (age_over_18, resident_city) | 공개 claim (age_over_18, resident_city) |
| 값 처리 | **단언(assert)** — 검증자가 값 제시 (§5) | **공개(disclose)** — 홀더가 값 공개 (§5) |
| 제시 결속 | session transcript | **KB-JWT nonce/aud를 회로 안에서 검증** |
| nullifier | `SHA(secret ‖ SHA(election))`, GF(2¹²⁸) 해시 회로 | 동일 |
| 실측 (2속성) | prove ≈ 1.0초, verify ≈ 0.4초, 번들 ≈ 344KB | prove ≈ 2.0초, verify ≈ 0.75초, 번들 ≈ 391KB |

둘 다 기존 블라인드 nullifier 회로를 **무변경 재사용**; 시나리오는 **앱 로직**(본-nullifier 집합, `jose` 서명 요청)만 추가. mdoc 바이너리는 콤마구분 다속성 공개를 추가(회로는 원래 N속성 지원), SD-JWT 바이너리는 이미 다중 claim 지원.

---

## 5. 값 처리: 단언(assert) vs 공개(disclose)

두 데모는 속성 *값*(예: 도시)을 검사하는 방식이 달라 보인다. 이는 **포맷의 한계가 아니라 스타일 선택**이다 — 값이 어느 쪽이든 회로의 **공개 입력**이라, 두 스타일 모두 양쪽 포맷에서 가능 (어느 쪽도 값을 회로에 박지 않음; 아래 캐싱 참고).

| | **① 단언/매치** (mdoc 데모) | **② 공개** (SD-JWT 데모) |
|---|---|---|
| 값을 누가 제공 | **검증자** ("== Seoul인가?") | **홀더** (자기 값 공개) |
| 회로가 증명 | `자격증명값 == 검증자값` | `공개값이 발급자-진본` |
| 결과 | ACCEPT(일치) / **proof 실패**(불일치) | ACCEPT + 검증자가 값 **읽음** |
| 불일치 시 | proof만 실패 — 실제 값 안 드러남 | 실제 값 드러남 |
| 정책 판단 | 회로 안 | 검증자 앱 |

데모가 다른 이유: mdoc은 longfellow 공개 API `RequestedAttribute{id, cbor_value}`가 단언식, SD-JWT 데모는 SD-JWT 본연의 선택공개라 공개식. 어느 포맷이든 양쪽 다 가능.

**영향** (실질 차이는 이것뿐):
- **불일치 시 프라이버시.** 단언은 "테스트값 ≠"만 드러내고, 공개는 실제 값을 드러냄. 순수 yes/no 검사면 단언이 덜 새어나감.
- **유연성.** 공개는 검증자가 드러난 값에 *임의 정책*(범위·집합 멤버십)을 회로 변경 없이 적용 가능; 단언은 특정 값 하나를 테스트.
- **신뢰 경계.** 단언은 요구를 proof에 박음(검증자 버그여도 틀린 값 수용 불가); 공개는 검증자 정책 코드가 정확해야 함.
- **캐싱/성능 — 동일.** 둘 다 값이 공개 입력 → 값 바꿔도(Seoul→Busan, true→false) **회로 재빌드 없음**; 회로는 *속성 개수*당 캐시, 값당 아님. (실측: Seoul·Busan 제시가 같은 캐시를 ~0.25초에 로드.)

> 주소 위조는 양쪽 다 차단: mdoc은 Seoul 자격증명에 `Busan`을 요청하면 proof 불가(REJECT); SD-JWT는 홀더가 진본 `Seoul`만 공개 가능 → Busan 지역 검증자 정책이 거부. 홀더는 발급받지 않은 도시를 증명 못 함.

---

## 6. 보안 성질 (단계별)

| 단계 | 막는 것 | 메커니즘 |
|---|---|---|
| 자격 (A/B) | 부적격 유권자(미성년/비거주) | 발급자 서명(서명된 다이제스트 집합 멤버십)으로 속성 진본성 |
| nullifier (C) | — | (secret, 선거)당 결정적; 신원 숨김 |
| 재투표 (D) | 두 번 투표 | 같은 secret ⇒ 같은 nullifier ⇒ EC 집합이 두 번째 거부 |
| 주소 위조 | 다른 지역 주장 | 값이 자격증명에 결속 (단언 실패 / 공개는 진본만) |
| 제3자 (E) | 데이터브로커의 nullifier 수집 | 월렛이 신뢰된 요청자(EC) 서명 요청만 응답 |
| 발급자 추적 | EC/발급자의 유권자 연결 | **블라인드 발급** — 발급자가 secret 못 봐서 nullifier 계산 불가 |
| 선거 간 연결 | 유권자를 선거 간 상관 | 선거별 nullifier scope (다른 context ⇒ 다른·비연결 nullifier) |
| 재생 (SD-JWT) | 캡처한 제시 재생 | KB-JWT가 EC nonce/aud에 결속, 회로 안에서 검증 |

---

## 7. 한계 / 데모 단순화

- **재투표 집합·요청 인증은 앱 로직**(의도된 설계), ZK 아님. 실배포는 영속 nullifier 저장소 + 제대로 된 RP 인증/OID4VP 서명요청 사용; 데모는 in-process(`Set`, 단일 신뢰 EC 키, `jose`)로 모델링.
- **발급-시점 well-formedness**(발급자가 `C`가 단일·올바른 커밋먼트임을 홀더에게 증명 요구)는 생략 — 블라인드 nullifier 보고서(mdoc §9.5 / SD-JWT §10.6)와 동일. 제시 ZK는 완전.
- **SD-JWT KB nonce는 발급 시 구움**(`KB_NONCE`/`KB_AUD`); 실플로우는 제시마다 검증자 fresh nonce로 KB-JWT 재생성. 시나리오는 EC nonce로 발급해 회로 결속이 유의미하게 함.
- **Sybil = 1인 1자격증명**은 여전히 발급자 정책(실신원당 `pseudonym_commitment` 하나)에 의존 — 회로로 강제 불가(CI/DI 동일).
- **발급자 공개키는 여전히 노출**(연결성 아닌 유추 문제 — 기반 보고서 프라이버시 절 참고).

---

## 8. 파일 / 실행

| 파일 | 역할 |
|---|---|
| `src/scenario-voting.js` | `pnpm run scenario:voting` — mdoc 시나리오 (단언식 값) |
| `src/scenario-voting-sdjwt.js` | `pnpm run scenario:voting-sdjwt` — SD-JWT-VC 시나리오 (공개식 + KB nonce/aud) |
| `native/mdoc_null_blind.cc` | 블라인드 mdoc nullifier 회로 (다속성) |
| `native/sdjwt_null_blind.cc` | 블라인드 SD-JWT nullifier 회로 (공개 claim 값 출력) |
| `tools/gen-mdoc-blind.mjs` / `tools/gen-sdjwt-blind.mjs` | 블라인드 발급기 (C 커밋; `resident_city` 추가) |

```bash
cd playground
pnpm run build:native          # 1회
pnpm run scenario:voting       # mdoc:    발급 → 요청 → 투표 → 재투표/위조/3자 거부
pnpm run scenario:voting-sdjwt # SD-JWT:  동일 + 회로 안 KB nonce/aud 결속
```

각 시나리오: [1] 블라인드 발급 → [2] EC 서명 제시요청, 월렛 검증 → [3] 첫 투표 ACCEPT(자격 + nullifier 등록) → [4] 재투표 REJECT(같은 nullifier) → [5] 타 지역 REJECT(값이 자격증명에 결속) → [6] 제3자 요청 REJECT(월렛 RP 인증).

---

## 9. 결론

이 시나리오는 블라인드 가명 nullifier가 실제로 일하는 모습을 보인다: 암호학적 자격(성인+지역) + 선거 간 비연결 + 어떤 중앙(발급자조차)도 유권자를 추적 못 하는 **익명 1인1표**. 또한 **ZK 계층**(자격·nullifier)과 **앱 계층**(재투표 집합·요청 인증)을 깔끔히 분리하고, 두 자격증명 포맷 모두에 적용되는 **단언 vs 공개** 값 처리 선택을 드러낸다.
