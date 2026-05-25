# SD-JWT-VC 프라이버시 보존 폐기(Revocation) — 서명된 구간 비-멤버십 분석 보고서

> 대상: `playground/` — SD-JWT-VC 선택공개 ZK 증명에 **프라이버시 보존 폐기**를 추가하는 연구 확장. 홀더가 "내 크리덴셜이 폐기 안 됨"을 **어떤 크리덴셜인지 안 밝히고** 증명.
> 위치: `/home/unknown/longfellow/playground`
> 작성일: 2026-05-25 · 상태: 프로토타입, 동작 + soundness 감사 완료
> 기반: 이 문서는 SD-JWT-VC 크리덴셜 증명의 **확장**입니다. 공유 기반(`_sd` 멤버십, 전체 SD-JWT-VC 증명, 2회로 MAC split, §6 free-index 감사)은 [`sd-jwt-longfellow-zk_analysis-report-ko.md`](sd-jwt-longfellow-zk_analysis-report-ko.md), 하부 longfellow 회로는 [`longfellow-zk_analysis-report-ko.md`](longfellow-zk_analysis-report-ko.md) 참조. 방식은 longfellow 자체의 `MdocRevocationSpan`(`lib/circuits/tests/mdoc/mdoc_revocation.h`)을 SD-JWT-VC에 적용한 것. 이 문서는 폐기-특화 부분만 다룸.

---

## 1. 개요

크리덴셜 시스템엔 **폐기**(만료/탈취/철회)가 필요합니다. 단순 확인 — "이 크리덴셜 id가 폐기목록에 있나?" — 은 **id를 노출**해서, ZK 증명이 지키려는 unlinkability를 깨뜨립니다. 목표는 프라이버시 보존 버전:

> "내 (숨긴) 폐기 식별자 `rev_id`가 폐기목록에 **없다**"를, `rev_id`도 어떤 크리덴셜인지도 안 밝히고 ZK로 증명.

즉 **비-멤버십(non-membership)** 증명. **서명된 구간(signed-span)** 방식을 쓰며, 이는 머클트리·accumulator·신뢰셋업 없이 **목록 크기와 무관하게 상수 크기 증명**을 주고, 증명이 어차피 내는 ECDSA+SHA 가젯을 재활용합니다.

프로토타입: `native/sdjwt_revoc_split.cc`(2회로 split); 데모 `pnpm run demo:revocation`; 발급기 `tools/gen-sdjwt.mjs`가 `revocation_id` 추가.

## 2. 왜 서명된 구간이 ZK에 가장 유리한가

| 방식 | 회로 크기 | 증명 | 셋업 | 홀더 유지 |
|---|---|---|---|---|
| 곱(∏(list[i]−id)≠0) | **O(N)** ❌ | 상수 | 없음 | 없음 |
| **서명된 구간**(이 방식) | **상수** ✅ | 상수 | 없음 | 새 span만 받음 |
| 머클 / sparse 머클 | O(depth) | 상수 | 없음 | 경로 갱신 ⚠️ |
| RSA / 페어링 accumulator | 매우 비쌈 ❌ | 상수 | RSA 필요 | witness 갱신 |
| epoch / 단명 | 0(가젯 없음) ✅✅ | — | 없음 | 자주 재발급 |

*실제* 폐기엔 서명된 구간이 최적: 베이스 증명 대비 한계비용이 **ECDSA 검증 1 + 2블록 SHA 1 + 비교 2개**뿐이고, 전부 기존 2회로 split에 맞음. (epoch/단명은 회로 비용 0이지만 폐기 지연을 트레이드오프 — 둘은 잘 조합됨.)

## 3. 구성

폐기기관(**CRA**)이 폐기 식별자 정렬집합 `R = {r_1 < r_2 < … < r_n}`(+ 센티넬 `0`, `2²⁵⁶−1`)을 유지. 인접쌍마다 **빈 구간(span)**을 서명:

```
span = epoch ‖ l ‖ r        (8B epoch ‖ 32B l ‖ 32B r, little-endian)
e_span = SHA256(span)        CRA의 ECDSA 키로 서명
```

폐기 안 된 `rev_id`는 정확히 한 구간에 들어감. 홀더는 자기 `rev_id`를 덮는 span을 제시하고 ZK로 증명:

```
1. e_span이 CRA의 유효 ECDSA 서명 대상         (진짜 span)
2. e_span == SHA256(epoch ‖ l ‖ r)            (l, r을 서명에 결속)
3. epoch == 검증자의 현재 epoch                (freshness)
4. l < rev_id < r                              (두 인접 폐기 id 사이 ⇒ 폐기 안 됨)
```

**`rev_id`가 뭔가?** 발급자가 크리덴셜마다 `revocation_id`를 `_sd` 클레임으로 박음(미공개). 그 **`_sd` 다이제스트** — `SHA256(disclosure)`를 big-endian 256비트 정수로 — 가 `rev_id`. 우아한 점: 다이제스트가 이미 256비트 숫자라 **회로 내 hex 디코드 불필요**, **발급자 커밋**(홀더가 못 고름), 숨김 유지(`_sd` 항목은 멤버십으로 증명, 노출 안 됨).

- **공개**: CRA 공개키 `(craPkX, craPkY)`, 현재 `epoch`.
- **숨김(witness)**: `rev_id`, span `(l, r)`, CRA 서명.

발급자 커밋 체인(위조/Sybil 저항, §6-S5): `SHA(revocation_id disclosure) = rev_id ∈ _sd ⊂ 서명 payload`, `SHA(payload) = e`, `e`는 발급자 ECDSA로 검증(서명회로에 MAC 결속). → `rev_id`는 발급자가 실제 서명한 크리덴셜에 묶이고, `","revocation_id","` 앵커가 *그 특정 클레임*임을 강제(다른 `_sd` 항목 대입 불가).

## 4. 아키텍처 & 성능

split은 베이스 증명을 따라가며, span의 ECDSA는 Fp256 회로, SHA+비교는 저렴한 GF(2¹²⁸) 회로:

- **sig 회로(Fp256)**: 발급자 ECDSA + 홀더 KB ECDSA + **CRA ECDSA(`e_span`)**.
- **hash 회로(GF(2¹²⁸))**: 전체 SD-JWT-VC 증명 + revocation 블록 — `revocation_id` `_sd` 멤버십(→ `rev_id`), `SHA(epoch‖l‖r)`, epoch 핀, `l < rev_id < r`.
- **MAC 링크 3 → 4값 확장**: `e, dpkx, dpky, e_span`. 공유 키 절반 `a_p[8]`, `a_v`는 commit 후 transcript에서. 8개 mac이 양쪽 회로의 공개입력이라 prover가 sig 회로의 `e_span`을 hash 회로의 SHA 결과와 다르게 못 씀. 번들 = `[8 macs][hash proof][sig proof]`.

| 지표 | 값(1속성 공개, 실제 fixture) |
|---|---|
| prove | ~2.0 s |
| verify | ~0.8 s |
| 번들 | ~403 KB |
| hash 회로 ninputs | ~180.9 k |

증명 크기·회로는 **폐기목록 크기와 무관** — 홀더는 항상 span 하나만 들고 다님.

## 5. 속성 (`demo:revocation`으로 검증)

- **폐기 안 됨** → ACCEPT (CRA 서명 gap이 `rev_id`를 brackets).
- **폐기됨** → REJECT — `rev_id ∈ R`이면 gap 끝점이라 strictly 포함하는 서명 gap 없음; `l < rev_id < r` 불가.
- **위조 상태**(CRA 아닌 키로 서명한 span) → REJECT.
- **stale span**(이전 epoch 서명) → REJECT.
- **링크 변조**(MAC 비트 플립) → 양쪽 회로 REJECT.

## 6. Soundness 감사

위협모델: 악성 prover가 (S1) 폐기됐는데 통과, (S2) 폐기상태 위조, (S3) stale 상태 재사용, (S4) 두 회로 desync, (S5) 미커밋/틀린 `rev_id` 사용 못 하게 + (P) 프라이버시.

| # | 속성 | 판정 | 메커니즘 / 음성 테스트 |
|---|---|---|---|
| S1 | 폐기됨 ⇒ 거부 | ✅ | `l < rev_id < r` 강제; 폐기 id는 gap 끝점이라 포함하는 서명 gap 없음. `REVOKED=1`이 `l = N` 설정 → 단언 실패 → **`eval_circuit failed`(증명 자체 불가)** |
| S2 | span은 CRA 서명 필수 | ✅ | sig 회로의 CRA ECDSA(`e_span`). `BADSIG=1`이 CRA 아닌 키로 서명 → ECDSA 불만족 → 거부 |
| S3 | freshness(stale 금지) | ✅ | `span_pre[0..8] == epoch_pub`(공개). `STALE=1`이 epoch `e+1` 서명, 검증자는 `e` 핀 → 불일치 → 거부 |
| S4 | 회로 간 결속 | ✅ | `e_span`이 4번째 MAC-link 값. `TAMPER=1` mac 비트 플립 → 양쪽 거부 |
| S5 | `rev_id` 발급자 커밋 & 올바른 클레임 | ✅ | `SHA(disclosure)=rev_ebits ∈ _sd`(멤버십→서명 payload→ECDSA 체인) + `","revocation_id","` 리터럴 앵커로 그 클레임에 결속 |
| P | unlinkability | ✅* | `rev_id`, `l`, `r`, 발급자 서명 전부 숨김; `craPk` + `epoch`만 공개. 매 제시 새 proof. (*베이스 증명과 동일 잔여: 발급자 공개키는 여전히 노출 — 기반 보고서 §8.1.) |

### 6.1 엔디안 노트 (`e`와 동일)

`rev_id`의 회로 `v256` 값 = 다이제스트의 big-endian 정수(`push_rev_bits(dg)` ⇒ 정수 `= BE(dg) = BN_bin2bn(dg)`). `e_span`은 발급자 해시 `e`와 똑같이 처리: sig쪽 `to_montgomery(nat_be(span_dg))`, hash쪽 `push_rev_bits(span_dg)`(= SHA 출력), MAC는 `to_bytes_field = reverse(span_dg)` — 양쪽 일치. `l, r`은 span에 little-endian 저장, `lbits[i] = span_pre[8 + i/8][i%8]`로 추출(longfellow `MdocRevocationSpan`과 동일)해서 `vlt`가 `rev_id`와 정수로 비교.

## 7. 한계 / 신뢰가정 (회로로 못 막음)

- **CRA 운영모델.** "폐기 안 됨"의 soundness는 CRA가 정렬된 폐기집합을 올바로 유지하고 **매 epoch span 재서명**하는 불변식만큼만 강함(freshness는 회로가 강제하나 CRA가 회전해야). 데모는 `l = N−1, r = N+1`로 gap 시뮬레이션; 실제 CRA는 실제 폐기집합에서 gap 유도.
- **rev_id = `_sd` 다이제스트.** 다이제스트를 식별자로 쓰면 CRA가 `revocation_id` `_sd` 다이제스트로 폐기(발급 시 발급자가 앎). 무방하나 폐기 핸들이 발급된 disclosure에 결합됨.
- **고정 길이 클레임.** `revocation_id`는 고정 64-hex `_sd` 클레임; 발급자가 준수(disclosure 하나에 들어가야).
- **mdoc — 구현됨.** 동일 구성을 실제 mdoc에 적용(`revocation_id` IssuerSignedItem의 valueDigests 항목이 `rev_id`, 동일 span 블록) — [`mdoc-revocation_analysis-report-ko.md`](mdoc-revocation_analysis-report-ko.md) 참조.

## 8. 파일 / 실행

| 파일 | 역할 |
|---|---|
| `native/sdjwt_revoc_split.cc` | 2회로 split: SD-JWT-VC 증명 + 서명된 구간 비-멤버십 폐기 |
| `tools/gen-sdjwt.mjs` | `revocation_id`(64-hex)를 `_sd` 클레임으로 발급 |
| `src/demo-revocation.js` | `pnpm run demo:revocation` (6단계: ACCEPT + soundness 거부 4종) |

```bash
# 직접 호출: <fixture> <issuer-jwk> <now> <claims> <vct> <nonce> <aud> <epoch>
native/sdjwt_revoc_split fixtures/sdjwt.txt fixtures/issuer-jwk.json 1700000000 \
  "age_over_18" "https://credentials.example/pid" 1234567890 https://verifier.example 7
# 음성 테스트: REVOKED=1 / BADSIG=1 / STALE=1 / TAMPER=1 (각각 거부돼야)
```

CRA P-256 키와 span 서명은 `main`에서 OpenSSL로 생성(CRA 역할); `l, r`은 BIGNUM으로 `rev_id`를 brackets.

## 9. 미래 과제

- **mdoc 폐기** — ✅ 완료 ([`mdoc-revocation_analysis-report-ko.md`](mdoc-revocation_analysis-report-ko.md)).
- **현실적 CRA 도구**: 정렬된 폐기집합 유지, span 유도/서명, epoch별 발행.
- **단명 epoch와 조합**: 대부분 만료로 처리, 긴급 폐기만 서명된 span.
- **nullifier와 결합**: 한 크리덴셜이 `pseudonym_secret` + `revocation_id` 둘 다 보유(독립 블록, MAC 값 추가 없음).
