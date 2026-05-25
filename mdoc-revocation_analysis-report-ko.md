# mdoc (ISO 18013-5) 프라이버시 보존 폐기(Revocation) — 분석 보고서

> 대상: `playground/` — **실제 mdoc** ZK 제시에 **프라이버시 보존 폐기**(서명된 구간 비-멤버십)를 추가하는 연구 확장. longfellow의 2회로 mdoc prover 위에서.
> 위치: `/home/unknown/longfellow/playground`
> 작성일: 2026-05-25 · 상태: 프로토타입, 동작 + soundness 감사 완료
> 기반: 이 문서는 mdoc 크리덴셜 증명의 **확장**. 공유 구성(서명된 구간 방식, ZK 최적성 논증, soundness 위협모델, 엔디안)은 SD-JWT 버전 [`sd-jwt-revocation_analysis-report-ko.md`](sd-jwt-revocation_analysis-report-ko.md)에 한 번 정리; 하부 longfellow mdoc 회로는 [`longfellow-zk_analysis-report-ko.md`](longfellow-zk_analysis-report-ko.md); 재활용하는 전용블록/CBOR앵커 machinery는 [`mdoc-nullifier_analysis-report-ko.md`](mdoc-nullifier_analysis-report-ko.md). 이 문서는 **mdoc 특화** 부분만 다룸.

---

## 1. 개요

**실제 mdoc** 크리덴셜이 **폐기 안 됨**을, 폐기 식별자도 어떤 크리덴셜인지도 안 밝히고 ZK로 증명. 방식 = longfellow 자체의 `MdocRevocationSpan`(`lib/circuits/tests/mdoc/mdoc_revocation.h`): 폐기기관(CRA)이 인접 폐기 id 사이 빈 구간 `epoch ‖ l ‖ r`을 서명, 홀더가 `l < rev_id < r` 증명. 목록 크기와 무관 상수 크기 증명.

프로토타입: `native/mdoc_revoc_split.cc`(2회로 split); 데모 `pnpm run demo:mdoc-revocation`; 발급기 `tools/gen-mdoc.mjs`가 `revocation_id` element 추가.

## 2. mdoc 특화 부분

구성 전체가 SD-JWT 버전과 동일하되, **`rev_id`를 얻는 방법**만 다르고 mdoc에선 오히려 *더 깔끔*:

- **`rev_id` = `revocation_id` IssuerSignedItem의 MSO `valueDigests` 항목**, 즉 `SHA256(item)`. mdoc은 *모든* element의 digest가 서명된 MSO에 있음(공개 여부 무관)이라, 그 digest가 곧 숨겨진·발급자 커밋·크리덴셜당 256비트 값. **회로 내 hex 디코드 불필요** — digest가 곧 256비트 정수.
- 회로는 **nullifier 블록 machinery를 그대로 재활용**: (1) COSE1(MSO) preimage 재구성 + index 범위검사, (2) `mm = SHA(sec_item)`이 서명된 MSO의 `sec_mso` 위치에 있음 증명(멤버십) — `mm`(v256)이 **곧** `rev_id`, (3) 리터럴 CBOR 앵커 `71 "elementIdentifier" 6D "revocation_id"`로 `sec_item`이 `revocation_id` element임을 결속(다른 item의 digest 대입 불가). 64바이트 값은 **추출 안 함**(nullifier와 달리) — digest만 필요.
- span 블록(`SHA(epoch‖l‖r)=e_span`, epoch 핀, `l < rev_id < r`)과 MAC 배관(4번째 링크값 `e_span` 추가, CRA ECDSA는 Fp256 sig 회로)은 SD-JWT 버전에서 그대로 복사.

엔디안은 `mm` 컨벤션과 일치(`integer(mm) = BE(digest) = BN_bin2bn(digest)`), MdocHash 및 SD-JWT `rev_ebits`와 동일 — [`sd-jwt-revocation_analysis-report-ko.md`](sd-jwt-revocation_analysis-report-ko.md) §6.1. `l, r`은 span에 little-endian 저장, `lbits[i] = span_pre[8+i/8][i%8]`로 추출(`MdocRevocationSpan`과 동일).

## 3. 아키텍처 & 성능

- **sig 회로(Fp256)**: `MdocSignature::assert_signatures`(발급자+디바이스 ECDSA) **+ CRA ECDSA(e_span)** + `e_span` MAC.
- **hash 회로(GF(2¹²⁸))**: `MdocHash::assert_valid_hash_mdoc`(불변) + 위 revocation 블록.
- **MAC 링크 3 → 4값**: `e, dpkx, dpky, e_span`; `a_p[8]`, `a_v`는 commit 후 transcript; 번들 = `[8 macs][hash proof][sig proof]`. Transcript는 session transcript로 시드.

| 지표 | 값(1속성 공개, 실제 fixture) |
|---|---|
| prove | ~0.95 s |
| verify | ~0.48 s |
| 번들 | ~361 KB |

폐기목록 크기와 무관 — 홀더는 span 하나만 들고 다님.

## 4. 속성 (`demo:mdoc-revocation`으로 검증)

- **폐기 안 됨** → ACCEPT. **폐기됨** → REJECT(서명 gap이 `rev_id`를 못 bracket). **위조 상태**(CRA 아닌 span) → REJECT. **stale span**(이전 epoch) → REJECT. **MAC 변조** → 양쪽 회로 REJECT.

## 5. Soundness 감사

SD-JWT 감사(S1–S5 + 프라이버시) 상속 — [`sd-jwt-revocation_analysis-report-ko.md`](sd-jwt-revocation_analysis-report-ko.md) §6 — 실제 mdoc에서 검증:

| # | 속성 | 판정 | 음성 테스트 |
|---|---|---|---|
| S1 | 폐기됨 ⇒ 거부 | ✅ | `REVOKED=1`(`l = N`) → `l < rev_id` 실패 → **PROVE REJECTED**(증명 불가) |
| S2 | span CRA 서명 | ✅ | `BADSIG=1` → ECDSA 불만족 → 거부 |
| S3 | freshness(epoch 핀) | ✅ | `STALE=1`(epoch `e+1` 서명, `e` 핀) → 거부 |
| S4 | 회로 간 결속 | ✅ | `TAMPER=1` → 양쪽 거부 |
| S5 | `rev_id` 발급자 커밋 & 올바른 element | ✅ | 멤버십(`mm = SHA(item) ∈ 서명 MSO valueDigests`) + `revocation_id` CBOR 앵커 |

mdoc 특화 free index(`sec_mso`, `sec_anchor`)는 nullifier 보고서([`mdoc-nullifier_analysis-report-ko.md`](mdoc-nullifier_analysis-report-ko.md) §5)에서 감사됨, 그대로 적용.

## 6. 한계 / 신뢰가정

- **CRA 운영모델**(SD-JWT와 동일): 정렬된 폐기집합 유지 + 매 epoch span 재서명(freshness는 회로 강제, 회전은 운영). 데모는 `l = N−1, r = N+1`로 gap 시뮬레이션.
- **고정 길이 element**: `revocation_id`는 64-hex mdoc element라 item이 3블록 버퍼(`SECB = 3`)에 들어감.
- **rev_id = item digest**: CRA가 `revocation_id` valueDigests 항목으로 폐기(발급 시 발급자가 앎).

## 7. 파일 / 실행

| 파일 | 역할 |
|---|---|
| `native/mdoc_revoc_split.cc` | 실제 mdoc 2회로 split + 서명된 구간 비-멤버십 폐기 |
| `tools/gen-mdoc.mjs` | `revocation_id` element 발급(`@lukas.j.han/mdoc`) |
| `src/demo-mdoc-revocation.js` | `pnpm run demo:mdoc-revocation` (ACCEPT + soundness 거부 4종) |

```bash
# 직접 호출: <mdoc.bin> <issuer.json> <transcript.bin> <now> <attr_id> <attr_hex> <epoch>
native/mdoc_revoc_split fixtures/mdoc.bin fixtures/mdoc-issuer.json \
  fixtures/mdoc-transcript.bin 2026-06-01T00:00:00Z age_over_18 f5 7
# 음성 테스트: REVOKED=1 / BADSIG=1 / STALE=1 / TAMPER=1 (각각 거부돼야)
```

CRA P-256 키와 span 서명은 `main`에서 OpenSSL로 생성; `l, r`은 BIGNUM으로 `rev_id`를 brackets.

## 8. nullifier와의 관계

`mdoc_revoc_split` = `mdoc_null_split`에서 nullifier 꼬리(`nullifier = SHA(secret‖SHA(context))`)를 span 블록으로 교체하고, 멤버십 블록을 재활용한 것: 거기서 이미 계산하는 digest(`mm`)가 `rev_id`가 됨. 한 크리덴셜이 `pseudonym_secret` + `revocation_id`를 독립 블록으로 동시 보유 가능(`e_span` 외 추가 MAC 값 없음).
