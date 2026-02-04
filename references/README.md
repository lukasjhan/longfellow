# 참고 자료 (References)

아래 논문 PDF는 로컬에는 내려받아 두었으나(이 폴더), 서드파티 저작물이라
git에는 포함하지 않습니다(`.gitignore`). 필요 시 아래 링크에서 받으세요.

| 자료 | 설명 | 링크 / 로컬 파일 |
|---|---|---|
| **Anonymous credentials from ECDSA** (ePrint 2024/2010) | Longfellow 원논문. Frigo & shelat (Google). sumcheck+Ligero로 ECDSA ZK | https://eprint.iacr.org/2024/2010 · `2024-2010_Anonymous-credentials-from-ECDSA.pdf` |
| **Ligero** (ePrint 2022/1608) | 신뢰 셋업 없는 sublinear 논증. 커밋먼트+ZK 토대 | https://eprint.iacr.org/2022/1608 · `2022-1608_Ligero.pdf` |
| **Novel polynomial basis / Additive FFT** (arXiv 1404.3458) | GF(2^k) extend 효율 구현 기반 (Lin et al. 2014) | https://arxiv.org/abs/1404.3458 · `1404.3458_Additive-FFT_Lin-et-al.pdf` |
| IETF draft-google-cfrg-libzk | 사양 초안 | https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/ |
| Fiat-Shamir from Simpler Assumptions (ePrint 2018/1004) | FS 건전성 이론적 근거 | https://eprint.iacr.org/2018/1004 |
| 공식 문서 (보안감사 Reviews 포함) | — | https://google.github.io/longfellow-zk/ |

다운로드 (선택):
```bash
cd references
curl -L -o 2024-2010_Anonymous-credentials-from-ECDSA.pdf https://eprint.iacr.org/2024/2010.pdf
curl -L -o 2022-1608_Ligero.pdf                            https://eprint.iacr.org/2022/1608.pdf
curl -L -o 1404.3458_Additive-FFT_Lin-et-al.pdf            https://arxiv.org/pdf/1404.3458
```
