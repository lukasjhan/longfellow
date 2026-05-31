# Paper: *Anonymous Credentials from SD-JWT VC*

LaTeX home for the paper. Working title:
**Anonymous Credentials from SD-JWT VC: Issuer-Unlinkable Nullifiers and Revocation in Transparent Zero-Knowledge.**
Target venue: PETS (1순위) / WPES / Financial Crypto.

## Files
- `paper.tex` — full single-file skeleton (all sections, merged from the markdown drafts).
- `refs.bib` — bibliography (some fields marked `[VERIFY]` pending camera-ready).
- `Makefile` — `make` to build (needs a TeX distribution).

## Build
This machine has **no TeX toolchain**. Two options:
1. **Overleaf** — upload `paper.tex` + `refs.bib`, compile with pdfLaTeX.
2. **Local** — install TeX, then `make`:
   ```
   sudo apt-get install texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended
   make            # pdflatex → bibtex → pdflatex ×2
   ```
The preamble is portable (`article` + amsmath/amsthm/booktabs/pifont/hyperref).
To target a venue, swap `\documentclass` for the PoPETs/ACM class.

## Section ↔ source-draft map
The prose was developed in the markdown drafts in **this folder** (Korean commentary +
English paper text); `paper.tex` is the merged English version. From here on treat
`paper.tex` as canonical; the drafts are kept for reference/provenance.

| Section | Source draft (in `paper/`) |
|---|---|
| Abstract, §1 Introduction | `paper-introduction-draft.md` |
| §2 Background | (stub — outline §2) |
| §3 Threat Model, §5 Security | `paper-security-draft.md` |
| §4 Construction | `paper-construction-draft.md` |
| §6 Implementation | (stub) |
| §7 Evaluation | `paper-evaluation-draft.md` |
| §8 Related Work + Table 1 | `paper-related-work-draft.md` |
| Outline / contributions | `paper-outline-ko.md` |
| Prior-art survey (3 rounds) | `paper-prior-art-research-ko.md` |

## Reproducing the evaluation (Table 2)
From `playground/`:
```
REPS=7 node tools/eval-bench.mjs      # regenerates fixtures, writes fixtures/eval-results.{json,csv}
```
Measured on AMD Ryzen 7 2700X (8C/16T). Raw numbers: `playground/fixtures/eval-results.csv`.

## Open items before submission
- [x] **Idemix / U-Prove** — facts confirmed (CL/Strong-RSA/multi-show; Brands/DL/one-show); primary sources cited.
- [x] §2 Background, §6 Implementation, §9 Discussion, §10 Conclusion — filled.
- [x] **Figure 1** — split-circuit seam (sig $\mathbb{F}_p$ ⊕ hash $\mathrm{GF}(2^{128})$, MAC link) + 3 feature blocks (TikZ).
- [ ] Deployment citations: verify EU 2024/1183, AAMVA mDL, RFC 9901 number/section against primary docs.
- [ ] (optional) mdoc-base row, formal gate counts, a mobile + server datapoint, batch-issuance issuer-side cost model (Table 3).
- [ ] Tighten security games to pseudocode; full proofs in appendix.
- [ ] Remaining `\TODO` in §7.4 (issuer-side cost model / Table 3).

## Honesty guardrails (do not drop)
- The signed-range revocation **mechanism** is longfellow's (`MdocRevocationSpan`); our
  contribution is its SD-JWT VC extension + integration. Kept as Table 1 footnote `a`
  and stated in §4.5 / §8.
- Novelty claims use "to the best of our knowledge" and are scoped to the precise triple
  (no setup ∧ unmodified standard format ∧ issuer-untraceable nullifier).
- `libzk` is an **Internet-Draft** (expired), not a standard; longfellow is the
  peer-reviewed IACR CiC paper.
