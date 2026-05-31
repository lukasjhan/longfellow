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

## Two-column layout

This draft is single-column `article` for readability. Conference venues are
two-column; switch only when you commit to a venue.

**Quick preview (generic, _not_ submission-accurate):** `./make-twocol.sh` derives
`paper-twocol.{tex,pdf}` from `paper.tex` (10pt twocolumn; wide tables/figure spanned
via `table*`/`figure*`; larger `\emergencystretch`). Generated files are throwaway and
git-ignored — `paper.tex` stays canonical.

**Real submission — use the venue class** (do _not_ ship the generic preview):
1. Replace `\documentclass[11pt]{article}` with the venue class:
   - **PETS/PoPETs**: the `popets` class from the PoPETs author kit (not in TeX Live — download it).
   - USENIX: the `usenixYYYY` style; **IEEE S&P**: `IEEEtran` (in texlive-full); **ACM CCS**: `acmart` with `sigconf` (in texlive-full).
2. Span only the wide floats — keep Table 1 (related work), Figure 1 (seam), and
   Table 2 (eval) as `table*`/`figure*`; keep the narrow Table 3 and the checks table
   single-column.
3. Let the class span the title + abstract across the top (popets/acmart do this; for
   plain `article`, wrap with `\twocolumn[\maketitle ...]`).
4. Body, theorems, and bibliography port unchanged — only the preamble and a few float
   widths change. Mind the venue page limit (two-column ≈ 8–10 pp here).

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
- [x] **Table 3** (§7.4) — analytical batch-issuance vs. this-work cost model.
- [x] Security games restated in pseudocode; full proofs of soundness + issuer-untraceability in Appendix A.
- [x] RFC 9901 confirmed (SD-JWT, IETF Internet Standard, 2025); mdoc base addressed by a note (nullifier adds <6%).
- [x] No `\TODO` markers remain in the document.
- [ ] Confirm EU 2024/1183 (eIDAS 2.0) and AAMVA mDL Guidelines citation details against the primary documents.
- [ ] Needs external resources only: formal gate/constraint counts (circuit-compiler instrumentation) and a mobile + server-class datapoint.

## Honesty guardrails (do not drop)
- The signed-range revocation **mechanism** is longfellow's (`MdocRevocationSpan`); our
  contribution is its SD-JWT VC extension + integration. Kept as Table 1 footnote `a`
  and stated in §4.5 / §8.
- Novelty claims use "to the best of our knowledge" and are scoped to the precise triple
  (no setup ∧ unmodified standard format ∧ issuer-untraceable nullifier).
- `libzk` is an **Internet-Draft** (expired), not a standard; longfellow is the
  peer-reviewed IACR CiC paper.
