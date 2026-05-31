#!/usr/bin/env bash
# Generate a TWO-COLUMN PREVIEW (paper-twocol.{tex,pdf}) from the canonical
# single-column paper.tex. The generated files are throwaway and git-ignored;
# paper.tex stays the source of truth.
#
#   ./make-twocol.sh           # derive + build paper-twocol.pdf (needs docker)
#   NOBUILD=1 ./make-twocol.sh # only derive paper-twocol.tex
#
# NOTE: this is a GENERIC preview (article 10pt twocolumn), NOT submission format.
# For a real submission, switch paper.tex's \documentclass to the venue class
# (PETS popets / IEEEtran / acmart) instead -- see README "Two-column layout".
set -euo pipefail
cd "$(dirname "$0")"

cp paper.tex paper-twocol.tex
# (1) 10pt two-column; (2) wider emergencystretch for narrow columns;
# (3) span every table/figure across both columns so wide floats don't overflow.
sed -i \
  -e 's/\\documentclass\[11pt\]{article}/\\documentclass[10pt,twocolumn]{article}/' \
  -e 's/\\setlength{\\emergencystretch}{1em}/\\setlength{\\emergencystretch}{3em}/' \
  -e 's/\\begin{table}/\\begin{table*}/g'  -e 's/\\end{table}/\\end{table*}/g' \
  -e 's/\\begin{figure}/\\begin{figure*}/g' -e 's/\\end{figure}/\\end{figure*}/g' \
  paper-twocol.tex

if [ "${NOBUILD:-0}" != 1 ] && command -v docker >/dev/null 2>&1; then
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/work -w /work \
    --entrypoint /bin/sh ghcr.io/xu-cheng/texlive-small:latest -c '
      pdflatex -interaction=nonstopmode paper-twocol.tex >/dev/null 2>&1
      bibtex paper-twocol >/dev/null 2>&1
      pdflatex -interaction=nonstopmode paper-twocol.tex >/dev/null 2>&1
      pdflatex -interaction=nonstopmode paper-twocol.tex >/dev/null 2>&1'
  rm -f paper-twocol.aux paper-twocol.bbl paper-twocol.blg paper-twocol.log paper-twocol.out
  echo "built paper-twocol.pdf"
else
  echo "generated paper-twocol.tex (build skipped)"
fi
