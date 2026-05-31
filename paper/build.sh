#!/usr/bin/env bash
# Build paper.pdf with NO local TeX install, using a TeX Live docker image.
# (This machine has no pdflatex; docker is available.)
#
#   ./build.sh            # -> paper.pdf
#   PDF=paper-twocol ./build.sh   # build a different file stem
#
# Runs as the current uid so outputs are user-owned; HOME=/tmp keeps the
# container's font cache writable. The image ships pdflatex + bibtex + the
# packages this paper needs (amsmath, booktabs, pifont, tikz, microtype, ...).
set -euo pipefail
cd "$(dirname "$0")"
PDF="${PDF:-paper}"
IMG="ghcr.io/xu-cheng/texlive-small:latest"

docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/work -w /work \
  --entrypoint /bin/sh "$IMG" -c "
    pdflatex -interaction=nonstopmode $PDF.tex >/tmp/r1 2>&1
    bibtex   $PDF                      >/tmp/rb 2>&1 || true
    pdflatex -interaction=nonstopmode $PDF.tex >/tmp/r2 2>&1
    pdflatex -interaction=nonstopmode $PDF.tex >/tmp/r3 2>&1
    grep -nE '^! |LaTeX Error|Emergency stop' /tmp/r3 && exit 1
    grep 'Output written' /tmp/r3
  "
# keep the folder clean: drop aux/log, leave only sources + the PDF
rm -f "$PDF".aux "$PDF".bbl "$PDF".blg "$PDF".log "$PDF".out
echo "ok -> $PDF.pdf"
