# Build the paper. Requires a TeX distribution (pdflatex + bibtex).
# This machine has no TeX installed; build locally or on Overleaf
# (upload paper.tex + refs.bib). To install locally on Debian/Ubuntu:
#   sudo apt-get install texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended
PAPER = paper

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex refs.bib
	pdflatex -interaction=nonstopmode $(PAPER)
	bibtex $(PAPER)
	pdflatex -interaction=nonstopmode $(PAPER)
	pdflatex -interaction=nonstopmode $(PAPER)

watch:
	latexmk -pdf -pvc $(PAPER).tex

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log $(PAPER).out $(PAPER).toc

distclean: clean
	rm -f $(PAPER).pdf

.PHONY: all watch clean distclean
