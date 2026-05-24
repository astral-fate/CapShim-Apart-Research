# CapShim — Makefile
# Convenience targets for demo, evaluation, and paper build.

PYTHON ?= python

.PHONY: help install test demo eval report clean

help:
	@echo "CapShim targets:"
	@echo "  make install   install package + test extras (editable)"
	@echo "  make test      run pytest suite (unit + property-based)"
	@echo "  make demo      one-shot scenario showing allow + deny"
	@echo "  make eval      run full 20-scenario benchmark, print headline numbers"
	@echo "  make report    build paper/main.pdf (requires pdflatex + bibtex)"
	@echo "  make clean     remove build artefacts"

install:
	$(PYTHON) -m pip install -e ".[test]"

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m evals.demo_one

eval:
	$(PYTHON) -m evals.run_evals

report:
	cd paper && pdflatex -interaction=nonstopmode main.tex
	cd paper && bibtex main || true
	cd paper && pdflatex -interaction=nonstopmode main.tex
	cd paper && pdflatex -interaction=nonstopmode main.tex
	@echo ""
	@echo "PDF written to paper/main.pdf"

clean:
	rm -rf __pycache__ src/capshim/__pycache__ tests/__pycache__
	rm -rf evals/__pycache__ examples/__pycache__ examples/servers/__pycache__
	rm -f paper/main.aux paper/main.bbl paper/main.blg paper/main.log
	rm -f paper/main.out paper/main.toc paper/main.fdb_latexmk paper/main.fls
	rm -f paper/main.synctex.gz
	rm -f evals/results.json
