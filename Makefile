PY ?= python3

.PHONY: setup check control test

setup:      ## sandbox runtime check, image and network
	$(PY) -m harness setup

check:      ## isolation checks
	$(PY) -m harness check

control:    ## positive controls in real containers
	$(PY) -m harness control

test:       ## unit tests (no Docker or model needed)
	$(PY) -m pytest -q
