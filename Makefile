# One-command demos on seeded synthetic traffic (brief section 3c).
#   make demo-all    run every scenario in demos/scenarios/, print the summary
#                    table, write out/summary.json and out/receipts/
#   make demo-test   the same scenarios as pytest assertions, plus seed change,
#                    determinism and one mutation check per scenario
# Needs python3 with PyYAML (requirements-dev.txt). No network, no secrets.

PYTHON ?= python3
OUT ?= out

.PHONY: demo-all demo-test

demo-all:
	$(PYTHON) demos/synthtraffic.py run demos/scenarios/ --out $(OUT)

demo-test:
	$(PYTHON) -m pytest -q -p no:cacheprovider demos/
