# One-command demos on seeded synthetic traffic.
#   make demo-all    run every scenario in demos/scenarios/, print the summary
#                    table, write out/summary.json and out/runs/
#   make demo-test   the same scenarios as pytest assertions, plus seed change,
#                    determinism and one mutation check per scenario
#   make demo-isolate  S14 alone: isolate calls through the plugin hook to the
#                    stub box door (real: false), written to out/isolate/
# Needs python3 with PyYAML (requirements-dev.txt). No network, no secrets.
# S14 also needs cargo and an isolation-layer checkout: ISOLATION_LAYER_ROOT,
# else ../isolation-layer. CG_ISOLATE_DOOR names a built sandbox-demo instead.

PYTHON ?= python3
OUT ?= out

.PHONY: demo-all demo-test demo-isolate

demo-all:
	$(PYTHON) demos/synthtraffic.py run demos/scenarios/ --out $(OUT)

demo-test:
	$(PYTHON) -m pytest -q -p no:cacheprovider demos/

demo-isolate:
	$(PYTHON) demos/synthtraffic.py run demos/scenarios/S14-isolate-route.yaml --out $(OUT)/isolate
