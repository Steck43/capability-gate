# One-command demos on seeded synthetic traffic.
#   make demo-all    run every scenario in demos/scenarios/, print the summary
#                    table, write out/summary.json and out/runs/
#   make demo-test   the same scenarios as pytest assertions, plus seed change,
#                    determinism and one mutation check per scenario
#   make demo-isolate  S14 alone: isolate calls through the plugin hook to the
#                    stub box door (real: false), written to out/isolate/
#   make hire-demo   allow / deny / kill switch / fail closed on the real gate,
#                    one command, writes out/hire/demo-output.txt
#   make hire-forge  rewrite a decision log line, verify rejects (60s audit)
#   make claimgate   lint claimgate/claims.yaml; the red fixture must fail
#   make hire-pins   every fail-when-removed mutant must turn its tests red
#   make hire-record a CISO decision record bound to a real log row: real
#                    accepts, missing or forged rejects
#   make hire-all    the five above
# Needs python3 with PyYAML (requirements-dev.txt). No network, no secrets.
# S14 also needs cargo and an isolation-layer checkout: ISOLATION_LAYER_ROOT,
# else ../isolation-layer. CG_ISOLATE_DOOR names a built sandbox-demo instead.

PYTHON ?= python3
OUT ?= out

.PHONY: demo-all demo-test demo-isolate hire-demo hire-forge claimgate hire-pins hire-record hire-all

demo-all:
	$(PYTHON) demos/synthtraffic.py run demos/scenarios/ --out $(OUT)

demo-test:
	$(PYTHON) -m pytest -q -p no:cacheprovider demos/

demo-isolate:
	$(PYTHON) demos/synthtraffic.py run demos/scenarios/S14-isolate-route.yaml --out $(OUT)/isolate

hire-demo:
	$(PYTHON) demos/hire/hire_demo.py --out $(OUT)/hire

hire-forge:
	$(PYTHON) demos/hire/forge_audit.py --out $(OUT)/hire

claimgate:
	$(PYTHON) claimgate/claimgate.py check claimgate/claims.yaml
	! $(PYTHON) claimgate/claimgate.py check claimgate/fixtures/red-overreach.yaml

hire-pins:
	$(PYTHON) demos/hire/pins.py --out $(OUT)/hire

hire-record:
	$(PYTHON) demos/hire/decision_record.py demo --out $(OUT)/hire

hire-all: hire-demo hire-forge claimgate hire-pins hire-record
