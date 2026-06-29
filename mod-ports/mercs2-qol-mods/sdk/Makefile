# SDK maintenance targets. The SDK itself is built into each mod (see sdk.mk);
# this Makefile only manages the generated world-load ladder header.

.PHONY: ladder ladder-check help

# Regenerate sdk/m2/load_ladder.gen.h from loadprobe's phases.rs.
# Override the source path with PHASES=/path/to/phases.rs if loadprobe lives
# somewhere other than the sibling ../mercenaries-game checkout.
ladder:
	python3 gen_ladder.py $(PHASES)

# Drift guard: fail if the committed header is out of sync with phases.rs.
ladder-check:
	python3 gen_ladder.py $(PHASES) --check

help:
	@echo "make ladder        — regenerate m2/load_ladder.gen.h from loadprobe phases.rs"
	@echo "make ladder-check  — verify the committed header matches phases.rs (drift guard)"
	@echo "  PHASES=/path/to/phases.rs to override the loadprobe source location"
