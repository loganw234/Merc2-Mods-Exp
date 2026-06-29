#!/usr/bin/env python3
"""Generate sdk/m2/load_ladder.gen.h from loadprobe's phases.rs LADDER.

loadprobe (in the mercenaries-game repo) is the single source of truth for the
world-load milestone ladder. This script parses its `phases.rs` and emits a C
header so the runtime trigger facility (m2_loadtrigger) matches the *exact* same
substrings — no hand-kept duplicate, no drift.

Usage:
    python3 sdk/gen_ladder.py [PATH_TO_phases.rs]

If PATH_TO_phases.rs is omitted, it defaults to the sibling checkout:
    ../mercenaries-game/tools/wad_simulator/crates/loadprobe/src/phases.rs
(overridable with the LOADPROBE_PHASES_RS environment variable).

Run `make -C sdk ladder` to regenerate, and `make -C sdk ladder-check` to verify
the committed header is in sync with phases.rs (used as a drift guard).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_PHASES = os.path.join(
    REPO, "..", "mercenaries-game",
    "tools", "wad_simulator", "crates", "loadprobe", "src", "phases.rs",
)
OUT = os.path.join(HERE, "m2", "load_ladder.gen.h")

# Phase { idx: 0, name: "Process init", matches: &["a", "b"] },
PHASE_RE = re.compile(
    r'Phase\s*\{\s*idx:\s*(\d+)\s*,\s*'
    r'name:\s*"((?:[^"\\]|\\.)*)"\s*,\s*'
    r'matches:\s*&\[(.*?)\]\s*\}',
    re.DOTALL,
)
# string literals inside a matches: &[ ... ] list
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
CONST_RE = lambda name: re.compile(r'pub\s+const\s+' + name + r'\s*:\s*usize\s*=\s*(\d+)\s*;')


def c_escape(s: str) -> str:
    # Rust string-literal escapes we care about map 1:1 to C.
    return s.replace('\\', '\\\\').replace('"', '\\"')


def parse(text: str):
    phases = []
    for m in PHASE_RE.finditer(text):
        idx = int(m.group(1))
        name = m.group(2)
        matches = STR_RE.findall(m.group(3))
        if not matches:
            sys.exit(f"error: phase idx {idx} ({name!r}) has no match substrings")
        phases.append((idx, name, matches))
    if not phases:
        sys.exit("error: no Phase entries found in phases.rs (format changed?)")
    phases.sort(key=lambda p: p[0])
    for i, (idx, _, _) in enumerate(phases):
        if idx != i:
            sys.exit(f"error: ladder idx not contiguous: expected {i}, got {idx}")

    def const(name, default):
        mm = CONST_RE(name).search(text)
        return int(mm.group(1)) if mm else default

    reached = const("REACHED_WORLD_IDX", phases[-1][0])
    entered = const("ENTERED_WORLD_IDX", 0)
    return phases, reached, entered


def emit(phases, reached, entered, src_path: str) -> str:
    rel = os.path.relpath(src_path, REPO)
    out = []
    out.append("/* AUTO-GENERATED from loadprobe by sdk/gen_ladder.py — DO NOT EDIT. */")
    out.append(f"/* Source of truth: {rel} */")
    out.append("#ifndef M2_LOAD_LADDER_GEN_H")
    out.append("#define M2_LOAD_LADDER_GEN_H")
    out.append("")
    out.append(f"#define M2_LADDER_COUNT {len(phases)}")
    out.append(f"#define M2_PHASE_REACHED_WORLD_IDX {reached}")
    out.append(f"#define M2_PHASE_ENTERED_WORLD_IDX {entered}")
    out.append("")
    out.append("typedef struct {")
    out.append("    int idx;")
    out.append("    const char* name;")
    out.append("    const char* const* matches;")
    out.append("    int match_count;")
    out.append("} M2LoadPhase;")
    out.append("")
    for idx, _name, matches in phases:
        lits = ", ".join(f'"{c_escape(s)}"' for s in matches)
        out.append(f"static const char* const k_m2_phase_{idx}_matches[] = {{ {lits} }};")
    out.append("")
    out.append(f"static const M2LoadPhase k_m2_ladder[M2_LADDER_COUNT] = {{")
    for idx, name, matches in phases:
        out.append(
            f'    {{ {idx}, "{c_escape(name)}", '
            f"k_m2_phase_{idx}_matches, {len(matches)} }},"
        )
    out.append("};")
    out.append("")
    out.append("#endif /* M2_LOAD_LADDER_GEN_H */")
    out.append("")
    return "\n".join(out)


def main():
    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    check = "--check" in sys.argv
    src = positional[0] if positional else os.environ.get(
        "LOADPROBE_PHASES_RS", DEFAULT_PHASES)
    src = os.path.abspath(src)
    if not os.path.exists(src):
        sys.exit(f"error: phases.rs not found at {src}\n"
                 f"       pass the path explicitly or set LOADPROBE_PHASES_RS")
    with open(src, encoding="utf-8") as f:
        text = f.read()
    phases, reached, entered = parse(text)
    header = emit(phases, reached, entered, src)

    if check:
        if not os.path.exists(OUT):
            sys.exit(f"DRIFT: {OUT} does not exist; run `make -C sdk ladder`")
        with open(OUT, encoding="utf-8") as f:
            current = f.read()
        if current != header:
            sys.exit(f"DRIFT: {os.path.relpath(OUT, REPO)} is out of sync with "
                     f"{os.path.relpath(src, REPO)}; run `make -C sdk ladder`")
        print(f"ladder in sync ({len(phases)} phases)")
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(header)
    print(f"wrote {os.path.relpath(OUT, REPO)} ({len(phases)} phases, "
          f"reached={reached}, entered={entered}) from {os.path.relpath(src, REPO)}")


if __name__ == "__main__":
    main()
