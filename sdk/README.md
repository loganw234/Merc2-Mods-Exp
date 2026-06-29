# `m2` — Mercenaries 2 mod stdlib

A small reusable runtime layer that every Mercs2 ASI mod tends to need, so mods can
be thin. Include `<m2.h>` and link the SDK via [`sdk.mk`](sdk.mk).

## Modules

| Header | What it gives you |
| --- | --- |
| [`m2_target.h`](m2/m2_target.h) | All binary-specific addresses for the target EXE in one place (log stub, VO bindings, section VAs). |
| [`m2_log.h`](m2/m2_log.h) | Per-module `<mod>.log` file logging (`m2_log_init` / `m2_logf`). |
| [`m2_ini.h`](m2/m2_ini.h) | Tiny callback-based INI reader (`m2_ini_parse`, `m2_ini_bool/int`). |
| [`m2_hook.h`](m2/m2_hook.h) | SecuROM-safe `.text` detours via MinHook (`m2_hook_attach`). |
| [`m2_luastack.h`](m2/m2_luastack.h) | Bounds-checked reads of a Lua 5.1 (float-build) C-function's string args. |
| [`m2_loghook.h`](m2/m2_loghook.h) | One subscription to the game's whole log stream (the shared log stub). |
| [`m2_loadtrigger.h`](m2/m2_loadtrigger.h) | Fire callbacks as the world load crosses loadprobe milestones. |

## Why these specifically

- **`.text` MinHook, never `.rdata`.** The cracked retail EXE tolerates code detours
  but anti-tampers registration-table writes (a `.rdata` slot patch crashed early init
  under SecuROM — confirmed in `tools/pmc_blackbox/lua_log_hook.c`). `m2_hook` routes
  everything through MinHook.
- **The log stub is the event bus.** ~700 stripped log functions — including Lua
  `print` / `Debug.Printf` — funnel through one no-op stub. `m2_loghook` detours it
  once and fans every line out to listeners.
- **loadprobe is the single source of truth for load progress.** `m2_loadtrigger`
  matches the *exact* milestone substrings loadprobe uses, via a generated header.

## The world-load ladder (generated)

[`m2/load_ladder.gen.h`](m2/load_ladder.gen.h) is generated from loadprobe's
`phases.rs` by [`gen_ladder.py`](gen_ladder.py) — **do not edit it by hand**.

```sh
make -C sdk ladder        # regenerate from ../mercenaries-game's loadprobe
make -C sdk ladder-check  # drift guard: fail if the header is stale
make -C sdk ladder PHASES=/path/to/phases.rs   # if loadprobe lives elsewhere
```

The committed header lets mods build without the loadprobe checkout present (e.g. in
CI); regeneration is a local step when the ladder changes.

## Using the SDK from a mod

```make
include ../../sdk/sdk.mk
mod.asi: mod.c
	i686-w64-mingw32-gcc -O2 -shared $(M2_CFLAGS) -o $@ $< $(M2_SRCS) -lkernel32 -luser32
```

```c
#include "m2.h"

static void on_world_load(int phase, void* ud) { /* arm your feature */ }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        m2_log_init(h);
        m2_hook_init();
        m2_loadtrigger_on_phase(M2_PHASE_ENTERED_WORLD_IDX, on_world_load, NULL);
        m2_loadtrigger_install();
    }
    return TRUE;
}
```

See [`mods/quiet-freeplay-vo`](../mods/quiet-freeplay-vo/) for a complete consumer.

## Target

Built for the cracked retail EXE (`53,482,288` bytes, image base `0x00400000`); the
addresses in `m2_target.h` are binary-specific. MinHook is vendored under
[`minhook/`](minhook/) (32-bit sources only).
