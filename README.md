# Mercenaries 2 Experimental Mods

A collection of experimental mods for **Mercenaries 2: World in Flames** (PC).

These are lightweight `.asi` plugins — DLLs loaded into the game at startup by an
[ASI loader](#installation). Each mod lives in its own directory under [`mods/`](mods/)
and builds independently against a shared mod stdlib.

## Layout

- [`mods/`](mods/) — the mods, one directory each
- [`sdk/`](sdk/) — **`m2`, the Mercenaries 2 mod stdlib**: logging, INI, SecuROM-safe
  MinHook detours, safe Lua-stack reads, a shared hook on the game's log stream, and
  load-progress triggers keyed to loadprobe's world-load ladder. Mods `#include <m2.h>`
  and link it via [`sdk/sdk.mk`](sdk/sdk.mk). See the [SDK README](sdk/README.md).

## Mods

| Mod | Description |
| --- | --- |
| [lua-bridge](mods/lua-bridge/) | Exposes the game's internal Lua state over a localhost TCP port (default: 27050) for real-time script injection, dynamic testing, and REPL console interaction. |
| [dev-cheat-menu](mods/dev-cheat-menu/) | Binds a configurable key (default: `Insert`) to trigger Pandemic's built-in developer cheat menu. |
| [debug-overlay](mods/debug-overlay/) | Custom Direct3D9 screen overlay for real-time debugging stats, stats tracking, and telemetry display. |

## Installation

These plugins are loaded by **`pmc_bb.dll`** — the Mercenaries Fan Build loader. It
bundles a SecuROM spoof, a debug console, and a built-in ASI loader (adapted from
[Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)'s code).

> **Ultimate ASI Loader itself is _not_ compatible** with Mercenaries 2 — don't drop a
> `dinput8.dll`/`dsound.dll` proxy in. The game loads `pmc_bb.dll` directly (its import
> table references it by ordinal), so the loader has to be `pmc_bb.dll`.

1. Get `pmc_bb.dll` into your game folder (next to `Mercenaries2.exe`). Easiest via the
   [mercs2-modkit](https://github.com/Mercenaries-Fan-Build/mercs2-modkit) **Setup** tab,
   which downloads it for you; or grab `pmc_bb.dll` from the
   [pmc-blackbox releases](https://github.com/Mercenaries-Fan-Build/pmc-blackbox/releases)
   and drop it in the game root.
2. Drop the mod's `.asi` (and its `.ini`, if any) into `<game>/scripts/`.
3. Launch the game.

Or skip the manual steps and install these from the modkit catalog (Browse → Download →
Enable → Deploy), which handles loader, placement, and updates.

Each mod writes a `<mod>.log` next to itself for troubleshooting.

## Building

You need a 32-bit MinGW cross-compiler (the game is a 32-bit process):

```sh
# macOS
brew install mingw-w64

# Ubuntu/Debian
apt install gcc-mingw-w64-i686
```

Build everything:

```sh
make
```

Or build a single mod:

```sh
make -C mods/dev-cheat-menu
```

Built `.asi` files are written into each mod's directory and are git-ignored.

### Updating the world-load ladder

`sdk/m2/load_ladder.gen.h` is generated from loadprobe's `phases.rs` (the single source
of truth for load milestones) and committed so mods build without the loadprobe checkout.
When loadprobe's ladder changes, regenerate and verify:

```sh
make -C sdk ladder        # regenerate from the sibling ../mercenaries-game checkout
make -C sdk ladder-check  # drift guard
```

## Releases

Publishing a GitHub release triggers a CI workflow
([`.github/workflows/build-release.yml`](.github/workflows/build-release.yml)) that
cross-compiles every mod and attaches the built `.asi` files to the release as
downloadable assets. The workflow can also be run manually via *Actions →
Build and attach ASI mods to release → Run workflow*, which uploads the binaries
as a build artifact without needing a release.

## License

MIT — see [LICENSE](LICENSE).
