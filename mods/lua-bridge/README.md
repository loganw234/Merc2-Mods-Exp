# lua-bridge (mercs2-qol-mods port)

Exposes Mercenaries 2's statically-linked Lua 5.1.2 runtime via a
localhost TCP REPL on `127.0.0.1:27050`, allowing arbitrary Lua chunks
to be executed against the live engine state. Ported from
[loganw234/Mercenaries2](https://github.com/loganw234/Mercenaries2)
to the [mercs2-qol-mods SDK](https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).

Pairs with the companion `multiplayer-restore/` mod in this same
repo but is independent: enable one, the other, or both via the
modkit.

> [!NOTE]
> Tested and verified working against **`v0.2.0` of the `pmc_bb.dll` loader** (the Mercenaries Fan Build loader).

## What it does

The bridge installs three MinHook detours (`noop_stub`, `luaB_type`,
`CreateTextWidget`) that together capture the engine's live
`lua_State` on any Lua dispatch and serve as pump sources for queued
chunks. When a client connects to `127.0.0.1:27050` and sends a Lua
chunk terminated with `<<<RUN>>>`, the chunk is queued; whenever one
of the detours fires with a verified-valid `L`, the chunk is compiled
via the real `luaB_loadstring` and run via `luaB_pcall`, with the
return values formatted back over the socket.

Per-binary RVA table + FNV-1a fingerprinting lets it work cleanly on
two known builds of `Mercenaries2.exe`:

| Fingerprint | Binary |
|-------------|--------|
| `0xB79E4DD22A4BFCB3` | v1.1 (archive.org English retail) |
| `0x1942B494FF9F4DB3` | v1.1 + mercs2-securom-bypass |

Unknown binaries trip the prologue validator on each hook target and
fail closed — the bridge logs the fingerprint and disables itself
rather than risking a CTD.

## Install

1. Drop a built `lua_bridge.asi` and `lua_bridge.ini` into your
   Mercenaries 2 install folder.
2. Launch the game with any ASI loader (`pmc_bb.dll`, dxwrapper, etc).
3. Connect with a client. Recommended:
   `py tools/lua_console.py` from the upstream
   [Merc2Reborn](https://github.com/loganw234/Mercenaries2) repo.

## Build

If this directory lives under `mercs2-qol-mods/mods/`:

```sh
cd mods/lua-bridge
make
```

Out-of-tree:

```sh
make SDK_DIR=/path/to/mercs2-qol-mods/sdk
```

Output: `lua_bridge.asi`.

## Config (`lua_bridge.ini`)

```ini
[repl]
host = 127.0.0.1   ; bind address (127.0.0.1 = localhost-only)
port = 27050       ; default matches the upstream client tools
```

## Status

**Fully verified and tested.** Builds cleanly using MinGW (`i686-w64-mingw32-gcc`) and has been fully runtime-tested and verified working on a real game session loaded with `pmc_bb.dll` (v0.2.0). All hooks arm correctly, the prologue validators pass on target binaries, and the REPL processes arbitrary Lua chunks dynamically.

## One known deferred feature: the `luaL_register` hijack

Mercenaries 2's `luaL_register` uses a non-standard register-argument
ABI (`ECX = lua_State* L`, `EAX = const char* libname`, `[esp+4] =
const luaL_Reg* table`, caller cleans 4 bytes). MinHook can't directly
detour this with a standard-convention wrapper; the upstream project
uses a `__declspec(naked)` MSVC function that manually preserves
registers and forwards.

GCC/MinGW on x86 doesn't support `__attribute__((naked))`. Three
reasonable resolutions are documented in detail in `lua_bridge.c`
right above the deferred section:

1. Translate the naked function to a global assembly file
   (`lua_bridge_asm.S`) and add it to the Makefile.
2. Compile this mod with MSVC. SDK helpers should work either way;
   only the build glue changes.
3. Ship without it. This is what the current draft does. The bridge
   degrades gracefully: the other three detours still capture L, the
   executor still runs chunks. Lost capabilities are the
   print/next/tostring hijack (a high-frequency pump source — chunks
   may take slightly longer to drain when the engine is between
   dispatches) and the registration-table dump (a discovery
   convenience — useful for mapping the engine's full API surface but
   not needed for runtime execution).

For a first PR / first compile, option 3 keeps complexity low. The
hijack can be added later without disturbing the rest of the file.

## Acknowledgements

- **u/Kunster_** on r/MercenariesGames for [this post](https://www.reddit.com/r/MercenariesGames/comments/1ufm2d1/mercenaries_2_pc_cheat_menu/)
  describing the Lua registration-table patch technique — pointing
  the upstream project at hooking `luaL_register` to intercept
  `print` is what made the bridge possible in the first place.
- The **mercs2-qol-mods** authors for the SDK this mod plugs into.
- **Tsuda Kageyu** for MinHook (vendored by the SDK, BSD-2-Clause).

## License

MIT — same as the upstream Merc2Reborn project.
