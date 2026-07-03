# Changelog

All notable changes to the Mercenaries 2 Experimental Mods project will be documented in this file.

## [v0.1.6] - 2026-07-03

Only `lua-bridge-DEV` bumped this release (0.1.5 → 0.1.6). `debug-overlay-DEV` and `multiplayer-restore-DEV` stay at 0.1.5 — the modkit downloads each mod's assets from the release matching that mod's own `version` field, so leaving them alone is truthful and reflects that nothing about them changed.

### Added (lua-bridge)

Extensive `Loader.*` namespace additions turning the bridge into a full keyboard / focus API surface. Discovered adequate for co-op text chat via an adversarial capture test — see the notes at the bottom.

- **`Loader.GetKeyboardState()`** — returns a 256-byte string; each byte's high bit is set iff the corresponding virtual-key code is currently pressed. Backed by `GetAsyncKeyState` (system-wide physical state, not thread-message-queue). Consume with `string.byte(s, vk + 1)`.
- **`Loader.IsKeyDown(vk)`** — beginner-friendly single-key predicate. Boolean return.
- **`Loader.PopKeyEvents()`** — press-order event queue. Backed by a dedicated **~60 Hz C-side sampler thread** and a **128-slot ring buffer**, so a poll-once-per-frame client never misses a keystroke to timing. Returns a string of raw VK bytes; empty when idle. **Focus-gated**: keystrokes typed while the game process is not the foreground window are silently dropped, so co-op chat mods don't accidentally capture Discord messages.
- **`Loader.ClearKeyEvents()`** — explicit ring reset. Meant to be called at the moment a chat input opens so the first `PopKeyEvents()` after that returns only what the user typed *since*.
- **`Loader.IsGameFocused()`** — boolean; true iff the foreground window belongs to the game process. Uses process-ID match so it works across window styles (borderless, fullscreen, multi-window).

### Changed (lua-bridge)

- **REPL rx buffer bumped 4 KB → 64 KB.** A Lua chunk with any single line longer than 4096 bytes silently wedged the receive loop (server `recv`'d 0 more bytes, then closed the connection). Found by the stress harness's big-chunk test. 64 KB comfortably covers realistic line lengths.

### Notes for consumers

- `Loader.Printf` and `Tcp.Send` are each **several milliseconds per call** (~5 ms and ~15 ms respectively — the former's cost is Windows Defender scanning `.log` writes, the latter's is localhost TCP handshake + `TIME_WAIT` per fresh socket). **Do not call inside per-frame Lua loops** — ~150/sec saturates a full 60 FPS frame. Both are fine for occasional use.

## [v0.1.5] - 2026-07-01

### Added
- **Self-healing `.ini` in all three mods.** Each `.asi` now writes a commented default `.ini` next to itself on first launch if none is present. Users can drop the `.asi` alone and get an editable, fully-annotated config without hunting down the accompanying file. Existing `.ini` files are never overwritten — the check is a plain `fopen("r")` first-pass. A `[*] <mod>: wrote default ...` line is emitted to the mod's log when the file is generated so the behavior is visible.

### Removed
- **`multiplayer-restore-DEV`: cert-blindfold and clock-spoof hooks.** Live testing on the current cracked binary confirmed the FESL CA pubkey patch alone is sufficient for the private server's cert chain to validate — the `WinVerifyTrust` return-`ERROR_SUCCESS` hook and the Win32/CRT clock spoof (pinning time to 2012-06-15) were experimentation-era belt-and-braces layers. Both are now gone, along with their `hook_cert`, `hook_time`, and `spoof_clock` INI keys, all associated typedefs / detour functions / static originals, and the `-lwintrust` link dependency. Binary size dropped ~2.5 KB. The DNS redirect (`hook_dns`), FESL CA key patch (`patch_ca`), and b-version patch (`patch_bversion` / `bversion`) are unchanged. A short "Historical note" paragraph was left in the source header explaining why the hooks aren't there anymore, so future contributors reading git blame have the context.

## [v0.1.4] - 2026-07-01

### Added
- **Global `Loader.Printf` Lua function** — writes lines to a dedicated `lua_loader_printf.log` next to the .asi. Intended as a low-noise replacement for the engine's `Debug.Printf`, which is called thousands of times per frame from stock scripts and drowns out custom-script output. Exposed on the `Loader` global via the same custom register-argument ABI used for `Tcp.Send`.
- **`perf_monitor.lua` OnKey script** — press F5 to toggle a perf HUD on the debug-overlay showing post-GC Lua memory (`collectgarbage("count")`) and a refresh counter. Snapshot-per-press; press F5 again for a new reading or to hide.

### Fixed
- **`_G` wipe recovery** — the engine clears `_G` on some game-state transitions (menu → mission, cutscene entry, etc.), which previously wiped both `Tcp` and `Loader` permanently until game restart. The bridge now re-registers both libs at the start of every pump batch (`luaL_register` is idempotent), so state transitions can no longer strand the globals.
- **`Loader.Printf` stall** — dropped the per-call `FlushFileBuffers`, which was forcing a synchronous disk sync on the game's Lua thread and could freeze the bridge for seconds on slow disks / cloud-synced folders.

### Changed (performance)
- **`CaptureL` seen-set fast-path** — the seen-set pointer scan now runs *before* `LooksLikeLuaState`. When the engine flips back to a VM we've already registered (dozens–hundreds of times/sec), we skip 4× `VirtualQuery` syscalls in favor of a small L1-resident pointer compare. Biggest concrete hot-path win.
- **Single `g_hotWork` gate in `GatedPump`** — replaces 4 volatile loads + compares with one. Steady-state detour cost drops to a single volatile-load + short-circuit return.
- **Register once per pump batch** — `PumpQueue` now calls `RegisterTcpLib` / `RegisterLoaderLib` at the top of the batch rather than per chunk. A 20-chunk drain goes from 40 register calls to 2, without losing the `_G`-wipe defence.
- Register-log lines gated to first-fire-only so repeated re-registrations don't spam `lua_bridge_DEV.log`.

## [v2.0.0] - 2026-06-29

### Added
- **Global `Tcp.Send` Telemetry:**
  - Implemented standard WinSock client connections dynamically registered into the global `Tcp` namespace.
  - Used GCC x86 inline assembly to call the game's custom register-argument `luaL_register` ABI (`ECX=L`, `EAX=libname`, `[esp+4]=table`) at startup.
  - Added loopback security restriction preventing outgoing network connections outside the `127.0.0.0/8` IP space to protect user security.
- **Native Lua Loader:**
  - Auto-creates loading directories: `scripts/OnBoot`, `scripts/OnLoad`, and `scripts/OnKey`.
  - Scans directories recursively, supporting drop-in folders of scripts.
  - Auto-generates `lua_loader.ini` with execution priority levels and virtual key references.
- **Boot-Time & Level-Load Script Triggers:**
  - `OnBoot` folder executes immediately on VM capture.
  - `OnLoad` folder triggers safely when loading screen fades out (milestone `"GlobalExit - Complete"`), preventing main-thread engine crashes.
- **Thread-Optimized `OnKey` Loader:**
  - Spawns a background listener thread polling hotkeys at 30Hz using `GetAsyncKeyState`.
  - Offloads slow disk file I/O to the background thread to prevent frame stutters.
  - Queues loaded scripts safely to the main thread via thread-safe queue injection.
  - Supports script-defined default hotkeys (`local KEYVAL = "keyname"`) on first 10 lines of files.

### Changed
- Removed high-frequency socket server connect/disconnect logs from `lua_bridge.log` to prevent log bloat.
