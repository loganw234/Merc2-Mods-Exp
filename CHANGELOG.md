# Changelog

All notable changes to the Mercenaries 2 Experimental Mods project will be documented in this file.

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
