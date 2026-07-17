# Changelog

All notable changes to the Mercenaries 2 Experimental Mods project will be documented in this file.

## [v0.4.0] - 2026-07-17

Only `lua-bridge-DEV` bumped (0.3.1 → 0.4.0). Version-family boundary: `v0.4` adds a **WebSocket transport** alongside the existing raw-TCP one, which unlocks a whole new class of client — a browser can now connect directly to the live game and drive Lua without a Python/PowerShell relay in the middle. Also adds a new Lua function for pushing values back out on a hidden channel.

### Added

- **WebSocket transport.** The same listener (`127.0.0.1:27050` by default) now speaks either raw TCP (the existing `lua_repl.py` / `lua_console.py` protocol) or WebSocket, auto-detected from the first bytes of each connection. Peek for `GET ` → WebSocket handshake (RFC 6455, SHA-1 via BCrypt + base64 via `CryptBinaryToStringA` — no vendored crypto); anything else falls through to the raw-TCP path unchanged. Wire contract is JSON text frames:
  ```
  client -> bridge   {"id":"q17abc","code":"<lua source>"}
  bridge -> client   {"type":"ack","id":"q17abc","status":"queued"}
  bridge -> client   {"type":"log","line":"…a Loader.Printf line…"}
  bridge -> client   {"type":"ws","line":"…a Loader.WsSend line…"}
  ```
  One WS message = one request. Ack is immediate (socket thread, deterministic). Log and WsSend feeds mirror in real time. Ping/pong and close frames are handled per spec. Frame sizes up to 1 MB per message, matching the raw-TCP chunk cap. Reference browser client lives in [`mercs2-lua-essentials/tools/ess-bridge.js`](https://github.com/loganw234/mercs2-lua-essentials).
- **`Loader.WsSend(str, …)`** — a new Lua global that broadcasts each call as `{"type":"ws","line":"…"}` to the connected WebSocket client **and never writes the log file**. Same join semantics as `Loader.Printf` (tab-separated string args). This is the "hidden channel" — REPL result plumbing (tagged nonces from the client-side wrapper) rides it without polluting `lua_loader_printf.log`, and mods can stream telemetry to a browser page without dumping it into the log too. No-op when no WS client is connected, so scripts that call it under raw-TCP or offline are harmless.
- **INI toggle** `websocket_enabled = 1` (default on). Rollback lever — set to 0 to disable the WS transport entirely and lock the listener to raw-TCP only.

### Changed

- `Loader.Printf` still writes to `lua_loader_printf.log` exactly as before, but now also mirrors each line to the connected WS client as `{"type":"log","line":"…"}`. This is the browser's "live console feed." Raw-TCP behavior is unaffected — Printf never wrote to that path in the first place, and doesn't now.

### Fixed

- **Cross-session `g_outBuf` leakage.** The single-client output buffer used by the raw-TCP path could carry stale content from a previous session — most commonly the executor's `result_buf` for a chunk a WS client queued and then disconnected before its pump run. A fresh raw-TCP client's first read would then contain that stale result before its own `[queued]` ack. Now cleared at accept-time on every new raw-TCP session and drained continuously during WS sessions, so no output can survive across session boundaries.

## [v0.3.1] - 2026-07-15

Only `lua-bridge-DEV` bumped (0.3.0 → 0.3.1). Watchdog reliability patch — no user-facing API changes.

### Fixed

- **Watchdog now detects "hung inside a native call from Lua."** Previously the watchdog's `since_detour > 2000` guard — meant to distinguish a genuine stall from a legitimate pause — silently misfired in the very case it existed to catch. When a queued script called into native code that never returned (e.g. `SetSwfFile()` on a wedged D3D device, an infinite `while true do end`), the game thread was blocked, so no more of our hooked detours could fire. After 2 seconds the watchdog treated the hang as "game paused" and bailed. This is the specific pattern users reported as "bridge queue stops draining, only PC restart fixes it."
- **New detection path.** A separate `g_bridgeExecStartTick` tracks when the pump entered `LuaDoString`. If it stays set for longer than the stuck threshold, the watchdog fires regardless of detour activity — because being inside exec proves the pump was active. Logged as `pattern: in-bridge-exec-not-returning (native call from Lua hung)` with `exec_elapsed=Xms` for post-mortem.
- **Boot-time timestamp seeding.** `g_lastDetourFireTick`, `g_lastPumpAttemptTick`, and `g_lastPumpProgressTick` are now initialized to `GetTickCount()` before the watchdog thread starts, instead of BSS-zero. Prevents `since_progress = GetTickCount()` (a huge number) on the first wake, which could produce incoherent diagnostics in edge cases.
- **What this fixes and doesn't fix.** When the game thread eventually recovers (driver unblocks, native call completes late), the reset means the next pump entry finds a clean bridge state — fresh `g_LuaState`, cleared `g_seenL`, `t_inBridgeExec` force-cleared — instead of a permanently jammed queue. The bridge cannot forcibly unstick a hung native call from a different thread; if the game process is genuinely dead, only a restart helps. But the failure mode is now recoverable rather than fatal, and the diagnostic log clearly identifies which of three stuck patterns fired.

## [v0.3.0] - 2026-07-09

Only `lua-bridge-DEV` bumped (0.2.2 → 0.3.0). Version-family boundary: `v0.1` had no math library, `v0.2` reached stock Lua math parity, `v0.3` adds **persistence** — the first user-facing capability that lets script authors do things previously impossible on this platform (survive a game restart with saved state). Also bundles a meaningful hot-path perf improvement to the input functions.

### Added

- **`Loader.SaveVar(sKey, xValue)` / `Loader.LoadVar(sKey)`** — simple key-value persistence for numbers, strings, and booleans. Values survive game restarts. Stored on disk as `lua_loader_data.ini` next to the `.asi` in a human-readable format that users can hand-edit while the game is offline:
  ```
  ; Format: key=type:value  (n=number, s=string, b=boolean 0/1)
  MasterCheatMenu_Progress=n:18
  MyMod_TutorialSeen=b:1
  MyMod_Setting=s:hardcore
  ```
  - **Types preserved** across the round trip — `Loader.SaveVar("count", 5)` then `Loader.LoadVar("count")` returns the number `5`, not the string `"5"`. Same for booleans and strings.
  - **Nil for missing keys** — `Loader.LoadVar("does_not_exist")` returns `nil`, standard Lua idiom for defaults: `local x = Loader.LoadVar("progress") or 0`.
  - **Atomic writes** — each save writes to `lua_loader_data.ini.tmp` then `MoveFileExA(MOVEFILE_REPLACE_EXISTING)`. A crash mid-write can't leave a truncated file.
  - **Flat namespace** — a single global namespace shared by all scripts. Convention (documented on the wiki): prefix your keys with your script's name (`MyMod_progress` not `progress`) to avoid collisions with other mods.
  - **String semantics**: each `SaveVar` with a string value allocates a fresh `TString`; the previous value's string stays valid for any Lua variable still holding a reference to a prior `LoadVar` result. Memory grows with write frequency (1000 writes × 100 chars ≈ 100 KB), bounded and acceptable for a game session.

### Changed (perf)

- **Fast-path input functions**: `Loader.IsKeyDown`, `Loader.GetKeyboardState`, `Loader.PopKeyEvents`, `Loader.IsGameFocused`, and every `math.*` function had 6+ `VirtualQuery` syscalls of defensive validation on the hot path (`LooksLikeLuaState` + individual `SafeProbe` on base and top). Removed — when Lua's own dispatch calls a `luaL_register`-installed C function, `L`/`base`/`top` are engine-guaranteed valid, and the `LUA_MINSTACK` reservation covers the one-slot push. **Hot-path cost drops from ~15 µs to ~0.81 µs per call** (measured: 500,000 `IsKeyDown` calls in 404 ms of isolated execution time, ~1.24 M calls/sec). A script can now safely call `Loader.IsKeyDown(vk)` 20,000 times per frame at 60 FPS while using <2% of the frame budget.

  Defensive checks retained on `Loader.Printf` and `Tcp.Send` — those are I/O-bound anyway, so the check cost is noise there.

### Notes for consumers

- `Loader.IsKeyDown` and its siblings now officially carry a **"safe in hot loops"** guarantee — the previous implicit assumption is now backed by measured data. The wiki page notes will be updated to reflect that.
- The `math.*` functions got the same fast-path treatment via the `MATH_ONEARG` / `MATH_TWOARG` macros, so `math.sin`/`math.cos`/etc. also drop to ~sub-µs per call. Also safe in per-frame loops.

### Verification

- `SaveVar`/`LoadVar` round-trip: **10/10** across number, string, boolean, missing-key, type-preservation, overwrite, and newline-escape cases.
- On-disk file format: verified human-readable, hand-editable, correct atomic replace.
- `IsKeyDown` throughput: measured **~0.81 µs/call**, **~1.24 M calls/sec**.
- Full stress suite (15 phases): **15/15 pass**, no regressions.
- Watchdog: armed once at boot, fired 0 times through the full session — no false positives from either the new subsystem or the fast-path changes.

## [v0.2.2] - 2026-07-06

Only `lua-bridge-DEV` bumped (0.2.1 → 0.2.2). Defensive addition: a background watchdog that self-heals the bridge from silent stuck-state conditions users have occasionally reported. No new user-facing features, no behavior changes to any hot path — the watchdog stays completely dormant unless it detects a real problem.

### Added

- **Bridge self-healing watchdog.** A dedicated background thread that wakes every ~2 seconds and, if the queue has pending chunks AND the game is running detours AND no pump progress has happened for `watchdog_stuck_ms` (default **8000**), force-resets the bridge's stuck-state candidates and logs a comprehensive diagnostic line. Reset actions: `hotWork = 1`, signal `PumpQueue` to clear its per-thread `t_inBridgeExec` flag (via a compare-exchange handshake), null out `g_LuaState`, memset the seen-L cache to zero. Next detour fire cleanly re-captures and pump resumes — no reboot required. Configurable via `watchdog_stuck_ms` in `lua_bridge_DEV.ini`; set to 0 to disable.
- **Three cheap timestamp probes** feeding the watchdog's decision logic: `g_lastDetourFireTick` (updated by every detour), `g_lastPumpAttemptTick` (updated when `GatedPump` enters its slow path), `g_lastPumpProgressTick` (updated after every successful chunk drain). Each is a single volatile store per event; measured cost: unmeasurably small, no fast-path impact.

### Diagnostic

When the watchdog fires, it logs four lines that describe exactly which stuck pattern was seen — one of two categories are distinguishable:
- `hotWork-stuck-at-0` (GatedPump never enters slow path) — the ms-since-slowpath timestamp reveals this
- `PumpQueue-not-draining` (t_inBridgeExec stuck TRUE, or LooksLikeLuaState failing on stale L) — slowpath is being attempted but no progress

Users seeing repeated `WATCHDOG` fires in their `lua_bridge_DEV.log` should send those lines upstream so we can finally diagnose the root cause of the intermittent stalls that motivated the watchdog. The self-heal is a safety net, not a fix — every fire indicates a real bug we still want to eventually eliminate.

### Notes

- `g_seenL[8]` was refactored from a `static` local inside `CaptureL` to file-scope so the watchdog can reset it directly. No behavioral change; same array, same lookup semantics.
- Cool-down of `stuck_ms / 2` between resets prevents the watchdog from hammering on a still-stuck bridge.
- Full stress suite (15 phases) run against this build: 15/15 pass, watchdog fired 0 times during 17s of aggressive stress including 256 KB chunks, 200-chunk queue floods, TCP-send bursts, and 1000-call Loader.Printf loops. No false positives observed under realistic load.

## [v0.2.1] - 2026-07-05

Only `lua-bridge-DEV` bumped (0.2.0 → 0.2.1). Stability / correctness patch focused on OnKey reentrancy protection and two small polyfill nits caught in the v0.2.0 code review.

### Added

- **Per-script OnKey cooldown.** Rapid double-presses of the same hotkey were queueing two back-to-back runs of a script; sequential (not concurrent) execution, but many gameplay scripts aren't reentrant and the second run running on state the first left behind could destabilize the engine. `LoaderKeyThread` now tracks `last_fired_tick` per script and skips re-firing if the last fire was within `loader_onkey_cooldown_ms` (default **250 ms**). The first throttle per script per session logs `[!] lua_bridge: OnKey '<key>' throttled (...)` so users notice the cooldown is engaging; subsequent throttles are silent to avoid log spam. Set `loader_onkey_cooldown_ms = 0` in `lua_bridge_DEV.ini` to disable. Fully compatible with `GetTickCount` wraparound (~49.7-day cycle) via unsigned subtraction.

### Fixed

- **`assert` error message location.** The polyfill's `error(msg or 'assertion failed!')` used the default level (1), which pointed error messages at the polyfill chunk (`[string "if math then..."]:1: bad msg`) instead of at the caller of `assert(...)`. Now uses `error(..., 2)` to skip the assert function frame — error messages now report the caller's location, matching stock Lua semantics. Critical for anyone debugging scripts with real error messages.
- **Polyfill success log is honest.** Previously logged `[*] polyfill applied ...` unconditionally, even if `LuaDoString` returned a compile error or internal bridge failure. Now checks the result buffer for `[compile]` or `[bridge]` prefixes and logs `[!] polyfill FAILED to apply: ...` in those cases. Prevents future silent breakage from hiding behind a misleading success line.

### Notes

`lua_loader.ini` still does not auto-prune stale script entries when the corresponding `.lua` file is deleted — this remains intentional (a moved `.lua` returning to its folder should keep its binding). If a specific user report shows the ini growing unmanageable, we'll add an opt-in `loader_prune_stale_ini` flag then.

## [v0.2.0] - 2026-07-05

Only `lua-bridge-DEV` bumped this release (0.1.6 → 0.2.0). The version-family jump (0.1.x → 0.2.x) reflects that the Lua environment inside the game has grown from "a bridge you can send chunks to" into a **usable general-purpose Lua runtime**. AI-assisted script authors can now reach for `math.sqrt`, `math.pi`, `assert(x, msg)`, `math.random`, etc. and have them just work — the stripped stdlib is no longer a papercut on every fresh script.

`debug-overlay-DEV` and `multiplayer-restore-DEV` stay at 0.1.5. Both are stable; nothing about them changed.

### Added

**Full Lua stdlib parity for math and assert** — a stdlib-completeness probe (run against the live game) identified 19 missing math functions and one critical missing base function. All are now available:

- **`math.sin`, `math.cos`, `math.tan`** — trig (`sin`/`cos` shipped in v0.1.6; `tan` new here)
- **`math.asin`, `math.acos`, `math.atan`, `math.atan2`** — inverse trig
- **`math.sinh`, `math.cosh`, `math.tanh`** — hyperbolic
- **`math.sqrt`, `math.log`, `math.log10`** — the ones AI-generated scripts reach for constantly
- **`math.fmod`, `math.ldexp`, `math.modf`, `math.frexp`** — the low-level number-manipulation set
- **`math.random(...)`, `math.randomseed(x)`** — matches stock Lua 5.1 semantics (`random()` / `random(n)` / `random(m, n)` all supported)
- **`math.pi`, `math.huge`** — constants, injected via a Lua polyfill chunk since `luaL_register` only takes functions
- **`assert(v, msg)`** — polyfilled in Lua on top of the engine's existing `error`. Idempotent (`if not _G.assert then`), re-applied on every pump batch so `_G` wipes don't strand it

All backed by the C stdlib's single-precision routines with the same `SafeProbe` + type-tag safety wrapping used across the rest of the file. Registered via the custom-ABI `luaL_register` path, additive to the engine's existing `math.floor` / `math.abs` / `math.max` / `math.min` / etc.

### Fixed

**`LoaderKeyThread` file-exists guard.** Pressing a hotkey whose backing `.lua` file had been deleted after game boot could destabilize the game. `GetFileAttributesA` now runs before every `fopen`; missing files log a clear warning line (`[!] lua_bridge: OnKey '<key>' bound to missing file: <name> (skipped)`) and are safely skipped.

### Changed

**Release workflow no longer ships sample scripts in the packaged zip.** When a user updates the mod through the modkit and the modkit's update logic does a clean-and-reinstall (as opposed to a diff-and-patch), any user-authored `.lua` files sharing the same `OnBoot/`, `OnLoad/`, `OnKey/` folders as our samples get wiped alongside them. Stripping the samples from the auto-deployed zip sidesteps that entirely — nothing in those folders belongs to the mod's install list, so the modkit has no reason to touch them. Sample `.lua` files stay in the repo as documentation.

### Documentation

- Wiki pointer ([wiki.mercs2.tools](https://wiki.mercs2.tools)) added to the top-level README and to the lua-bridge README (twice — intro callout and inside the Script Loader section). Users looking for sample scripts, deep-dives, and per-function reference now have one authoritative destination.

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
