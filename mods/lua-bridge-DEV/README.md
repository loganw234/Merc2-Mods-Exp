# lua-bridge (mercs2-qol-mods port)

Exposes Mercenaries 2's statically-linked Lua 5.1.2 runtime via a localhost TCP REPL on `127.0.0.1:27050`, allowing arbitrary Lua chunks to be executed against the live engine state. It also features a thread-optimized Lua script loader supporting boot-time, level-load, and hotkey-triggered scripts.

Ported from [loganw234/Mercenaries2](https://github.com/loganw234/Mercenaries2) to the [mercs2-qol-mods SDK](https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).

> [!TIP]
> **Ready-to-drop script samples, per-function reference docs, and deep-dive tutorials all live on the wiki: [wiki.mercs2.tools](https://wiki.mercs2.tools).**
> The mod ships with the runtime only — no sample `.lua` files in the zip (so an auto-updater can't wipe your custom scripts alongside ours). Grab any samples you want from the wiki.

> [!NOTE]
> Tested and verified working against **`v0.2.0` of the `pmc_bb.dll` loader** (the Mercenaries Fan Build loader).

---

## Features

### 1. The REPL Socket Server
Exposes a localhost socket interface. When a client connects to `127.0.0.1:27050` and sends a Lua chunk terminated with the line `<<<RUN>>>`, the chunk is queued and executed on the next game engine frame, returning the results back over the socket followed by `<<<END>>>`.

### 2. Global `Tcp.Send` Telemetry
Registers a global `Tcp` namespace containing `Tcp.Send(host, port, msg)`.
*   **ABI Hijack:** Implemented the custom calling convention of the game's `luaL_register` (`ECX = L`, `EAX = libname`, `[esp+4] = table`, caller cleans 4 bytes) using inline GCC assembly.
*   **Localhost Security Restriction:** Enforces loopback-only connections (`127.0.0.0/8` IP space). Attempts to communicate with external hosts are blocked for security.

### 3. Global `Loader.*` Namespace
Registers a `Loader` namespace with utility functions available to any script or REPL chunk. Registered via the same custom-ABI `luaL_register` path as `Tcp.Send`, and re-registered on every pump batch so `_G` wipes across game-state transitions don't strand the globals.

*   **`Loader.Printf(msg, ...)`** — appends a line to `lua_loader_printf.log` next to the .asi. Low-noise alternative to the engine's `Debug.Printf`, which fires thousands of times per frame from stock scripts.
*   **`Loader.GetKeyboardState()`** — 256-byte string, one byte per virtual-key code, high bit set iff currently pressed. Read with `string.byte(s, vk + 1)`. Uses `GetAsyncKeyState` (system-wide physical state), not the thread-message-queue-based Win32 `GetKeyboardState`.
*   **`Loader.IsKeyDown(vk)`** — beginner-friendly single-key predicate. Returns a boolean. Wraps one `GetAsyncKeyState` call.
*   **`Loader.PopKeyEvents()`** — returns a string of raw VK bytes (one byte per event, in press order) for every up→down edge observed since the last call. Filled by a dedicated ~60 Hz C-side sampler thread into a 128-slot ring buffer, so a poll-once-per-frame client never misses a keystroke to timing. Empty string when idle. **Focus-gated**: keystrokes are silently dropped when the game process is not the foreground window, so mods (co-op chat, rebind UIs, debug consoles) don't accidentally capture keystrokes typed into other apps.
*   **`Loader.ClearKeyEvents()`** — drops every buffered event without returning them. Use as an explicit reset when opening a chat input or key-rebind capture.
*   **`Loader.IsGameFocused()`** — returns a boolean; true iff the foreground window belongs to the game's process. Uses process-ID match so it works regardless of window style (borderless, fullscreen, multi-window).

> [!IMPORTANT]
> **Do not call `Loader.Printf` or `Tcp.Send` inside per-frame Lua loops.**  
> Each `Loader.Printf` costs ~5 ms under Windows Defender (write-intercept scanning). Each `Tcp.Send` costs ~15 ms (localhost TCP handshake + TIME_WAIT). A `for i=1,60 do Loader.Printf(...) end` in a 60 FPS update loop will saturate the frame budget. Both are fine for occasional use — REPL results, one-shot HUD updates, event-triggered logging.

### 4. Native Script Loader
Recursively scans for and runs scripts dropped into three folders under `<game>/scripts/`. **Sample scripts and pattern references are on the wiki at [wiki.mercs2.tools](https://wiki.mercs2.tools).**

#### 📁 `scripts/OnBoot/`
*   Executed immediately on the main thread when a valid Lua state (`L`) is first captured.
*   Ideal for early-stage memory overrides, variable initialization, or library overrides.

#### 📁 `scripts/OnLoad/`
*   Executed on the main thread as soon as the level loader completes (milestone `"GlobalExit - Complete"`), signaling control has returned to the player.
*   Safe for hud modifications, spawning entities, or starting telemetry loops.

#### 📁 `scripts/OnKey/`
*   **Background Thread Polling:** Spawns a dedicated native background thread (`LoaderKeyThread`) that polls hotkeys at 30Hz using `GetAsyncKeyState`.
*   **I/O Offloading:** The background thread opens and reads `.lua` scripts into memory, offloading slow disk reads from the game's main thread to prevent frame stutters.
*   **Multiple Script Bindings:** Hotkeys are resolved per-script (using `was_down` edge tracking), allowing multiple scripts to be bound to the same key.
*   **Metadata Declared Bindings:** Scripts can declare their default hotkey by specifying `local KEYVAL = "keyname"` on the first 10 lines.

---

## Configuration

### Mod Configuration (`lua_bridge.ini`)
Configures the REPL server bindings and the loader switches:
```ini
[repl]
host = 127.0.0.1       ; bind address (localhost only for security)
port = 27050           ; REPL server port

[loader]
loader_enabled = 1     ; master script loader switch
loader_onboot = 1      ; enable OnBoot script directory
loader_onload = 1      ; enable OnLoad script directory
loader_delay_ms = 50   ; delay (ms) between consecutive script loads
```

### Script Loader Bindings (`lua_loader.ini`)
Auto-generated in `<game>/scripts/` on first run. Lists the execution priority order and hotkeys:
```ini
; lua_loader.ini — Lua Script Loader Configuration
; Define execution order for [OnBoot] and [OnLoad] (lowest numbers load first)
; Define hotkey triggers under [OnKey] (e.g. script.lua = F1 or script.lua = insert)
;
; Virtual Key codes reference: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
; Common keys: insert, delete, home, end, pageup, pagedown, space, enter, escape, F1..F12, A..Z, 0..9

[OnBoot]
print_boot.lua = 10

[OnLoad]
print_load.lua = 10

[OnKey]
test_key.lua = insert
```

---

## Install

1. Drop the built `lua_bridge.asi` and `lua_bridge.ini` into your game's `scripts/` folder.
2. Launch the game using `pmc_bb.dll` (or any compatible ASI loader).
3. Connect with a console client (e.g. `py tools/lua_console.py`).

## Build

```sh
cd mods/lua-bridge
make STRIP_MINGW=strip
```

Output: `lua_bridge.asi`.

---

## Acknowledgements

- **u/Kunster_** on r/MercenariesGames for describing the Lua registration-table patch technique.
- The **mercs2-qol-mods** authors for the SDK this mod plugs into.
- **Tsuda Kageyu** for MinHook (vendored by the SDK, BSD-2-Clause).

## License

MIT
