# Changelog

All notable changes to the Mercenaries 2 Experimental Mods project will be documented in this file.

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
