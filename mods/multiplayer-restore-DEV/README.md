# multiplayer-restore (mercs2-qol-mods port)

Restores Mercenaries 2 online multiplayer by routing EA matchmaking
traffic to a private server and accepting that server's self-signed
TLS certificate. Drop-in mod for the
[mercs2-qol-mods SDK](https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).

This is a port of the multiplayer layer from
[loganw234/Mercenaries2](https://github.com/loganw234/Mercenaries2),
stripped of the Lua bridge so it cleanly fits the QoL mods framework.

> [!NOTE]
> Tested and verified working against **`v0.2.0` of the `pmc_bb.dll` loader** (the Mercenaries Fan Build loader).

## What it does

1. **DNS redirect** — hooks `ws2_32` resolvers so `*.ea.com`,
   `*.gamespy.com`, and `fesl*` resolve to the configured private
   server (default `refesl.live`).
2. **Cert blindfold** — hooks `wintrust!WinVerifyTrust` to accept the
   private server's self-signed cert blob. Local file/catalog cert
   validation is untouched.
3. **Time spoof** — pins the clock returned by Win32 + CRT time APIs
   to a date inside the served cert's validity window. Optional.
4. **FESL CA pubkey patch** — replays MLoader's 128-byte `.rdata`
   write at RVA `0x768378` so the game's SSL stack accepts the
   private server's cert chain. Gated on a SecuROM-unpack poll.

What it does NOT do: Lua bridge, REPL, modding hooks. Use the
upstream Merc2Fix ASI if you want those.

## Install

1. Build (see below) or drop a prebuilt `multiplayer_restore.asi`
   into your Mercenaries 2 install folder.
2. Drop `multiplayer_restore.ini` alongside it (only needed if you
   want to override the default server or disable the clock spoof).
3. Launch the game. Connect online normally — no MLoader required.

## Build

If this directory lives under `mercs2-qol-mods/mods/`:

```sh
cd mods/multiplayer-restore
make
```

Out-of-tree:

```sh
make SDK_DIR=/path/to/mercs2-qol-mods/sdk
```

Output: `multiplayer_restore.asi`.

## Config (`multiplayer_restore.ini`)

```ini
[server]
ip = refesl.live              ; hostname or dotted-quad

[compat]
spoof_clock = 1               ; 1 = spoof to 2012-06-15 (recommended)
```

## Status

**Fully verified and tested.** Builds cleanly using MinGW (`i686-w64-mingw32-gcc`) and has been fully runtime-tested and verified working on a real game session loaded with `pmc_bb.dll` (v0.2.0). All hooks arm cleanly, the DNS redirect, cert verification bypass, and CA pubkey patch work as expected, restoring online multiplayer connectivity.

## Acknowledgements

- **u/Kunster_** on r/MercenariesGames for ongoing collaboration
  on the Mercenaries 2 modding stack.
- The **mercs2-qol-mods** authors for the SDK this mod plugs into.
- **Tsuda Kageyu** for MinHook (vendored by the SDK, BSD-2-Clause).

## License

MIT — same as the upstream Merc2Reborn project.
