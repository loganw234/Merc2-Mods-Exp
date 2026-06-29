# dev-cheat-menu

A quality-of-life ASI mod for **Mercenaries 2: World in Flames** that opens the developer cheat menu when a configured key (default: `Insert`) is pressed.

> [!NOTE]
> Tested and verified working against **`v0.2.0` of the `pmc_bb.dll` loader** (the Mercenaries Fan Build loader).

## How it works

This mod does not interact directly with the game engine's Lua state. Instead, it listens for a key press and sends the cheat menu activation script over TCP to the **[lua-bridge](../lua-bridge/)** REPL server. 

> [!IMPORTANT]
> **Dependency**: This mod requires the `lua-bridge` mod to be active and running on the configured port (default `27050`) to function.

## Configuration (`dev_cheat_menu.ini`)

The configuration file must be placed in the same directory as the `.asi` plugin (e.g. `<game>/scripts/`).

```ini
[repl]
host = 127.0.0.1   ; bind address of the lua bridge
port = 27050       ; port of the lua bridge

[key]
key = insert       ; trigger key. Can be a name like "insert", "delete", "home",
                   ; a hex code (e.g., "0x2D"), or decimal virtual-key code (e.g., "45").
```

## Build

To compile the mod, run the following from this directory:

```sh
make
```

Or from the root of the workspace:

```sh
make mods/dev-cheat-menu
```

## Installation

1. Copy `dev_cheat_menu.asi` and `dev_cheat_menu.ini` to your game's `scripts/` directory.
2. Ensure `lua_bridge.asi` and `lua_bridge.ini` are also in your `scripts/` directory and active.
3. Start the game. Press the **Insert** key in-game to open the developer cheat menu.

## Credits

- **u/Kunster_** on r/MercenariesGames for finding the Lua script/sequence to open the developer cheat menu.
