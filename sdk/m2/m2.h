/* m2.h — umbrella include for the Mercenaries 2 mod stdlib.
 *
 * A small reusable runtime layer for Mercs2 ASI mods: per-module logging, INI
 * config, SecuROM-safe MinHook detours, safe Lua-stack reads, a shared subscription
 * to the game's log stream, and load-progress triggers keyed to loadprobe's
 * world-load ladder. Link the SDK sources via sdk/sdk.mk.
 */
#ifndef M2_H
#define M2_H

#include "m2_target.h"
#include "m2_log.h"
#include "m2_ini.h"
#include "m2_hook.h"
#include "m2_luastack.h"
#include "m2_loghook.h"
#include "m2_loadtrigger.h"

#endif /* M2_H */
