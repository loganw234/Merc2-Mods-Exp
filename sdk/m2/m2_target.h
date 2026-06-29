/* m2_target.h — binary-specific addresses for the target Mercenaries 2 EXE.
 *
 * All hardcoded VAs live here so there is ONE place to retarget if the executable
 * changes. Verified against the cracked retail EXE (53,482,288 bytes, image base
 * 0x00400000) — see the mercenaries-game RE notes.
 */
#ifndef M2_TARGET_H
#define M2_TARGET_H

/* Section layout (image base 0x00400000). */
#define M2_RDATA_START_VA   0x00B05000u
#define M2_RDATA_SIZE       0x000F1000u
#define M2_TEXT_START_VA    0x00401000u
#define M2_TEXT_SIZE        0x00703000u

/* Shared no-op log stub (33 C0 C3 = xor eax,eax; ret). ~700 stripped log fns —
 * including Lua print / Debug.Printf — funnel through here. MinHooking this one
 * .text site captures the entire log stream and is SecuROM-safe (a .rdata reg-slot
 * patch trips anti-tamper; see tools/pmc_blackbox/lua_log_hook.c). */
#define M2_LOG_STUB_VA      0x006D5640u

/* VO Lua bindings (native code). CERTAIN per docs/lua_engine_bindings_audit.md. */
#define M2_VO_CUE_VA                0x005E9DE0u
#define M2_VO_CUEWITHOUTSUBS_VA     0x005E9F40u

#endif /* M2_TARGET_H */
