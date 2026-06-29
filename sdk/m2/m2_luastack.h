/* m2_luastack.h — safe argument reads off a Lua 5.1 (32-bit, float-number) stack.
 *
 * Mercenaries 2 ships the float-number Lua 5.1 build: TValue is 8 bytes
 * { u32 value; u32 tt }, lua_State->top @ +0x08, ->base @ +0x0C. These helpers
 * resolve a C function's argument range and read string arguments with full
 * bounds checking (every dereference is VirtualQuery-guarded), so a malformed or
 * non-Lua caller yields a safe failure rather than a fault.
 *
 * Ported from tools/pmc_blackbox/lua_log_hook.c (the proven, crash-survivable
 * reader used to capture the game's stripped log stream).
 */
#ifndef M2_LUASTACK_H
#define M2_LUASTACK_H

/* Number of arguments on L's current C-function frame, or -1 if the stack looks
 * invalid (used as a cheap "is this really a lua_State?" check). */
int m2_lua_nargs(void* L);

/* Copy argument `idx0` (0-based) into `out` IF it is a Lua string. Returns the
 * length copied, or 0 if the arg isn't a string / stack is invalid. */
int m2_lua_arg_string(void* L, int idx0, char* out, int out_max);

/* Join every string-typed argument into `out`, tab-separated (mirrors how the
 * game's print/Debug.Printf line reads). Returns the count of string args joined,
 * or -1 if the stack is invalid. */
int m2_lua_join_strings(void* L, char* out, int out_max);

#endif /* M2_LUASTACK_H */
