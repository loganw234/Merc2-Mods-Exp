#include "m2_luastack.h"
#include <windows.h>

/* --- Lua 5.1.2 (32-bit, float number) layout --- */
typedef struct { DWORD value; DWORD tt; } LuaTValue;

#define LUA_STATE_OFF_TOP         0x08
#define LUA_STATE_OFF_BASE        0x0C
#define LUA_STATE_OFF_CI          0x14
#define LUA_STATE_OFF_STACK_LAST  0x1C
#define LUA_STATE_OFF_STACK       0x20
#define CALLINFO_OFF_BASE         0x00
#define CALLINFO_OFF_FUNC         0x04

#define LUA_TSTRING 4
#define TSTRING_DATA_OFF 16   /* string bytes start at TString + 16 (32-bit) */

#define MAX_ARGS 32

/* Bytes safely readable from p within its single committed region (one query). */
static SIZE_T ReadableSpan(const void* p) {
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR region_end;
    if (!p) return 0;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    switch (mbi.Protect & 0xFF) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            break;
        default: return 0;
    }
    region_end = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    if ((ULONG_PTR)p >= region_end) return 0;
    return (SIZE_T)(region_end - (ULONG_PTR)p);
}

static BOOL PtrReadable(const void* p, SIZE_T n) {
    if (n == 0) return FALSE;
    return ReadableSpan(p) >= n;
}

static int CopyTString(DWORD tstring_val, char* out, int out_max) {
    const char* str;
    SIZE_T span;
    int limit, slen;
    if (!tstring_val || out_max <= 1) return 0;
    if (ReadableSpan((void*)tstring_val) < (TSTRING_DATA_OFF + 4)) return 0;
    str = (const char*)((BYTE*)tstring_val + TSTRING_DATA_OFF);
    span = ReadableSpan(str);
    if (span == 0) return 0;
    limit = out_max - 1;
    if ((SIZE_T)limit > span) limit = (int)span;
    slen = 0;
    while (slen < limit && str[slen]) { out[slen] = str[slen]; slen++; }
    out[slen] = '\0';
    return slen;
}

static BOOL StkInRange(LuaTValue* p, LuaTValue* stack, LuaTValue* stack_last) {
    return p && stack && stack_last && stack <= stack_last && p >= stack && p <= stack_last;
}

/* Resolve base/nargs and validate the frame; returns FALSE for non-Lua callers. */
static BOOL ResolveStack(void* L, LuaTValue** out_base, int* out_nargs) {
    BYTE* Lp = (BYTE*)L;
    LuaTValue *top, *base, *stack, *stack_last;
    int nargs;

    if ((ULONG_PTR)L < 0x10000 || ((ULONG_PTR)L & 3)) return FALSE;
    if (!PtrReadable(Lp + LUA_STATE_OFF_STACK, sizeof(LuaTValue*) * 3)) return FALSE;

    top        = *(LuaTValue**)(Lp + LUA_STATE_OFF_TOP);
    base       = *(LuaTValue**)(Lp + LUA_STATE_OFF_BASE);
    stack_last = *(LuaTValue**)(Lp + LUA_STATE_OFF_STACK_LAST);
    stack      = *(LuaTValue**)(Lp + LUA_STATE_OFF_STACK);

    if (!StkInRange(stack, stack, stack_last)) return FALSE;
    if (!StkInRange(top, stack, stack_last)) return FALSE;

    if (!StkInRange(base, stack, stack_last)) {
        /* L->base can be 0 during VM transitions; try ci->func+1 / ci->base. */
        if (PtrReadable(Lp + LUA_STATE_OFF_CI, sizeof(void*))) {
            BYTE* ci = *(BYTE**)(Lp + LUA_STATE_OFF_CI);
            if (ci && PtrReadable(ci + CALLINFO_OFF_FUNC, sizeof(LuaTValue*))) {
                LuaTValue* func = *(LuaTValue**)(ci + CALLINFO_OFF_FUNC);
                if (StkInRange(func, stack, stack_last)) {
                    base = func + 1;
                } else if (PtrReadable(ci + CALLINFO_OFF_BASE, sizeof(LuaTValue*))) {
                    LuaTValue* cb = *(LuaTValue**)(ci + CALLINFO_OFF_BASE);
                    if (StkInRange(cb, stack, stack_last)) base = cb;
                }
            }
        }
    }
    if (!StkInRange(base, stack, stack_last)) return FALSE;
    if (top < base) return FALSE;
    if (((ULONG_PTR)base & 3) || ((ULONG_PTR)top & 3)) return FALSE;
    if (((ULONG_PTR)base - (ULONG_PTR)stack) % sizeof(LuaTValue) != 0 ||
        ((ULONG_PTR)top  - (ULONG_PTR)stack) % sizeof(LuaTValue) != 0) return FALSE;

    nargs = (int)(top - base);
    if (nargs <= 0 || nargs > MAX_ARGS) return FALSE;
    if (!PtrReadable(base, (SIZE_T)nargs * sizeof(LuaTValue))) return FALSE;

    *out_base = base;
    *out_nargs = nargs;
    return TRUE;
}

int m2_lua_nargs(void* L) {
    LuaTValue* base;
    int nargs;
    if (!ResolveStack(L, &base, &nargs)) return -1;
    return nargs;
}

int m2_lua_arg_string(void* L, int idx0, char* out, int out_max) {
    LuaTValue* base;
    int nargs;
    LuaTValue arg;
    if (out_max > 0) out[0] = '\0';
    if (!ResolveStack(L, &base, &nargs)) return 0;
    if (idx0 < 0 || idx0 >= nargs) return 0;
    arg = *(base + idx0);
    if (arg.tt != LUA_TSTRING) return 0;
    return CopyTString(arg.value, out, out_max);
}

int m2_lua_join_strings(void* L, char* out, int out_max) {
    LuaTValue* base;
    int nargs, i, pos = 0, count = 0;
    if (out_max > 0) out[0] = '\0';
    if (!ResolveStack(L, &base, &nargs)) return -1;
    for (i = 0; i < nargs && pos < out_max - 2; i++) {
        LuaTValue arg = *(base + i);
        if (arg.tt != LUA_TSTRING) continue;
        if (count > 0 && pos < out_max - 1) out[pos++] = '\t';
        pos += CopyTString(arg.value, out + pos, out_max - pos);
        count++;
    }
    out[pos < out_max ? pos : out_max - 1] = '\0';
    return count;
}
