/* lua_bridge.c — exposes Mercenaries 2's statically-linked Lua 5.1.2
 * runtime via a localhost TCP REPL, allowing arbitrary Lua chunks to
 * be executed against the live engine state.
 *
 * Ported from Merc2Reborn's Merc2Fix (https://github.com/loganw234/Mercenaries2)
 * to the mercs2-qol-mods SDK
 * (https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).
 *
 * Pairs with the companion `multiplayer-restore/` mod in this same
 * repo, but is independent: enable one or both via the modkit.
 *
 * What it does:
 *   * Detects which Mercenaries2.exe build is running (canonical retail
 *     vs the mercs2-securom-bypass-patched form) via an FNV-1a
 *     fingerprint, and selects the matching per-binary RVA table.
 *   * MinHook-detours: the shared no-op stub, luaB_type, and
 *     CreateTextWidget. These together capture the live lua_State on
 *     any Lua dispatch and serve as pump sources for queued chunks.
 *   * Hijacks `_G.print` / `_G.next` / `_G.tostring` at registration
 *     time by patching the engine's luaL_Reg table BEFORE the real
 *     luaL_register sees it. The hijacked functions drain the chunk
 *     queue whenever scripts call them — gives high-frequency pump
 *     sources without needing more MinHook detours.
 *   * Phase 3 executor: pushes a hand-crafted TString onto the engine's
 *     Lua stack, calls luaB_loadstring + luaB_pcall directly to
 *     compile + run a chunk, formats the return values, ships them
 *     back over the REPL socket.
 *
 * Listens on 127.0.0.1:27050 by default. Configurable via lua_bridge.ini.
 * Use tools/lua_repl.py or tools/lua_console.py from the parent project
 * for a client.
 *
 * Reverse-engineering notes — verified gotchas baked into this code:
 *   * TValue is 8 bytes here (Pandemic built with lua_Number = float),
 *     not the stock 16. Layout: Value at +0, int tt at +4.
 *   * lua_State packs CommonHeader tightly: L->top at +0x08, L->base
 *     at +0x0C (vs stock +0x0C and +0x10).
 *   * Lua's debug library is stripped; no lua_sethook. Pump from the
 *     captured dispatch sites instead.
 *   * luaB_pcall is non-stock: returns stack-shaped junk at slot 0
 *     instead of a clean bool status. Display-layer handles this.
 *   * The "noop stub" is shared across ~60 names (print, SendEvent_*,
 *     music stubs, _SummonEd, ...). Hooking it captures L from any of
 *     them. C++ engine code also routes through here with `this` in
 *     arg0 — LooksLikeLuaState filters those out.
 *
 * Full background, design rationale, and incident history:
 *   https://github.com/loganw234/Mercenaries2/blob/main/Merc2Fix/dllmain.cpp
 *   https://github.com/loganw234/Mercenaries2/blob/main/tools/lua_api_findings.md
 *   https://github.com/loganw234/Mercenaries2/blob/main/tools/engine_api.md
 */

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>       /* SHA-1 for the WebSocket handshake */
#include <wincrypt.h>     /* CryptBinaryToStringA — base64 for the same */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "m2.h"

/* Compatibility shim: the upstream Merc2Fix uses MSVC's safe-string
 * extensions (_snprintf_s with _TRUNCATE, strncpy_s, strcpy_s).
 * MinGW doesn't ship those; map them to POSIX snprintf / strncpy
 * with manual NUL-termination so the same source compiles under both
 * toolchains. Link with -lws2_32 (see Makefile). */
#ifdef _MSC_VER
  /* MSVC: native safe-string, SEH, and TLS extensions. */
  #define SEH_TRY            __try {
  #define SEH_CATCH_AV(rv)   } __except (EXCEPTION_EXECUTE_HANDLER) { return (rv); }
  #define MOD_THREAD         __declspec(thread)
#else
  /* MinGW: substitute POSIX where possible, skip SEH (no support on
   * GCC x86 — if SafeCallLuaCFunction's target AVs, the game crashes
   * instead of being caught here). _TRUNCATE is already defined by
   * MinGW's _mingw.h as ((size_t)-1); reuse it. */
  #define _snprintf_s(buf, sz, _trunc, ...) snprintf((buf), (sz), __VA_ARGS__)
  #define strncpy_s(dst, dst_sz, src, count) \
      (strncpy((dst), (src), (count)), (dst)[(dst_sz) - 1] = 0, 0)
  #define strcpy_s(dst, dst_sz, src) \
      (strncpy((dst), (src), (dst_sz) - 1), (dst)[(dst_sz) - 1] = 0, 0)
  #define SEH_TRY            do {
  #define SEH_CATCH_AV(rv)   } while (0)
  #define MOD_THREAD         __thread
#endif

/* ======================================================================== *
 * Status: PROOF OF CONCEPT — this port has NOT been built or test-run
 * against the mercs2-qol-mods framework. Drafted without the SDK build
 * environment set up locally. See README.md for what is and isn't
 * validated.
 *
 * The architecture is proven: the upstream Merc2Fix.asi runs cleanly
 * against a mercs2-securom-bypass-patched binary loaded by pmc_bb.dll,
 * with the bridge fully operational. So the surface area below is
 * known-correct; what's untested is the per-SDK-helper mapping
 * (m2_logf vs Log, m2_hook_attach vs MH_CreateHook, m2_ini_parse vs
 * a custom parser) — likely needs adjustments to match this SDK's
 * exact signatures.
 *
 * ONE KNOWN COMPLICATION: the luaL_register hijack requires a "naked"
 * detour to preserve a non-standard register-arg ABI (ECX=L, EAX=libname,
 * stack=table). On MSVC this is a one-paragraph __declspec(naked)
 * function. On the GCC/MinGW toolchain the SDK uses, x86 doesn't
 * support __attribute__((naked)), so this needs to live in a separate
 * .S file with global assembly. The DetourLuaLRegister section below
 * has the MSVC source as a comment block plus the GCC translation
 * sketch. Without this hook the bridge still works — we lose the
 * print/next/tostring hijack and the registration-table dump, but
 * the executor + the other detours keep functioning. Easier to ship
 * v1 without it and add later.
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * Per-binary RVA tables and fingerprint-based selection.
 *
 * The Mercenaries 2 binary ships in multiple flavors. The Lua bridge
 * needs per-binary addresses for the C functions it hooks. We compute
 * an FNV-1a fingerprint over a 4 KB region of .text at startup and
 * select the matching table.
 *
 * To add a new binary: run the static analyzers from the upstream repo
 * (tools/find_lua_print.py, tools/resolve_lua_api.py) against the new
 * exe to derive RVAs; compute the FNV-1a hash of 4 KB at RVA 0x11000
 * to get the fingerprint; add another LuaRvaSet and switch case below.
 * ------------------------------------------------------------------------ */

typedef struct LuaRvaSet {
    const char* label;
    DWORD noop_stub;         /* shared no-op stub: print, SendEvent_*, music, etc. */
    DWORD luaB_type;
    DWORD luaB_loadstring;
    DWORD luaB_pcall;
    DWORD CreateTextWidget;
    DWORD luaL_register;
} LuaRvaSet;

static const LuaRvaSet kRvas_v1_1 = {
    "v1.1 (archive.org English retail)",
    0x002AEF90, /* noop_stub        VA 0x006AEF90 */
    0x00460E90, /* luaB_type        VA 0x00860E90 */
    0x004611E0, /* luaB_loadstring  VA 0x008611E0 (real __cdecl) */
    0x00461810, /* luaB_pcall       VA 0x00861810 (real __cdecl) */
    0x001B7D30, /* CreateTextWidget VA 0x005B7D30 (__fastcall engine binding) */
    0x0045F720, /* luaL_register    VA 0x0085F720 (custom register ABI) */
};

static const LuaRvaSet kRvas_v1_1_bypass = {
    "v1.1 + mercs2-securom-bypass (cracked retail)",
    0x002D5640, /* noop_stub        (moved +0x266B0 vs v1.1) */
    0x00460C70, /* luaB_type        (shifted -0x220) */
    0x00460FC0, /* luaB_loadstring  (shifted -0x220) */
    0x004615F0, /* luaB_pcall       (shifted -0x220) */
    0x001B7D40, /* CreateTextWidget (shifted +0x10) */
    0x0045F500, /* luaL_register    (shifted -0x220) */
};

static const LuaRvaSet* g_rvas = &kRvas_v1_1;

/* FNV-1a 64-bit. Hashes are stable, deterministic, no crypto deps. */
static uint64_t Fnv1a64(const void* data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t* b = (const uint8_t*)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= b[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

/* ------------------------------------------------------------------------ *
 * Memory-safety helpers
 * ------------------------------------------------------------------------ */
static BOOL SafeProbe(const void* p, size_t bytes) {
    const char* addr;
    const char* end;
    const DWORD readable =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const DWORD unreadable = PAGE_NOACCESS | PAGE_GUARD;
    MEMORY_BASIC_INFORMATION mbi;

    if (!p || (uintptr_t)p < 0x10000) return FALSE;
    addr = (const char*)p;
    end  = addr + bytes;
    while (addr < end) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return FALSE;
        if (mbi.State != MEM_COMMIT) return FALSE;
        if (mbi.Protect & unreadable) return FALSE;
        if (!(mbi.Protect & readable)) return FALSE;
        addr = (const char*)mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}

/* ------------------------------------------------------------------------ *
 * Layout constants — verified against the engine
 * ------------------------------------------------------------------------ */
#define LUA_OFF_TOP       0x08
#define LUA_OFF_BASE      0x0C
#define TVALUE_SIZE       0x08
#define TVALUE_TT_OFFSET  0x04

#define LUA_TNIL          0
#define LUA_TBOOLEAN      1
#define LUA_TNUMBER       3
#define LUA_TSTRING       4
#define LUA_TTABLE        5
#define LUA_TFUNCTION     6
#define LUA_TTHREAD       8

/* Identifies a lua_State by tt-byte at +4 (LUA_TTHREAD = 8) plus
 * structural checks. Filters out C++ this-pointers that the shared
 * noop stub gets called with from engine code. */
static BOOL LooksLikeLuaState(void* L) {
    uint8_t L_tt;
    void *top, *base, *l_G;
    uintptr_t t, b;

    if (!SafeProbe(L, 0x18)) return FALSE;
    L_tt = *(uint8_t*)((char*)L + 4);
    if (L_tt != LUA_TTHREAD) return FALSE;

    top  = *(void**)((char*)L + LUA_OFF_TOP);
    base = *(void**)((char*)L + LUA_OFF_BASE);
    l_G  = *(void**)((char*)L + 0x10);

    if (!SafeProbe(base, 16) || !SafeProbe(top, 4) || !SafeProbe(l_G, 4)) return FALSE;
    t = (uintptr_t)top;
    b = (uintptr_t)base;
    if ((t | b) & 0x3) return FALSE;
    if (t < b) return FALSE;
    if (t - b > 0x10000) return FALSE;
    return TRUE;
}

/* ------------------------------------------------------------------------ *
 * Fingerprint + RVA selection
 * ------------------------------------------------------------------------ */
static const LuaRvaSet* SelectRvas(HMODULE mod) {
    BYTE* base = (BYTE*)mod;
    uint64_t fp;

    if (!SafeProbe(base + 0x11000, 0x1000)) {
        m2_logf("[!] lua_bridge: SelectRvas: 4KB at RVA 0x11000 unreadable; default v1.1");
        return &kRvas_v1_1;
    }
    fp = Fnv1a64(base + 0x11000, 0x1000);
    m2_logf("[*] lua_bridge: binary fingerprint = 0x%016llX", fp);

    switch (fp) {
        case 0xB79E4DD22A4BFCB3ULL:
            m2_logf("[*] lua_bridge: matched %s", kRvas_v1_1.label);
            return &kRvas_v1_1;
        case 0x1942B494FF9F4DB3ULL:
            m2_logf("[*] lua_bridge: matched %s", kRvas_v1_1_bypass.label);
            return &kRvas_v1_1_bypass;
        default:
            m2_logf("[!] lua_bridge: unknown binary (fp=0x%016llX); defaulting to v1.1 + relying on prologue validator", fp);
            return &kRvas_v1_1;
    }
}

/* ------------------------------------------------------------------------ *
 * Hook-target validator — refuses to install a hook if the bytes at the
 * target don't look right for the kind of code we expect. Prevents CTDs
 * when our RVA table doesn't match this binary.
 * ------------------------------------------------------------------------ */
typedef enum HookKind { HOOK_NOOP_STUB, HOOK_NORMAL_FUNC } HookKind;

static BOOL ValidateHookTarget(const void* p, HookKind kind) {
    const uint8_t* b;
    if (!SafeProbe(p, 8)) return FALSE;
    b = (const uint8_t*)p;
    if (kind == HOOK_NOOP_STUB) {
        return b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3;  /* xor eax,eax; ret */
    }
    /* HOOK_NORMAL_FUNC: any common x86 prologue */
    if (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) return TRUE;
    if (b[0] == 0x53) return TRUE;
    if (b[0] == 0x56) return TRUE;
    if (b[0] == 0x57) return TRUE;
    if (b[0] == 0x83 && b[1] == 0xEC) return TRUE;
    if (b[0] == 0x81 && b[1] == 0xEC) return TRUE;
    if (b[0] == 0x6A) return TRUE;
    if (b[0] == 0x68) return TRUE;
    if (b[0] == 0x8B && b[1] == 0xFF) return TRUE;
    if (b[0] == 0x8B && (b[1] & 0xC0) == 0xC0) return TRUE;
    return FALSE;
}

/* ------------------------------------------------------------------------ *
 * Calling-convention typedefs
 * ------------------------------------------------------------------------ */
typedef int  (__cdecl*   lua_CFunction_t)(void* L);
typedef int  (__fastcall* pandemic_CFunction_t)(void* L, void* edx);

/* ------------------------------------------------------------------------ *
 * Crafted TString for pushing arbitrary source onto the Lua stack.
 *
 * Layout matches stock Lua 5.1.2 TString (verified — Pandemic packed
 * TValue but NOT TString). FIXEDBIT in `marked` tells the GC to leave
 * us alone.
 * ------------------------------------------------------------------------ */
#pragma pack(push, 4)
typedef struct FixedTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[1048576];  /* 1 MB — sized to absorb any realistic chunk */
} FixedTString;
#pragma pack(pop)
static FixedTString g_chunkSource;

static void InitChunkSource(void) {
    memset(&g_chunkSource, 0, sizeof(g_chunkSource));
    g_chunkSource.tt     = (uint8_t)LUA_TSTRING;
    g_chunkSource.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_chunkSource.hash   = 0xDEADBEEF;
}

/* Fixed-size TString for Loader.GetKeyboardState()'s return value.
 * 256 bytes, one per VK code; high bit set = currently pressed.
 *
 * Two documented caveats:
 *   1. Static buffer, reused per call. `local a = Loader.GetKeyboardState();
 *      Loader.GetKeyboardState()` — `a` now reflects the second call's
 *      contents because both references point at this same struct.
 *      Copy bytes out if you need to compare two snapshots.
 *   2. Not interned with the engine's string table. `s == "..."` will
 *      always be false regardless of content. Decode byte-wise with
 *      string.byte(s, vk+1). */
#pragma pack(push, 4)
typedef struct KeyboardStateTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[256];
} KeyboardStateTString;
#pragma pack(pop)
static KeyboardStateTString g_kbStateTString;

static void InitKeyboardStateTString(void) {
    memset(&g_kbStateTString, 0, sizeof(g_kbStateTString));
    g_kbStateTString.tt     = (uint8_t)LUA_TSTRING;
    g_kbStateTString.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_kbStateTString.hash   = 0x4B425953;    /* "KBYS" — arbitrary, unused unless interned */
    g_kbStateTString.len    = 256;
}

/* Companion TString for Loader.PopKeyEvents(). Same buffer-reuse
 * semantics as g_kbStateTString — the returned string is a private,
 * per-call view; consume immediately, don't hold across another pop. */
#define KEYEVENT_BUFFER_SIZE 128
#pragma pack(push, 4)
typedef struct KeyEventsTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[KEYEVENT_BUFFER_SIZE];
} KeyEventsTString;
#pragma pack(pop)
static KeyEventsTString g_keyEventsTString;

static void InitKeyEventsTString(void) {
    memset(&g_keyEventsTString, 0, sizeof(g_keyEventsTString));
    g_keyEventsTString.tt     = (uint8_t)LUA_TSTRING;
    g_keyEventsTString.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_keyEventsTString.hash   = 0x45564553;   /* "EVES" */
    g_keyEventsTString.len    = 0;
}

/* ------------------------------------------------------------------------ *
 * Globals
 * ------------------------------------------------------------------------ */
static HMODULE g_hModule = NULL;

/* Resolved RVAs (set in WorkerThread): */
static lua_CFunction_t      fpOriginal_NoopStub          = NULL;
static lua_CFunction_t      fpOriginal_luaB_type         = NULL;
static pandemic_CFunction_t fpOriginal_CreateTextWidget  = NULL;
static lua_CFunction_t      p_luaB_loadstring            = NULL;
static lua_CFunction_t      p_luaB_pcall                 = NULL;

/* Captured engine lua_State, set by the detours: */
static void* volatile g_LuaState = NULL;

/* Output buffer — accumulates execution results before the next TCP flush. */
static CRITICAL_SECTION g_outMtx;
static char*  g_outBuf       = NULL;
static size_t g_outBuf_len   = 0;
static size_t g_outBuf_cap   = 0;

/* Input queue — pending chunks waiting for a pump source to fire. */
typedef struct ChunkNode {
    char*  code;
    size_t len;
    struct ChunkNode* next;
} ChunkNode;
static CRITICAL_SECTION g_inMtx;
static ChunkNode* g_inQueue_head = NULL;
static ChunkNode* g_inQueue_tail = NULL;
static volatile LONG g_PendingScripts = 0;

/* Loader lifecycle flags — moved up so RecomputeHotWork can see them. */
static volatile LONG g_OnLoadTriggered = 0;
static volatile LONG g_OnLoadExecuted  = 0;

/* Hot-path gate. When 0, GatedPump fast-returns after a single volatile
 * load. Set to 1 whenever there might be pump work (script queued, or
 * OnLoad transition pending); recomputed from ground-truth after any
 * event that could clear it. Idempotent — occasional stale-1 just costs
 * one extra slow-path traversal, no correctness impact. */
static volatile LONG g_hotWork = 0;

static __inline void RecomputeHotWork(void) {
    LONG onload_pending = (g_OnLoadTriggered && !g_OnLoadExecuted) ? 1 : 0;
    LONG scripts_pending = (g_PendingScripts > 0) ? 1 : 0;
    g_hotWork = onload_pending | scripts_pending;
}

/* Per-thread re-entry guard — prevents the executor from recursing
 * into itself if a capture detour fires mid-LuaDoString. */
static MOD_THREAD BOOL t_inBridgeExec = FALSE;

/* ------------------------------------------------------------------------ *
 * Watchdog — self-healing safety net for silent pump stalls.
 *
 * The bridge has several state variables that in principle can end up in
 * a stuck configuration where PendingScripts > 0 but the pump never
 * drains: hotWork stuck at 0 despite pending work, t_inBridgeExec stuck
 * TRUE on the game thread, g_LuaState pointing at a destroyed VM, or a
 * seen[] set full of stale pointers. Every one of these is a real bug we
 * should eventually diagnose — but until we can reproduce them, users
 * hit "chunks stopped executing, only a reboot fixes it."
 *
 * The watchdog runs on a background thread, wakes every ~2 seconds, and
 * if it observes (a) chunks pending, (b) game running (detour fired
 * recently), (c) no pump progress for `watchdog_stuck_ms`, then it does
 * a full-hammer reset: hotWork=1, signal PumpQueue to force-clear its
 * TLS flag next entry, null out g_LuaState + seen[] so the next detour
 * re-captures cleanly. Log everything for post-mortem diagnosis.
 *
 * All three reset actions are individually safe. Not escalating to
 * medium/hard tiers keeps the code simple — the cost of over-resetting
 * a transient blip is one extra re-capture log line, no user harm.
 * ------------------------------------------------------------------------ */
static volatile DWORD g_lastDetourFireTick    = 0;
static volatile DWORD g_lastPumpAttemptTick   = 0;
static volatile DWORD g_lastPumpProgressTick  = 0;
/* 0 = not currently executing; else the tick when we entered LuaDoString.
 * Read by the watchdog to detect "hung inside a native call from Lua" — the
 * case where the game thread is blocked so no more detours can fire and the
 * since_detour heuristic would incorrectly bail. */
static volatile DWORD g_bridgeExecStartTick   = 0;
static volatile LONG  g_watchdogForceClearTLS = 0;

/* Configuration (loaded from lua_bridge.ini). */
static char  g_repl_host[64] = "127.0.0.1";
static int   g_repl_port     = 27050;
static int   g_loader_enabled  = 1;
static int   g_loader_onboot   = 1;
static int   g_loader_onload   = 1;
static int   g_loader_delay_ms = 50;
static int   g_loader_onkey_cooldown_ms = 250;  /* per-script re-fire lockout */
static int   g_watchdog_stuck_ms = 8000;         /* 0 disables the watchdog */
static int   g_ws_enabled        = 1;            /* 0 disables the WebSocket transport (raw-TCP only) */

/* ------------------------------------------------------------------------ *
 * WebSocket client tracking (single-client v1 — matches the listener's
 * existing "one connection at a time" design). When a WS client is
 * connected, g_wsClient holds the socket; Loader.Printf and Loader.WsSend
 * fan out to it under g_wsClientMtx. When no WS client is connected,
 * g_wsClient == INVALID_SOCKET and the fanouts are no-ops. The socket
 * thread owns connect/disconnect transitions; game-thread fanouts only
 * read + send under the mutex. ws_send failure inside a fanout means the
 * client is gone — the socket thread will discover it via recv shortly.
 * ------------------------------------------------------------------------ */
static CRITICAL_SECTION g_wsClientMtx;
static int              g_wsClientMtxInit = 0;
static SOCKET           g_wsClient        = INVALID_SOCKET;

/* Forward declarations — the loader_lib[] table and LuaLoaderPrintf
 * reference these; their definitions live in the WebSocket section
 * further down. */
static void ws_broadcast_typed_line(const char* type, const char* line, size_t line_len);
static int  LuaLoaderWsSend(void* L);

/* ------------------------------------------------------------------------ *
 * Output-buffer helpers
 * ------------------------------------------------------------------------ */
static void OutAppend(const char* s, size_t s_len) {
    EnterCriticalSection(&g_outMtx);
    {
        size_t needed = g_outBuf_len + s_len + 2;
        if (needed > g_outBuf_cap) {
            size_t newcap = g_outBuf_cap ? g_outBuf_cap * 2 : 4096;
            char*  newbuf;
            while (newcap < needed) newcap *= 2;
            newbuf = (char*)realloc(g_outBuf, newcap);
            if (newbuf) { g_outBuf = newbuf; g_outBuf_cap = newcap; }
            else { LeaveCriticalSection(&g_outMtx); return; }
        }
        memcpy(g_outBuf + g_outBuf_len, s, s_len);
        g_outBuf_len += s_len;
        g_outBuf[g_outBuf_len++] = '\n';
        g_outBuf[g_outBuf_len]   = '\0';
    }
    LeaveCriticalSection(&g_outMtx);
}

/* ------------------------------------------------------------------------ *
 * Input-queue helpers
 * ------------------------------------------------------------------------ */
static void InQueuePush(const char* code, size_t len) {
    ChunkNode* node = (ChunkNode*)malloc(sizeof(ChunkNode));
    if (!node) return;
    node->code = (char*)malloc(len + 1);
    if (!node->code) { free(node); return; }
    memcpy(node->code, code, len);
    node->code[len] = '\0';
    node->len  = len;
    node->next = NULL;

    EnterCriticalSection(&g_inMtx);
    if (g_inQueue_tail) g_inQueue_tail->next = node;
    else                g_inQueue_head       = node;
    g_inQueue_tail = node;
    LeaveCriticalSection(&g_inMtx);

    InterlockedIncrement(&g_PendingScripts);
    g_hotWork = 1;
}

static ChunkNode* InQueuePop(void) {
    ChunkNode* node;
    EnterCriticalSection(&g_inMtx);
    node = g_inQueue_head;
    if (node) {
        g_inQueue_head = node->next;
        if (!g_inQueue_head) g_inQueue_tail = NULL;
        InterlockedDecrement(&g_PendingScripts);
    }
    LeaveCriticalSection(&g_inMtx);
    return node;
}

static void ChunkNodeFree(ChunkNode* n) {
    if (!n) return;
    free(n->code);
    free(n);
}

/* ------------------------------------------------------------------------ *
 * Result-formatting + executor
 * ------------------------------------------------------------------------ */
static int SafeCallLuaCFunction(lua_CFunction_t fn, void* L) {
#ifdef _MSC_VER
    __try {
        return fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
#else
    /* MinGW x86 doesn't support MSVC SEH; call unguarded. If the
     * target AVs, the game crashes. Documented trade-off. */
    return fn(L);
#endif
}

/* Append "<value>" (or "nil" / "true" / a number) representing one
 * TValue slot to `out`. `out_cap` is the buffer's total capacity,
 * `*out_len` is updated. Caller ensures room. */
static void FormatTValue(const char* slot, char* out, size_t out_cap, size_t* out_len) {
    int tt = *(const int*)(slot + TVALUE_TT_OFFSET);
    char tmp[128];
    int n = 0;
    switch (tt) {
        case LUA_TNIL:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "nil");
            break;
        case LUA_TBOOLEAN:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                            *(const int*)slot ? "true" : "false");
            break;
        case LUA_TNUMBER: {
            float f = *(const float*)slot;  /* lua_Number = float in this build */
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "%g", (double)f);
            break;
        }
        case LUA_TSTRING: {
            void* gc = *(void* const*)slot;
            uint32_t slen;
            const char* sdata;
            if (!SafeProbe(gc, 0x14)) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<string: gc unreadable>");
                break;
            }
            slen = *(uint32_t*)((char*)gc + 0x0C);
            if (slen > 16u * 1024u * 1024u) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                                "<string: implausible len=%u>", slen);
                break;
            }
            sdata = (const char*)gc + 0x10;
            if (!SafeProbe(sdata, slen + 1)) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<string: data unreadable>");
                break;
            }
            /* Bypass the tmp buffer for string content — copy straight to out. */
            if (*out_len + slen + 3 < out_cap) {
                out[(*out_len)++] = '"';
                memcpy(out + *out_len, sdata, slen);
                *out_len += slen;
                out[(*out_len)++] = '"';
                out[*out_len] = '\0';
            }
            return;
        }
        case LUA_TTABLE:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<table>");
            break;
        case LUA_TFUNCTION:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<function>");
            break;
        default: {
            void* v = *(void* const*)slot;
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                            "<tt=%d val=%p>", tt, v);
            break;
        }
    }
    if (n > 0 && (size_t)n + *out_len + 1 < out_cap) {
        memcpy(out + *out_len, tmp, n);
        *out_len += n;
        out[*out_len] = '\0';
    }
}

/* Phase 3 executor. Builds a NEW Lua frame on top of the engine's
 * active frame (does NOT clobber base) and runs the chunk via
 * luaB_loadstring + luaB_pcall. Result formatted into `out`.
 *
 * Must be called from inside a real lua_CFunction detour with a
 * verified-valid L (i.e. after LooksLikeLuaState). */
static void LuaDoString(void* L, const char* code, size_t code_len,
                        char* out, size_t out_cap) {
    char *Lc, *new_base, *top_slot;
    void **top_ptr, **base_ptr;
    void *saved_top, *saved_base;
    int load_n, pcall_n, compiled_tt;
    size_t out_len = 0;
    ptrdiff_t after_exec;
    int result_slots, i;
    int succeeded = 0;
    int have_status = 0;
    int first_result;

    if (!L) { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] no L"); return; }
    if (!LooksLikeLuaState(L)) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] L failed validation");
        return;
    }
    if (!p_luaB_loadstring || !p_luaB_pcall) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] executor fn pointers not resolved");
        return;
    }
    if (code_len == 0)                          { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] empty chunk"); return; }
    if (code_len >= sizeof(g_chunkSource.data)) { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] chunk too large"); return; }

    Lc       = (char*)L;
    top_ptr  = (void**)(Lc + LUA_OFF_TOP);
    base_ptr = (void**)(Lc + LUA_OFF_BASE);
    saved_top  = *top_ptr;
    saved_base = *base_ptr;
    new_base   = (char*)saved_top;

    if (!SafeProbe(new_base, 3 * TVALUE_SIZE)) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] L->top + scratch unwritable");
        return;
    }

    memcpy(g_chunkSource.data, code, code_len);
    g_chunkSource.data[code_len] = '\0';
    g_chunkSource.len = (uint32_t)code_len;

    *(void**)new_base                            = &g_chunkSource;
    *(int*)(new_base + TVALUE_TT_OFFSET)         = LUA_TSTRING;
    *base_ptr = new_base;
    *top_ptr  = new_base + TVALUE_SIZE;

    load_n = SafeCallLuaCFunction(p_luaB_loadstring, L);
    if (load_n < 0) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] luaB_loadstring crashed");
        return;
    }
    if (load_n == 2) {
        char* err_slot = new_base + 2 * TVALUE_SIZE;
        out_len = 0;
        out_len += _snprintf_s(out, out_cap, _TRUNCATE, "[compile] ");
        FormatTValue(err_slot, out, out_cap, &out_len);
        *top_ptr = saved_top; *base_ptr = saved_base;
        return;
    }
    if (load_n != 1) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] loadstring returned %d", load_n);
        return;
    }

    /* Success: stack is [chunk, fn] at new_base. Slide fn down to new_base[0]
     * so pcall reads it at index 1. */
    top_slot = (char*)*top_ptr - TVALUE_SIZE;
    compiled_tt = *(int*)(top_slot + TVALUE_TT_OFFSET);
    if (compiled_tt != LUA_TFUNCTION) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE,
                    "[bridge] loadstring result not a function (tt=%d)", compiled_tt);
        return;
    }
    if (top_slot != new_base) memcpy(new_base, top_slot, TVALUE_SIZE);
    *top_ptr = new_base + TVALUE_SIZE;

    pcall_n = SafeCallLuaCFunction(p_luaB_pcall, L);
    if (pcall_n < 0) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] luaB_pcall crashed");
        return;
    }

    after_exec = (char*)*top_ptr - new_base;
    result_slots = (int)(after_exec / TVALUE_SIZE);
    if (result_slots > 16) result_slots = 16;

    /* Detect status: accept either bool (stock) or number (Pandemic's variant). */
    if (result_slots >= 1) {
        int tt0 = *(int*)(new_base + TVALUE_TT_OFFSET);
        if (tt0 == LUA_TBOOLEAN) {
            have_status = 1;
            succeeded   = (*(int*)new_base != 0);
        } else if (tt0 == LUA_TNUMBER) {
            have_status = 1;
            succeeded   = (*(const float*)new_base != 0.0f);
        }
    }
    first_result = have_status ? 1 : 0;

    out_len = 0;
    out_len += _snprintf_s(out, out_cap, _TRUNCATE, "%s", succeeded ? "[ok]" : "[runtime]");
    for (i = first_result; i < result_slots; ++i) {
        char* rslot = new_base + i * TVALUE_SIZE;
        if (out_len + 2 < out_cap) {
            out[out_len++] = succeeded ? '\t' : ' ';
            out[out_len]   = '\0';
        }
        FormatTValue(rslot, out, out_cap, &out_len);
    }

    *top_ptr = saved_top;
    *base_ptr = saved_base;
}

static void RegisterTcpLib(void* L);
static void RegisterLoaderLib(void* L);
static void RegisterMathLib(void* L);
static void RunPolyfill(void* L);
static void ExecuteLuaFolder(void* L, const char* folder_name);
static void InitializeKeyScripts(void);

/* ------------------------------------------------------------------------ *
 * Pump — drain the input queue against a verified-valid L
 * ------------------------------------------------------------------------ */
static void PumpQueue(void* L_for_exec) {
    char result_buf[16384];
    int L_ok;

    if (g_PendingScripts <= 0) return;
    if (t_inBridgeExec) {
        /* Watchdog escape hatch: if the watchdog decided this thread's
         * TLS is stuck TRUE (leaked from an earlier abnormal exit), it
         * sets g_watchdogForceClearTLS. Consume the flag and clear our
         * TLS so this call proceeds. Uses InterlockedCompareExchange so
         * only one thread claims the reset even in the rare case that
         * multiple threads race into this branch. */
        if (InterlockedCompareExchange(&g_watchdogForceClearTLS, 0, 1) == 1) {
            t_inBridgeExec = FALSE;
            m2_logf("[!] lua_bridge: watchdog force-cleared t_inBridgeExec on this thread");
        } else {
            return;
        }
    }

    /* Re-register our libs ONCE at batch start, not per chunk. Defends
     * against engine _G resets between batches (menu → mission,
     * cutscene entry, etc.); a wipe mid-batch is essentially impossible
     * since chunks drain back-to-back. luaL_register is idempotent, so
     * this is also cheap. */
    L_ok = (L_for_exec && LooksLikeLuaState(L_for_exec));
    if (L_ok) {
        RegisterTcpLib(L_for_exec);
        RegisterLoaderLib(L_for_exec);
        RegisterMathLib(L_for_exec);
        RunPolyfill(L_for_exec);
    }

    for (;;) {
        ChunkNode* node = InQueuePop();
        if (!node) return;

        g_bridgeExecStartTick = GetTickCount();
        t_inBridgeExec = TRUE;
        if (L_ok) {
            LuaDoString(L_for_exec, node->code, node->len, result_buf, sizeof(result_buf));
        } else {
            _snprintf_s(result_buf, sizeof(result_buf), _TRUNCATE,
                        "[bridge] pump fired without a valid L — chunk dropped");
        }
        t_inBridgeExec = FALSE;
        g_bridgeExecStartTick = 0;

        m2_logf("[+] lua_bridge: Script executed. Result: %s", result_buf);
        OutAppend(result_buf, strlen(result_buf));
        OutAppend("<<<END>>>", 9);
        ChunkNodeFree(node);

        /* Watchdog telemetry: successful drain proves the pump path is
         * alive. Updated per-chunk (not per-batch) so long batches don't
         * look stuck to the watchdog if they take longer than the
         * stuck-timeout. */
        g_lastPumpProgressTick = GetTickCount();
    }
}

static __inline void GatedPump(void* L_arg0) {
    /* Fast path: single volatile load. Fires thousands of times per
     * second from detours; anything else here is measurable. */
    if (!g_hotWork) return;

    /* Slow path: something wants doing. Watchdog uses this timestamp
     * to distinguish "hotWork stuck at 0" (this never updates) from
     * "hotWork trying, PumpQueue not draining" (this updates but
     * g_lastPumpProgressTick doesn't). */
    g_lastPumpAttemptTick = GetTickCount();

    if (g_loader_enabled && g_loader_onload && g_OnLoadTriggered && !g_OnLoadExecuted) {
        if (LooksLikeLuaState(L_arg0)) {
            g_OnLoadExecuted = 1;
            ExecuteLuaFolder(L_arg0, "OnLoad");
        }
    }

    if (g_PendingScripts > 0 && !t_inBridgeExec && LooksLikeLuaState(L_arg0)) {
        PumpQueue(L_arg0);
    }

    RecomputeHotWork();
}

/* Seen-L set, file-scope so the watchdog can memset it during a hard reset.
 * All access from the game thread's CaptureL; the watchdog only writes
 * (never reads for logic), so no atomicity needed beyond aligned-store. */
static void* g_seenL[8] = {0};

static void CaptureL(void* L, const char* via) {
    /* Fast path #1: same L as last capture. This is the common case
     * (every detour fire on the same VM). Single pointer compare. */
    if (!L || L == g_LuaState) return;

    /* Fast path #2: L is in g_seenL[]. We've already validated + registered
     * on this VM before; the engine just flipped back to it. Scanning a
     * small pointer array is pure L1 (~5 cycles) versus LooksLikeLuaState
     * which does 4 VirtualQuery syscalls (~2µs). This is the biggest
     * hot-path win — the engine flips between frontend / gameplay VMs
     * many times per second. */
    int i;
    int free_slot = -1;
    for (i = 0; i < 8; ++i) {
        if (g_seenL[i] == L) { g_LuaState = L; return; }
        if (g_seenL[i] == NULL) { free_slot = i; break; }
    }

    /* Slow path: L we've never seen. Validate, register, log, remember. */
    if (!LooksLikeLuaState(L)) return;
    g_LuaState = L;
    if (free_slot < 0) return;  /* g_seenL[] full — silently drop the log entry */
    g_seenL[free_slot] = L;

    m2_logf("[+] lua_bridge: Lua VM captured via %s: L=%p", via, L);
    RegisterTcpLib(L);
    RegisterLoaderLib(L);
    RegisterMathLib(L);
    RunPolyfill(L);

    if (g_loader_enabled) {
        static int key_loader_initialized = 0;
        if (!key_loader_initialized) {
            key_loader_initialized = 1;
            InitializeKeyScripts();
        }
    }

    if (g_loader_enabled && g_loader_onboot) {
        static int onboot_executed = 0;
        if (!onboot_executed) {
            onboot_executed = 1;
            ExecuteLuaFolder(L, "OnBoot");
        }
    }
}

/* ------------------------------------------------------------------------ *
 * Detours
 * ------------------------------------------------------------------------ */
static int __cdecl DetourNoopStub(void* L) {
    g_lastDetourFireTick = GetTickCount();
    if (g_loader_enabled && g_loader_onload && !g_OnLoadTriggered) {
        char msg[512];
        if (m2_lua_join_strings(L, msg, sizeof(msg)) >= 1) {
            if (strstr(msg, "GlobalExit - Complete")) {
                m2_logf("[*] lua_bridge: OnLoad milestone reached (GlobalExit - Complete). Queuing OnLoad scripts.");
                InterlockedExchange(&g_OnLoadTriggered, 1);
                g_hotWork = 1;
            }
        }
    }
    GatedPump(L);
    return fpOriginal_NoopStub ? fpOriginal_NoopStub(L) : 0;
}

static int __cdecl DetourLuaType(void* L) {
    g_lastDetourFireTick = GetTickCount();
    CaptureL(L, "type");
    GatedPump(L);
    return fpOriginal_luaB_type ? fpOriginal_luaB_type(L) : 0;
}

static int __fastcall DetourCreateTextWidget(void* L, void* edx) {
    g_lastDetourFireTick = GetTickCount();
    GatedPump(L);
    return fpOriginal_CreateTextWidget ? fpOriginal_CreateTextWidget(L, edx) : 0;
}

/* ------------------------------------------------------------------------ *
 * Print/Next/ToString hijack — see commented-out luaL_register section
 * below. Without that hook these hijacks never get installed, so the
 * functions below are unused in this draft. Left in place so they're
 * ready when the naked-detour question is resolved.
 * ------------------------------------------------------------------------ */
static lua_CFunction_t fpOriginalPrint    = NULL;
static lua_CFunction_t fpOriginalNext     = NULL;
static lua_CFunction_t fpOriginalToString = NULL;

static int __cdecl HijackedPrint(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalPrint ? fpOriginalPrint(L) : 0;
}
static int __cdecl HijackedNext(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalNext ? fpOriginalNext(L) : 0;
}
static int __cdecl HijackedToString(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalToString ? fpOriginalToString(L) : 0;
}

/* ======================================================================== *
 * luaL_register hijack — DEFERRED
 *
 * Mercenaries 2's luaL_register uses a custom register-arg ABI:
 *   ECX = lua_State* L
 *   EAX = const char* libname
 *   [esp+4] = const luaL_Reg* table
 * Caller cleans the 4-byte stack arg.
 *
 * On MSVC, hooking this needs a __declspec(naked) detour that
 * preserves the registers and forwards. The MSVC source is below as
 * a comment, since GCC/MinGW on x86 doesn't support
 * __attribute__((naked)) and this SDK's Makefiles use MinGW.
 *
 * Three reasonable resolutions:
 *
 *   1) Translate to a global assembly file (lua_bridge_asm.S). The
 *      contents are essentially the same instructions GCC's inline
 *      asm would emit. Add to the Makefile as an additional source.
 *
 *   2) Compile with MSVC instead. The SDK's helpers should work fine
 *      either way; only the build glue would need to change.
 *
 *   3) Skip this hook. The bridge degrades gracefully without it: the
 *      noop_stub / luaB_type / CreateTextWidget detours still capture
 *      L, the executor still runs chunks. We lose the print/next/
 *      tostring hijack (a high-frequency pump source) and the
 *      registration-table dump (a discovery convenience), but core
 *      functionality is intact. This is what the draft below opts for.
 *
 * MSVC reference implementation:
 *
 *   __declspec(naked) static void DetourLuaLRegister(void) {
 *       __asm {
 *           push edx
 *           push eax
 *           push ecx
 *           push dword ptr [esp + 0x10]   ; table
 *           push dword ptr [esp + 0x08]   ; libname
 *           push dword ptr [esp + 0x08]   ; L
 *           call OnLuaRegisterCalled
 *           add esp, 12
 *           pop ecx
 *           pop eax
 *           pop edx
 *           jmp dword ptr [fpOriginal_luaL_register]
 *       }
 *   }
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * Expose Tcp.Send to Lua
 * ------------------------------------------------------------------------ */
typedef struct luaL_Reg {
    const char *name;
    int (__cdecl *func)(void* L);
} luaL_Reg;

static int LuaTcpSend(void* L) {
    char host[128];
    char msg[2048];
    int port;

    if (m2_lua_nargs(L) < 3) return 0;
    if (m2_lua_arg_string(L, 0, host, sizeof(host)) == 0) return 0;
    
    // Port is standard Lua float, extract from stack base:
    char* base = *(char**)((char*)L + 0x0C); // L->base
    if (!base) return 0;
    float port_val = *(float*)(base + 8);    // First stack slot (8 bytes per TValue)
    port = (int)port_val;

    if (m2_lua_arg_string(L, 2, msg, sizeof(msg)) == 0) return 0;

    unsigned long ip = inet_addr(host);
    if (ip == INADDR_NONE) return 0;

    /*
     * SECURITY RESTRICTION:
     * Only allow connections to loopback/localhost (127.0.0.0/8).
     * This decision was made for player security, preventing malicious or
     * untrusted Lua scripts from performing port scans on the player's
     * local network or exfiltrating data to external servers on the internet.
     *
     * NOTE: If this restriction is removed, it could potentially allow
     * secondary out-of-band communication between coop players to sync
     * mod status over the network without needing to integrate directly
     * with the game's built-in P2P networking core.
     */
    unsigned long ip_host = ntohl(ip);
    if ((ip_host & 0xFF000000) != 0x7F000000) {
        return 0; // Block non-localhost destinations
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = ip;

        DWORD timeout = 500;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            send(s, msg, (int)strlen(msg), 0);
        }
        closesocket(s);
    }
    return 0;
}

static const luaL_Reg tcp_lib[] = {
    {"Send", LuaTcpSend},
    {NULL, NULL}
};

/* ------------------------------------------------------------------------ *
 * Native Lua Script Loader
 * ------------------------------------------------------------------------ */
#define MAX_SCRIPTS 128

typedef struct {
    char path[MAX_PATH];
    char rel_path[MAX_PATH];
    int load_order;
} LuaScriptFile;

static int CompareAlphabetical(const void* a, const void* b) {
    return _stricmp(((const LuaScriptFile*)a)->rel_path, ((const LuaScriptFile*)b)->rel_path);
}

static int CompareLoadOrder(const void* a, const void* b) {
    int diff = ((const LuaScriptFile*)a)->load_order - ((const LuaScriptFile*)b)->load_order;
    if (diff != 0) return diff;
    return _stricmp(((const LuaScriptFile*)a)->rel_path, ((const LuaScriptFile*)b)->rel_path);
}

static void EnsureLoaderDirectories(void) {
    char exe_dir[MAX_PATH];
    char path[MAX_PATH];
    char* slash;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(path, sizeof(path), "%sscripts", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnBoot", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnLoad", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnKey", exe_dir);
    CreateDirectoryA(path, NULL);
}

static void CollectScriptsRecursive(const char* base_path, const char* sub_path, LuaScriptFile* list, int* count, int max_count) {
    char search_path[MAX_PATH];
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;

    snprintf(search_path, sizeof(search_path), "%s%s*", base_path, sub_path);
    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) {
            continue;
        }

        char relative_path[MAX_PATH];
        if (sub_path[0] == '\0') {
            snprintf(relative_path, sizeof(relative_path), "%s", ffd.cFileName);
        } else {
            snprintf(relative_path, sizeof(relative_path), "%s%s", sub_path, ffd.cFileName);
        }

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            char next_sub[MAX_PATH];
            snprintf(next_sub, sizeof(next_sub), "%s\\", relative_path);
            CollectScriptsRecursive(base_path, next_sub, list, count, max_count);
        } else {
            size_t len = strlen(ffd.cFileName);
            if (len > 4 && _stricmp(ffd.cFileName + len - 4, ".lua") == 0) {
                if (*count < max_count) {
                    snprintf(list[*count].path, sizeof(list[*count].path), "%s%s", base_path, relative_path);
                    
                    strncpy(list[*count].rel_path, relative_path, sizeof(list[*count].rel_path) - 1);
                    list[*count].rel_path[sizeof(list[*count].rel_path) - 1] = '\0';
                    
                    list[*count].load_order = -1;
                    (*count)++;
                }
            }
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
}

static void EnsureLoaderIniHeader(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) {
        fclose(f);
        return; // File already exists
    }
    
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "; lua_loader.ini — Lua Script Loader Configuration\n");
        fprintf(f, "; Define execution order for [OnBoot] and [OnLoad] (lowest numbers load first)\n");
        fprintf(f, "; Define hotkey triggers under [OnKey] (e.g. script.lua = F1 or script.lua = insert)\n");
        fprintf(f, ";\n");
        fprintf(f, "; Virtual Key codes reference: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes\n");
        fprintf(f, "; Common keys: insert, delete, home, end, pageup, pagedown, space, enter, escape, F1..F12, A..Z, 0..9\n\n");
        fclose(f);
    }
}

static void ExtractDefaultKey(const char* file_path, char* out_key, size_t out_max) {
    strncpy(out_key, "unassigned", out_max);
    FILE* f = fopen(file_path, "r");
    if (!f) return;
    
    char line[256];
    int i;
    for (i = 0; i < 10; ++i) {
        if (!fgets(line, sizeof(line), f)) break;
        char* p = strstr(line, "KEYVAL");
        if (p) {
            char* eq = strchr(p, '=');
            if (eq) {
                char* q1 = strchr(eq, '"');
                if (!q1) q1 = strchr(eq, '\'');
                if (q1) {
                    q1++;
                    char* q2 = strchr(q1, '"');
                    if (!q2) q2 = strchr(q1, '\'');
                    if (q2 && (size_t)(q2 - q1) < out_max) {
                        size_t len = q2 - q1;
                        memcpy(out_key, q1, len);
                        out_key[len] = '\0';
                        break;
                    }
                }
            }
        }
    }
    fclose(f);
}

static int ResolveKeyName(const char* name) {
    if (!name) return 0;
    if (_stricmp(name, "unassigned") == 0) return 0;

    if (name[0] != '\0' && name[1] == '\0') {
        char c = name[0];
        if (c >= 'a' && c <= 'z') return 0x41 + (c - 'a');
        if (c >= 'A' && c <= 'Z') return 0x41 + (c - 'A');
        if (c >= '0' && c <= '9') return 0x30 + (c - '0');
    }

    if ((name[0] == 'f' || name[0] == 'F') && name[1] >= '1' && name[1] <= '9') {
        int num = atoi(name + 1);
        if (num >= 1 && num <= 12) return 0x70 + (num - 1);
    }

    if (_stricmp(name, "insert") == 0) return VK_INSERT;
    if (_stricmp(name, "delete") == 0) return VK_DELETE;
    if (_stricmp(name, "home") == 0) return VK_HOME;
    if (_stricmp(name, "end") == 0) return VK_END;
    if (_stricmp(name, "pageup") == 0) return VK_PRIOR;
    if (_stricmp(name, "pagedown") == 0) return VK_NEXT;
    if (_stricmp(name, "space") == 0) return VK_SPACE;
    if (_stricmp(name, "enter") == 0 || _stricmp(name, "return") == 0) return VK_RETURN;
    if (_stricmp(name, "escape") == 0 || _stricmp(name, "esc") == 0) return VK_ESCAPE;
    if (_stricmp(name, "backspace") == 0) return VK_BACK;
    if (_stricmp(name, "tab") == 0) return VK_TAB;
    if (_stricmp(name, "shift") == 0) return VK_SHIFT;
    if (_stricmp(name, "ctrl") == 0 || _stricmp(name, "control") == 0) return VK_CONTROL;
    if (_stricmp(name, "alt") == 0) return VK_MENU;
    if (_stricmp(name, "left") == 0) return VK_LEFT;
    if (_stricmp(name, "up") == 0) return VK_UP;
    if (_stricmp(name, "right") == 0) return VK_RIGHT;
    if (_stricmp(name, "down") == 0) return VK_DOWN;

    return 0;
}

static void ExecuteLuaFolder(void* L, const char* folder_name) {
    char exe_dir[MAX_PATH];
    char folder_path[MAX_PATH];
    char loader_ini_path[MAX_PATH];
    char* slash;
    LuaScriptFile scripts[MAX_SCRIPTS];
    int script_count = 0;
    int i;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(folder_path, sizeof(folder_path), "%sscripts\\%s\\", exe_dir, folder_name);
    m2_module_path(g_hModule, "lua_loader.ini", loader_ini_path, sizeof(loader_ini_path));
    EnsureLoaderIniHeader(loader_ini_path);

    CollectScriptsRecursive(folder_path, "", scripts, &script_count, MAX_SCRIPTS);

    if (script_count == 0) {
        m2_logf("[*] lua_bridge: No scripts found in scripts/%s/", folder_name);
        return;
    }

    qsort(scripts, script_count, sizeof(LuaScriptFile), CompareAlphabetical);

    for (i = 0; i < script_count; ++i) {
        int order = GetPrivateProfileIntA(folder_name, scripts[i].rel_path, -1, loader_ini_path);
        if (order == -1) {
            order = (i + 1) * 10;
            char order_str[32];
            snprintf(order_str, sizeof(order_str), "%d", order);
            WritePrivateProfileStringA(folder_name, scripts[i].rel_path, order_str, loader_ini_path);
        }
        scripts[i].load_order = order;
    }

    qsort(scripts, script_count, sizeof(LuaScriptFile), CompareLoadOrder);

    /* Re-register libs before running the batch — same reasoning as
     * PumpQueue: engine may have wiped _G between capture and now. */
    RegisterTcpLib(L);
    RegisterLoaderLib(L);
    RegisterMathLib(L);
    RunPolyfill(L);

    for (i = 0; i < script_count; ++i) {
        FILE* f = fopen(scripts[i].path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);

            if (sz > 0 && sz < 1024 * 1024) { // Max 1MB
                char* buf = (char*)malloc(sz + 1);
                if (buf) {
                    size_t read_bytes = fread(buf, 1, sz, f);
                    buf[read_bytes] = '\0';

                    m2_logf("[*] lua_bridge: Loading script (%s): %s (%ld bytes)", folder_name, scripts[i].rel_path, sz);
                    
                    char result_buf[4096];
                    t_inBridgeExec = TRUE;
                    LuaDoString(L, buf, read_bytes, result_buf, sizeof(result_buf));
                    t_inBridgeExec = FALSE;
                    
                    m2_logf("[+] lua_bridge: Script result: %s", result_buf);

                    free(buf);
                }
            }
            fclose(f);
        } else {
            m2_logf("[!] lua_bridge: Failed to open script: %s", scripts[i].path);
        }

        if (g_loader_delay_ms > 0 && i < script_count - 1) {
            Sleep(g_loader_delay_ms);
        }
    }
}

typedef struct {
    char  path[MAX_PATH];
    char  rel_path[MAX_PATH];
    char  key_name[64];
    int   vk_code;
    int   was_down;
    DWORD last_fired_tick;   /* GetTickCount() at last successful queue-push */
    int   throttle_logged;   /* First cooldown throttle for this script logged? */
} LuaKeyScript;

static LuaKeyScript g_KeyScripts[MAX_SCRIPTS];
static int g_KeyScriptCount = 0;

/* ------------------------------------------------------------------------ *
 * Key-event ring buffer — feeds Loader.PopKeyEvents().
 *
 * LoaderKeyEventThread samples GetAsyncKeyState across all 256 VK codes at
 * ~60 Hz, tracks per-key previous state, and appends the VK code to this
 * ring on each up→down edge. LuaLoaderPopKeyEvents drains the ring into
 * g_keyEventsTString and returns it to Lua as a string of raw VK bytes.
 *
 * Presses only (no release events). If a caller needs release edges,
 * we'd extend the encoding (pair of bytes or a companion buffer) — held
 * off for a first cut since chat / rebind / debug-console use cases only
 * need presses.
 *
 * Ring overflow policy: drop oldest. 128 events between polls covers
 * ~10 seconds of continuous 100 WPM typing; realistic clients poll much
 * faster than that.
 * ------------------------------------------------------------------------ */
static CRITICAL_SECTION g_keyEventMtx;
static int              g_keyEventMtxInit = 0;
static uint8_t          g_keyEventRing[KEYEVENT_BUFFER_SIZE];
static int              g_keyEventHead    = 0;   /* next write slot */
static int              g_keyEventTail    = 0;   /* next read slot */
static int              g_keyEventCount   = 0;   /* live events in ring */

static void KeyEventsPush(uint8_t vk) {
    if (!g_keyEventMtxInit) return;
    EnterCriticalSection(&g_keyEventMtx);
    g_keyEventRing[g_keyEventHead] = vk;
    g_keyEventHead = (g_keyEventHead + 1) % KEYEVENT_BUFFER_SIZE;
    if (g_keyEventCount < KEYEVENT_BUFFER_SIZE) {
        g_keyEventCount++;
    } else {
        /* Full — advance tail to drop oldest. Head has already lapped it. */
        g_keyEventTail = (g_keyEventTail + 1) % KEYEVENT_BUFFER_SIZE;
    }
    LeaveCriticalSection(&g_keyEventMtx);
}

static int KeyEventsPopAll(uint8_t* out, int max_out) {
    int n = 0;
    if (!g_keyEventMtxInit) return 0;
    EnterCriticalSection(&g_keyEventMtx);
    while (g_keyEventCount > 0 && n < max_out) {
        out[n++] = g_keyEventRing[g_keyEventTail];
        g_keyEventTail = (g_keyEventTail + 1) % KEYEVENT_BUFFER_SIZE;
        g_keyEventCount--;
    }
    LeaveCriticalSection(&g_keyEventMtx);
    return n;
}

/* Is the foreground window owned by our process? Uses process-ID match
 * rather than window-class matching, so it works across any game version
 * or multi-window layout without hardcoded strings. */
static BOOL IsGameFocused(void) {
    HWND fg;
    DWORD fg_pid = 0;
    fg = GetForegroundWindow();
    if (!fg) return FALSE;
    GetWindowThreadProcessId(fg, &fg_pid);
    return fg_pid == GetCurrentProcessId();
}

/* ------------------------------------------------------------------------ *
 * WatchdogThread — silent-stall self-healer. See the big design comment
 * above g_lastDetourFireTick for the full rationale.
 *
 * Wakes every ~2 seconds, decides based on three timestamps whether the
 * bridge is stuck, and if so does a comprehensive state reset. Cheap to
 * run: two InterlockedCompare-ish reads and a Sleep(2000) between checks
 * — measured under a microsecond per iteration, ~0.00005% of one core.
 * ------------------------------------------------------------------------ */
static DWORD WINAPI WatchdogThread(LPVOID param) {
    DWORD last_reset_tick = 0;
    (void)param;
    for (;;) {
        Sleep(2000);

        int stuck_ms = g_watchdog_stuck_ms;
        if (stuck_ms <= 0) continue;            /* watchdog disabled by ini */
        if (g_PendingScripts <= 0) continue;    /* nothing to be stuck about */

        DWORD now             = GetTickCount();
        DWORD since_detour    = now - g_lastDetourFireTick;
        DWORD since_attempt   = now - g_lastPumpAttemptTick;
        DWORD since_progress  = now - g_lastPumpProgressTick;
        DWORD since_last_reset = now - last_reset_tick;
        DWORD exec_start      = g_bridgeExecStartTick;
        int   fired           = 0;
        const char* diag      = NULL;

        /* Path A — hung-inside-exec: the game thread is blocked inside
         * LuaDoString (typically a native call from Lua that never returned
         * — SetSwfFile on a wedged D3D device, an infinite Lua loop, etc.).
         * When this happens, the same thread that runs our hooked detours
         * is stuck, so no more detours can fire and the since_detour guard
         * in Path B would incorrectly bail. Check this first, independent
         * of detour activity. */
        if (exec_start != 0 && (now - exec_start) > (DWORD)stuck_ms) {
            if (last_reset_tick == 0 || since_last_reset >= (DWORD)(stuck_ms / 2)) {
                diag  = "in-bridge-exec-not-returning (native call from Lua hung)";
                fired = 1;
                m2_logf("[!] lua_bridge:   exec_elapsed=%lums",
                        (unsigned long)(now - exec_start));
            }
        }

        /* Path B — detour-visible stuck states: hotWork stuck at 0 or the
         * pump entering but not draining. Requires detours to have fired
         * recently to distinguish real stalls from legitimate pauses. */
        if (!fired) {
            if (since_detour > 2000) continue;
            if (since_progress < (DWORD)stuck_ms) continue;
            if (last_reset_tick != 0 && since_last_reset < (DWORD)(stuck_ms / 2)) continue;

            if (since_attempt > (DWORD)stuck_ms) {
                diag = "hotWork-stuck-at-0 (GatedPump not entering slow path)";
            } else {
                diag = "PumpQueue-not-draining (t_inBridgeExec stuck or L invalid)";
            }
            fired = 1;
        }

        m2_logf("[!] lua_bridge: WATCHDOG stuck-state detected — pattern: %s", diag);
        m2_logf("[!] lua_bridge:   hotWork=%d PendingScripts=%d "
                "since_detour=%lums since_attempt=%lums since_progress=%lums",
                (int)g_hotWork, (int)g_PendingScripts,
                (unsigned long)since_detour,
                (unsigned long)since_attempt,
                (unsigned long)since_progress);
        m2_logf("[!] lua_bridge:   g_LuaState=%p", g_LuaState);

        /* Full-hammer reset. All three actions are individually safe.
         * Non-escalating: cost of over-resetting is one extra re-capture
         * cycle on the next detour, no user-visible harm. */
        g_hotWork = 1;
        InterlockedExchange(&g_watchdogForceClearTLS, 1);
        g_LuaState = NULL;
        memset(g_seenL, 0, sizeof(g_seenL));
        last_reset_tick = now;

        m2_logf("[*] lua_bridge: WATCHDOG reset applied "
                "(hotWork=1, force-clear TLS, clear g_LuaState + g_seenL)");
    }
    return 0;
}

static DWORD WINAPI LoaderKeyEventThread(LPVOID param) {
    static uint8_t prev_down[256];
    int vk;
    (void)param;
    memset(prev_down, 0, sizeof(prev_down));
    for (;;) {
        /* Sample state every tick regardless of focus so prev_down stays
         * accurate. Only the push is focus-gated — this avoids ghost
         * events when the user Alt+Tabs while holding a key: the sampler
         * observes the eventual up→down while unfocused (no push), then
         * the follow-on down→up on refocus is a real edge with fresh
         * state. */
        BOOL focused = IsGameFocused();
        for (vk = 0; vk < 256; ++vk) {
            SHORT s = GetAsyncKeyState(vk);
            uint8_t is_down = (s & 0x8000) ? 1 : 0;
            if (is_down && !prev_down[vk] && focused) {
                KeyEventsPush((uint8_t)vk);
            }
            prev_down[vk] = is_down;
        }
        Sleep(16); /* ~60 Hz — 3–4× the highest realistic typing rate */
    }
    return 0;
}

static DWORD WINAPI LoaderKeyThread(LPVOID param) {
    (void)param;
    for (;;) {
        int i;
        for (i = 0; i < g_KeyScriptCount; ++i) {
            int vk = g_KeyScripts[i].vk_code;
            if (vk > 0 && vk < 256) {
                int is_down = (GetAsyncKeyState(vk) & 0x8000) != 0;
                if (is_down) {
                    if (!g_KeyScripts[i].was_down) {
                        g_KeyScripts[i].was_down = 1;

                        /* Per-script cooldown gate. If the same script fires
                         * again inside `loader_onkey_cooldown_ms` of its last
                         * queue-push, skip. Purpose: keep non-reentrant
                         * gameplay scripts (menus, cheats that mutate engine
                         * state) safe from human hammer-tapping the hotkey.
                         * DWORD subtraction handles GetTickCount wrap
                         * correctly (~49.7-day cycle). Log the first throttle
                         * per script per session so users learn about it,
                         * then stay silent to avoid log spam. */
                        if (g_loader_onkey_cooldown_ms > 0 &&
                            g_KeyScripts[i].last_fired_tick != 0) {
                            DWORD now     = GetTickCount();
                            DWORD elapsed = now - g_KeyScripts[i].last_fired_tick;
                            if (elapsed < (DWORD)g_loader_onkey_cooldown_ms) {
                                if (!g_KeyScripts[i].throttle_logged) {
                                    g_KeyScripts[i].throttle_logged = 1;
                                    m2_logf("[!] lua_bridge: OnKey '%s' throttled (%s "
                                            "re-fired %lu ms after last press; cooldown = %d ms). "
                                            "Further throttles on this script this session will be silent.",
                                            g_KeyScripts[i].key_name,
                                            g_KeyScripts[i].rel_path,
                                            (unsigned long)elapsed,
                                            g_loader_onkey_cooldown_ms);
                                }
                                continue;
                            }
                        }

                        /* Explicit existence check before fopen. If the .lua
                         * file was deleted after boot (or the ini has a stale
                         * mapping to something that never existed), skip
                         * cleanly rather than proceeding down the read+queue
                         * path — reports have shown that path can destabilize
                         * the game when the file is gone. */
                        DWORD attrs = GetFileAttributesA(g_KeyScripts[i].path);
                        if (attrs == INVALID_FILE_ATTRIBUTES ||
                            (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                            m2_logf("[!] lua_bridge: OnKey '%s' bound to missing file: %s (skipped)",
                                    g_KeyScripts[i].key_name, g_KeyScripts[i].rel_path);
                            continue;
                        }

                        g_KeyScripts[i].last_fired_tick = GetTickCount();

                        // Load script file and queue it
                        FILE* f = fopen(g_KeyScripts[i].path, "rb");
                        if (f) {
                            fseek(f, 0, SEEK_END);
                            long sz = ftell(f);
                            fseek(f, 0, SEEK_SET);
                            
                            if (sz > 0 && sz < 1024 * 1024) {
                                char* buf = (char*)malloc(sz + 1);
                                if (buf) {
                                    size_t read_bytes = fread(buf, 1, sz, f);
                                    buf[read_bytes] = '\0';
                                    
                                    m2_logf("[*] lua_bridge: OnKey hotkey '%s' pressed. Queuing script %s", 
                                            g_KeyScripts[i].key_name, g_KeyScripts[i].rel_path);
                                    InQueuePush(buf, read_bytes);
                                    
                                    free(buf);
                                }
                            }
                            fclose(f);
                        }
                    }
                } else {
                    g_KeyScripts[i].was_down = 0;
                }
            }
        }
        Sleep(33); // 30Hz polling rate
    }
    return 0;
}

static void InitializeKeyScripts(void) {
    char exe_dir[MAX_PATH];
    char folder_path[MAX_PATH];
    char loader_ini_path[MAX_PATH];
    char* slash;
    int i;
    
    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(folder_path, sizeof(folder_path), "%sscripts\\OnKey\\", exe_dir);
    m2_module_path(g_hModule, "lua_loader.ini", loader_ini_path, sizeof(loader_ini_path));
    EnsureLoaderIniHeader(loader_ini_path);

    LuaScriptFile temp_files[MAX_SCRIPTS];
    int file_count = 0;
    CollectScriptsRecursive(folder_path, "", temp_files, &file_count, MAX_SCRIPTS);

    g_KeyScriptCount = 0;

    if (file_count == 0) {
        m2_logf("[*] lua_bridge: No scripts found in scripts/OnKey/");
        return;
    }

    qsort(temp_files, file_count, sizeof(LuaScriptFile), CompareAlphabetical);

    for (i = 0; i < file_count && g_KeyScriptCount < MAX_SCRIPTS; ++i) {
        char key_name[64];
        
        GetPrivateProfileStringA("OnKey", temp_files[i].rel_path, "", key_name, sizeof(key_name), loader_ini_path);
        
        if (key_name[0] == '\0') {
            ExtractDefaultKey(temp_files[i].path, key_name, sizeof(key_name));
            WritePrivateProfileStringA("OnKey", temp_files[i].rel_path, key_name, loader_ini_path);
        }

        strncpy(g_KeyScripts[g_KeyScriptCount].path, temp_files[i].path, sizeof(g_KeyScripts[g_KeyScriptCount].path) - 1);
        g_KeyScripts[g_KeyScriptCount].path[sizeof(g_KeyScripts[g_KeyScriptCount].path) - 1] = '\0';

        strncpy(g_KeyScripts[g_KeyScriptCount].rel_path, temp_files[i].rel_path, sizeof(g_KeyScripts[g_KeyScriptCount].rel_path) - 1);
        g_KeyScripts[g_KeyScriptCount].rel_path[sizeof(g_KeyScripts[g_KeyScriptCount].rel_path) - 1] = '\0';

        strncpy(g_KeyScripts[g_KeyScriptCount].key_name, key_name, sizeof(g_KeyScripts[g_KeyScriptCount].key_name) - 1);
        g_KeyScripts[g_KeyScriptCount].key_name[sizeof(g_KeyScripts[g_KeyScriptCount].key_name) - 1] = '\0';

        g_KeyScripts[g_KeyScriptCount].vk_code = ResolveKeyName(key_name);
        g_KeyScripts[g_KeyScriptCount].was_down = 0;

        m2_logf("[*] lua_bridge: Registered OnKey script: scripts/OnKey/%s bound to '%s' (VK 0x%X)", 
                temp_files[i].rel_path, key_name, g_KeyScripts[g_KeyScriptCount].vk_code);

        g_KeyScriptCount++;
    }

    CreateThread(NULL, 0, LoaderKeyThread, NULL, 0, NULL);
    m2_logf("[*] lua_bridge: Spawning background hotkey polling thread");
}

static void RegisterTcpLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "Tcp";
    const luaL_Reg* table = tcp_lib;

    __asm__ volatile (
        "push %2\n\t"        // Push table pointer (stack arg)
        "call *%3\n\t"       // Call luaL_register
        "add $4, %%esp\n\t"  // Clean stack (4 bytes)
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    static int logged = 0;
    if (!logged) { logged = 1; m2_logf("[*] lua_bridge: Registered Tcp.Send globally"); }
}

/* ------------------------------------------------------------------------ *
 * Expose Loader.Printf to Lua — a lightweight replacement for the engine's
 * Debug.Printf, aimed at custom scripts that want their own uncluttered log.
 * Debug.Printf is called thousands of times per frame from stock scripts, so
 * routing script debug output there gets drowned out. Loader.Printf writes
 * to a dedicated <module dir>\lua_loader_printf.log instead.
 *
 * Usage from Lua:
 *   Loader.Printf("[give_cash] +10000 cash")
 *   Loader.Printf("tag", "value")   -- multiple string args join tab-separated
 * ------------------------------------------------------------------------ */
static HANDLE            g_LoaderPrintfLog = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION  g_LoaderPrintfMtx;
static int               g_LoaderPrintfMtxInit = 0;

static void InitLoaderPrintfLog(void) {
    char path[MAX_PATH];
    if (!g_LoaderPrintfMtxInit) {
        InitializeCriticalSection(&g_LoaderPrintfMtx);
        g_LoaderPrintfMtxInit = 1;
    }
    m2_module_path(g_hModule, "lua_loader_printf.log", path, sizeof(path));
    g_LoaderPrintfLog = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
                                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_LoaderPrintfLog == INVALID_HANDLE_VALUE) {
        m2_logf("[!] lua_bridge: failed to open %s GLE=%lu",
                path, (unsigned long)GetLastError());
    } else {
        m2_logf("[*] lua_bridge: Loader.Printf log opened at %s", path);
    }
}

static int LuaLoaderPrintf(void* L) {
    char msg[2048];
    int  joined;
    DWORD written;
    size_t len;

    if (g_LoaderPrintfLog == INVALID_HANDLE_VALUE) return 0;

    /* Join every string arg tab-separated (mirrors Lua's print()). Non-string
     * args are silently skipped — matches m2_lua_join_strings semantics.
     * On extraction failure, still emit a marker line so the log tells us
     * the C fn was reached rather than staying silent. */
    joined = m2_lua_join_strings(L, msg, (int)sizeof(msg) - 32);
    if (joined <= 0) {
        len = (size_t)_snprintf_s(msg, sizeof(msg), _TRUNCATE,
                                  "[Loader.Printf: no string args (joined=%d)]", joined);
    } else {
        len = strlen(msg);
    }
    if (len > sizeof(msg) - 2) len = sizeof(msg) - 2;
    msg[len++] = '\r';
    msg[len++] = '\n';

    /* NB: no FlushFileBuffers here — it forces a synchronous disk sync
     * that can stall the game's Lua thread for seconds (AV, HDD, cloud
     * sync). WriteFile alone commits to the OS write cache, which is
     * enough for a live debug log; entries survive normal shutdown. */
    EnterCriticalSection(&g_LoaderPrintfMtx);
    WriteFile(g_LoaderPrintfLog, msg, (DWORD)len, &written, NULL);
    LeaveCriticalSection(&g_LoaderPrintfMtx);

    /* Also mirror this line to the connected WS client as
     * {type:"log",line:"…"} — the live console feed. Strip the trailing
     * \r\n we appended for the log file; the WS side is line-oriented
     * on the receiver so we ship the line contents only. No-op if no
     * WS client is connected. */
    {
        size_t body_len = len;
        if (body_len >= 2 && msg[body_len - 2] == '\r') body_len -= 2;
        else if (body_len >= 1 && msg[body_len - 1] == '\n') body_len -= 1;
        ws_broadcast_typed_line("log", msg, body_len);
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * Loader.GetKeyboardState() — return a 256-byte string where byte[vk] has
 * its high bit set iff virtual-key `vk` is currently pressed. Lua-side:
 *   local s = Loader.GetKeyboardState()
 *   if string.byte(s, VK_SHIFT + 1) >= 128 then ... end
 *
 * Uses GetAsyncKeyState (physical, system-wide) NOT Win32 GetKeyboardState
 * (per-thread message-queue snapshot — would return stale/zero from the
 * game thread). Same call LoaderKeyThread already trusts.
 *
 * Pushes the hand-crafted g_kbStateTString directly onto L->top and
 * advances top by one TValue slot. Safe because the engine reserves at
 * least LUA_MINSTACK slots for every C function frame. See the
 * KeyboardStateTString definition for the buffer-reuse caveats.
 * ------------------------------------------------------------------------ */
static int LuaLoaderGetKeyboardState(void* L) {
    /* Fast path — see the note on LuaLoaderIsKeyDown below. */
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);
    int i;

    for (i = 0; i < 256; ++i) {
        SHORT s = GetAsyncKeyState(i);
        g_kbStateTString.data[i] = (s & 0x8000) ? (char)0x80 : (char)0x00;
    }

    *(void**)top                             = &g_kbStateTString;
    *(int*)(top + TVALUE_TT_OFFSET)          = LUA_TSTRING;
    *(char**)(Lc + LUA_OFF_TOP)              = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.IsKeyDown(vk) — beginner-friendly single-key predicate.
 * Lua-side:
 *   if Loader.IsKeyDown(0x10) then ... end   -- Shift held?
 *
 * Same GetAsyncKeyState-based state as Loader.GetKeyboardState, just
 * scoped to one VK code and returning a plain boolean. Cheaper if the
 * caller only needs one key; also easier to teach.
 * ------------------------------------------------------------------------ */
static int LuaLoaderIsKeyDown(void* L) {
    /* Fast path — no SafeProbe / LooksLikeLuaState. When Lua's own
     * dispatch calls a registered C function, L / base / top are
     * engine-guaranteed valid; reserved LUA_MINSTACK slots at top mean
     * we can push one return value without checking. Dropping the checks
     * saves 6+ VirtualQuery syscalls per call (~15µs → ~1µs). Safe
     * because this function is only reachable via luaL_register-
     * installed dispatch, never called with a caller-supplied L. Same
     * treatment applied below to GetKeyboardState / IsGameFocused /
     * PopKeyEvents / ClearKeyEvents / math.*. */
    char* Lc   = (char*)L;
    char* base = *(char**)(Lc + LUA_OFF_BASE);
    char* top  = *(char**)(Lc + LUA_OFF_TOP);
    int   vk;
    SHORT ks;

    if (!base || (top - base) < TVALUE_SIZE) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;

    vk = (int)*(float*)base;  /* lua_Number = float in this build */
    if (vk < 0 || vk > 255) return 0;

    ks = GetAsyncKeyState(vk);

    *(int*)top                       = (ks & 0x8000) ? 1 : 0;
    *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TBOOLEAN;
    *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.PopKeyEvents() — drain the C-side event ring into a string of
 * raw VK codes (one byte per event), in press order. Empty string if
 * nothing new since last call.
 *
 *   local events = Loader.PopKeyEvents()
 *   for i=1,#events do
 *       local vk = string.byte(events, i)
 *       -- ...dispatch...
 *   end
 *
 * The ring is filled by LoaderKeyEventThread at ~60 Hz across all 256
 * VKs, so a poll-once-per-frame client never misses a keypress the way
 * client-side edge detection on GetKeyboardState does.
 * ------------------------------------------------------------------------ */
static int LuaLoaderPopKeyEvents(void* L) {
    /* Fast path — see the note on LuaLoaderIsKeyDown below. */
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);
    int   n;

    n = KeyEventsPopAll((uint8_t*)g_keyEventsTString.data, KEYEVENT_BUFFER_SIZE);
    g_keyEventsTString.len = (uint32_t)n;

    *(void**)top                     = &g_keyEventsTString;
    *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TSTRING;
    *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.ClearKeyEvents() — drop every buffered event without returning
 * them. Useful right when a chat input opens: call this once, then wait
 * for the user to type, then PopKeyEvents(). Same effect as calling
 * PopKeyEvents() and discarding the result — this just reads more
 * clearly at the call site.
 * ------------------------------------------------------------------------ */
static int LuaLoaderClearKeyEvents(void* L) {
    (void)L;
    if (!g_keyEventMtxInit) return 0;
    EnterCriticalSection(&g_keyEventMtx);
    g_keyEventCount = 0;
    g_keyEventHead  = 0;
    g_keyEventTail  = 0;
    LeaveCriticalSection(&g_keyEventMtx);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * Loader.IsGameFocused() — is the foreground window owned by our
 * process? True for any window belonging to the game (main or dialog);
 * false when Alt+Tabbed to another app.
 *
 * PopKeyEvents already gates its captures on this internally. Exposed
 * here so callers can gate their own logic (e.g. skip heavy work while
 * backgrounded, or wrap raw IsKeyDown queries with focus-awareness).
 * ------------------------------------------------------------------------ */
static int LuaLoaderIsGameFocused(void* L) {
    /* Fast path — see the note on LuaLoaderIsKeyDown below. */
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);

    *(int*)top                       = IsGameFocused() ? 1 : 0;
    *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TBOOLEAN;
    *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Persistence — Loader.SaveVar(key, value) / Loader.LoadVar(key)
 *
 * Simple key-value store that survives game restarts. Values are numbers,
 * strings, or booleans. Stored on disk as `lua_loader_data.ini` next to
 * the .asi, in a human-readable format that users can hand-edit if they
 * want to reset a value:
 *
 *   ; auto-managed by lua-bridge
 *   ; Format: key=type:value  (n=number, s=string, b=boolean 0/1)
 *   MasterCheatMenu_Progress=n:18
 *   MyMod_Setting=s:hardcore
 *   MyMod_TutorialSeen=b:1
 *
 * Namespacing: single flat namespace shared by every script. Wiki docs
 * tell script authors to prefix keys with their script name.
 *
 * Type preservation: SaveVar accepts number/string/boolean, LoadVar
 * returns the same Lua type it was saved as (or nil if the key isn't
 * set). Numbers and booleans are stored inline; strings are heap-
 * allocated FixedTStrings with FIXEDBIT set (GC-ignored, same trick as
 * g_kbStateTString). New string values allocate fresh — old strings are
 * intentionally leaked so any Lua variable still holding a reference to
 * a previous LoadVar result stays valid. Bounded by SaveVar call rate
 * (thousands of calls per session is still ~100 KB, tolerable).
 *
 * Crash safety: SaveVar writes to `lua_loader_data.ini.tmp` and then
 * MoveFileExA(MOVEFILE_REPLACE_EXISTING) — a crash mid-write leaves the
 * old file intact rather than truncating.
 * ------------------------------------------------------------------------ */
#define DATA_KEY_MAX      128
#define DATA_STR_MAX      2048
#define DATA_TYPE_NUMBER  'n'
#define DATA_TYPE_STRING  's'
#define DATA_TYPE_BOOL    'b'

typedef struct DataEntry {
    char    key[DATA_KEY_MAX];
    char    type;      /* 'n' / 's' / 'b' */
    float   num_val;
    int     bool_val;
    void*   str_tstring;   /* FixedTString ptr for type='s', NULL otherwise */
    struct DataEntry* next;
} DataEntry;

static DataEntry*        g_dataDict     = NULL;
static CRITICAL_SECTION  g_dataMtx;
static int               g_dataMtxInit  = 0;
static int               g_dataLoaded   = 0;

/* Allocate a fresh Lua-visible TString for a value. Uses the same layout
 * trick as g_kbStateTString / g_chunkSource — matches Pandemic's packed
 * TValue, marked FIXEDBIT so the engine's GC leaves it alone.
 *
 * Deliberately leaked (never freed). Each SaveVar overwriting an existing
 * key allocates a NEW TString rather than mutating the existing one, so
 * any Lua variable holding a reference to a previous LoadVar result
 * remains valid with the old value. Bounded by write frequency — 1000
 * SaveVar calls with 100-char strings = 100 KB, fine for a game session. */
#pragma pack(push, 4)
typedef struct DataTString {
    void*    next_gc;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[1];   /* flexible; actual allocation is sizeof(struct) + len */
} DataTString;
#pragma pack(pop)

static DataTString* AllocDataTString(const char* value, size_t len) {
    DataTString* ts = (DataTString*)malloc(sizeof(DataTString) + len);
    if (!ts) return NULL;
    ts->next_gc = NULL;
    ts->tt      = (uint8_t)LUA_TSTRING;
    ts->marked  = 0x20 | 0x01;   /* FIXEDBIT | WHITE0BIT */
    ts->reserved= 0;
    ts->_pad    = 0;
    ts->hash    = 0xDA7A0000u | (uint32_t)(len & 0xFFFF);
    ts->len     = (uint32_t)len;
    memcpy(ts->data, value, len);
    return ts;
}

/* Value escaping for the on-disk format. Only backslash, CR, LF need
 * quoting since we use `=` and `:` as delimiters but strip them on
 * parse; user string values containing `=` or `:` round-trip fine. */
static void EscapeValue(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    while (*in && o + 3 < out_size) {
        char c = *in++;
        if (c == '\\')      { out[o++] = '\\'; out[o++] = '\\'; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n';  }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r';  }
        else                { out[o++] = c; }
    }
    out[o] = '\0';
}

static void UnescapeValue(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    while (*in && o + 1 < out_size) {
        char c = *in++;
        if (c == '\\' && *in) {
            char n = *in++;
            if      (n == 'n')  out[o++] = '\n';
            else if (n == 'r')  out[o++] = '\r';
            else if (n == '\\') out[o++] = '\\';
            else                out[o++] = n;      /* unknown escape — pass through */
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}

/* Look up an entry by key. Caller must hold g_dataMtx. Returns NULL if not present. */
static DataEntry* DataDictFind(const char* key) {
    DataEntry* e = g_dataDict;
    while (e) {
        if (strcmp(e->key, key) == 0) return e;
        e = e->next;
    }
    return NULL;
}

/* Insert or update. Caller must hold g_dataMtx. `type` is 'n'/'s'/'b'. */
static DataEntry* DataDictUpsert(const char* key, char type) {
    DataEntry* e = DataDictFind(key);
    if (!e) {
        e = (DataEntry*)malloc(sizeof(DataEntry));
        if (!e) return NULL;
        memset(e, 0, sizeof(*e));
        strncpy(e->key, key, DATA_KEY_MAX - 1);
        e->key[DATA_KEY_MAX - 1] = '\0';
        e->next = g_dataDict;
        g_dataDict = e;
    }
    e->type = type;
    /* Don't null out fields other than the one being written — old
     * str_tstring stays valid for any Lua vars still referencing it. */
    return e;
}

static void PersistDataFileLocked(void) {
    char ini_path[MAX_PATH];
    char tmp_path[MAX_PATH];
    FILE* f;
    DataEntry* e;

    m2_module_path(g_hModule, "lua_loader_data.ini", ini_path, sizeof(ini_path));
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", ini_path);

    f = fopen(tmp_path, "w");
    if (!f) return;

    fputs("; lua_loader_data.ini — auto-managed by lua-bridge Loader.SaveVar/LoadVar\n"
          "; Format: key=type:value   (n=number, s=string, b=boolean 0/1)\n"
          "; Safe to hand-edit while the game is not running; edits made while\n"
          "; the game is running will be overwritten on the next SaveVar.\n\n", f);

    for (e = g_dataDict; e; e = e->next) {
        if (e->type == DATA_TYPE_NUMBER) {
            fprintf(f, "%s=n:%g\n", e->key, (double)e->num_val);
        } else if (e->type == DATA_TYPE_BOOL) {
            fprintf(f, "%s=b:%d\n", e->key, e->bool_val ? 1 : 0);
        } else if (e->type == DATA_TYPE_STRING && e->str_tstring) {
            DataTString* ts = (DataTString*)e->str_tstring;
            char escaped[DATA_STR_MAX * 2 + 4];
            /* Build a null-terminated copy of the TString bytes for EscapeValue. */
            char raw[DATA_STR_MAX + 1];
            size_t n = ts->len < DATA_STR_MAX ? ts->len : DATA_STR_MAX;
            memcpy(raw, ts->data, n);
            raw[n] = '\0';
            EscapeValue(raw, escaped, sizeof(escaped));
            fprintf(f, "%s=s:%s\n", e->key, escaped);
        }
    }
    fclose(f);

    /* Atomic replace so a crash mid-write leaves the old file intact. */
    if (!MoveFileExA(tmp_path, ini_path, MOVEFILE_REPLACE_EXISTING)) {
        m2_logf("[!] lua_bridge: SaveVar persist rename failed (GLE=%lu)",
                (unsigned long)GetLastError());
    }
}

static void LoadDataFileLocked(void) {
    char ini_path[MAX_PATH];
    FILE* f;
    char line[DATA_STR_MAX * 2 + 32];

    m2_module_path(g_hModule, "lua_loader_data.ini", ini_path, sizeof(ini_path));
    f = fopen(ini_path, "r");
    if (!f) return;    /* file doesn't exist yet — first run, empty dict is fine */

    int loaded_count = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Skip blank lines + comments. */
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ';' || *p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char* type_val = eq + 1;

        /* Strip trailing whitespace from key. */
        size_t klen = strlen(p);
        while (klen > 0 && (p[klen - 1] == ' ' || p[klen - 1] == '\t')) p[--klen] = '\0';

        /* type_val looks like `n:18` — first char is type, then colon, then value. */
        if (type_val[0] == '\0' || type_val[1] != ':') continue;
        char type = type_val[0];
        char* raw_val = type_val + 2;

        /* Strip trailing newline from value. */
        size_t vlen = strlen(raw_val);
        while (vlen > 0 && (raw_val[vlen - 1] == '\n' || raw_val[vlen - 1] == '\r')) {
            raw_val[--vlen] = '\0';
        }

        DataEntry* e = DataDictUpsert(p, type);
        if (!e) continue;
        if (type == DATA_TYPE_NUMBER) {
            e->num_val = (float)atof(raw_val);
        } else if (type == DATA_TYPE_BOOL) {
            e->bool_val = (atoi(raw_val) != 0) ? 1 : 0;
        } else if (type == DATA_TYPE_STRING) {
            char unescaped[DATA_STR_MAX + 1];
            UnescapeValue(raw_val, unescaped, sizeof(unescaped));
            size_t ulen = strlen(unescaped);
            e->str_tstring = AllocDataTString(unescaped, ulen);
        }
        loaded_count++;
    }
    fclose(f);
    if (loaded_count > 0) {
        m2_logf("[*] lua_bridge: Loaded %d persisted variable(s) from lua_loader_data.ini",
                loaded_count);
    }
}

static void InitDataDict(void) {
    if (!g_dataMtxInit) {
        InitializeCriticalSection(&g_dataMtx);
        g_dataMtxInit = 1;
    }
    EnterCriticalSection(&g_dataMtx);
    if (!g_dataLoaded) {
        g_dataLoaded = 1;
        LoadDataFileLocked();
    }
    LeaveCriticalSection(&g_dataMtx);
}

/* Loader.SaveVar(sKey, xValue) — accepts number, string, boolean.
 * Persists to disk immediately. Returns nothing. */
static int LuaLoaderSaveVar(void* L) {
    char* Lc; char* base;
    char key[DATA_KEY_MAX];
    int tt_val;
    if (!L) return 0;
    if (m2_lua_nargs(L) < 2) return 0;
    if (m2_lua_arg_string(L, 0, key, sizeof(key)) <= 0) return 0;
    if (!g_dataMtxInit) InitDataDict();

    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base) return 0;
    tt_val = *(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET);

    EnterCriticalSection(&g_dataMtx);
    if (tt_val == LUA_TNUMBER) {
        DataEntry* e = DataDictUpsert(key, DATA_TYPE_NUMBER);
        if (e) e->num_val = *(float*)(base + TVALUE_SIZE);
    } else if (tt_val == LUA_TBOOLEAN) {
        DataEntry* e = DataDictUpsert(key, DATA_TYPE_BOOL);
        if (e) e->bool_val = (*(int*)(base + TVALUE_SIZE) != 0) ? 1 : 0;
    } else if (tt_val == LUA_TSTRING) {
        char sval[DATA_STR_MAX];
        int slen = m2_lua_arg_string(L, 1, sval, sizeof(sval));
        if (slen > 0) {
            DataEntry* e = DataDictUpsert(key, DATA_TYPE_STRING);
            if (e) {
                /* Fresh TString; old one stays alive for any Lua vars still
                 * referencing a prior LoadVar result. Intentional leak. */
                e->str_tstring = AllocDataTString(sval, (size_t)slen);
            }
        }
    } else {
        LeaveCriticalSection(&g_dataMtx);
        return 0;  /* unsupported value type */
    }
    PersistDataFileLocked();
    LeaveCriticalSection(&g_dataMtx);
    return 0;
}

/* Loader.LoadVar(sKey) — returns number/string/boolean (with original
 * type) or nil if the key isn't set. */
static int LuaLoaderLoadVar(void* L) {
    char* Lc; char* top;
    char key[DATA_KEY_MAX];
    DataEntry* e;
    if (!L) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    if (m2_lua_arg_string(L, 0, key, sizeof(key)) <= 0) return 0;
    if (!g_dataMtxInit) InitDataDict();

    Lc  = (char*)L;
    top = *(char**)(Lc + LUA_OFF_TOP);

    EnterCriticalSection(&g_dataMtx);
    e = DataDictFind(key);
    if (!e) {
        LeaveCriticalSection(&g_dataMtx);
        /* Push nil — tt = LUA_TNIL, value doesn't matter. */
        *(int*)top                       = 0;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TNIL;
        *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
        return 1;
    }

    if (e->type == DATA_TYPE_NUMBER) {
        *(float*)top                     = e->num_val;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TNUMBER;
    } else if (e->type == DATA_TYPE_BOOL) {
        *(int*)top                       = e->bool_val ? 1 : 0;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TBOOLEAN;
    } else if (e->type == DATA_TYPE_STRING && e->str_tstring) {
        *(void**)top                     = e->str_tstring;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TSTRING;
    } else {
        LeaveCriticalSection(&g_dataMtx);
        *(int*)top                       = 0;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TNIL;
        *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
        return 1;
    }
    LeaveCriticalSection(&g_dataMtx);
    *(char**)(Lc + LUA_OFF_TOP) = top + TVALUE_SIZE;
    return 1;
}

static const luaL_Reg loader_lib[] = {
    {"Printf",           LuaLoaderPrintf},
    {"WsSend",           LuaLoaderWsSend},
    {"GetKeyboardState", LuaLoaderGetKeyboardState},
    {"IsKeyDown",        LuaLoaderIsKeyDown},
    {"PopKeyEvents",     LuaLoaderPopKeyEvents},
    {"ClearKeyEvents",   LuaLoaderClearKeyEvents},
    {"IsGameFocused",    LuaLoaderIsGameFocused},
    {"SaveVar",          LuaLoaderSaveVar},
    {"LoadVar",          LuaLoaderLoadVar},
    {NULL, NULL}
};

static void RegisterLoaderLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "Loader";
    const luaL_Reg* table = loader_lib;

    __asm__ volatile (
        "push %2\n\t"        // Push table pointer (stack arg)
        "call *%3\n\t"       // Call luaL_register
        "add $4, %%esp\n\t"  // Clean stack (4 bytes)
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    static int logged = 0;
    if (!logged) { logged = 1; m2_logf("[*] lua_bridge: Registered Loader.Printf globally"); }
}

/* ------------------------------------------------------------------------ *
 * math.* — Pandemic's stripped Lua build is missing most of the trig,
 * log, and random helpers a modern script (or an AI-assisted one) will
 * reach for. This section registers real single-precision math functions
 * so scripts can call math.sin, math.sqrt, math.random, etc. natively
 * instead of re-implementing them via Taylor series.
 *
 * The engine's luaL_register reuses the existing `math` global table
 * (Pandemic kept the table — just without most entries), so what's here
 * is additive: math.floor / math.abs / math.max / math.min / etc. that
 * the engine already ships stay untouched. See stdlib_report.txt in the
 * stress harness scratchpad for the full present/missing enumeration
 * that motivated each entry.
 * ------------------------------------------------------------------------ */

/* One-arg → one-return single-precision math wrapper. Fast path: no
 * SafeProbe / LooksLikeLuaState — same reasoning as LuaLoaderIsKeyDown
 * (engine guarantees L/base/top valid when Lua dispatches to a
 * registered C function). Just checks arg count via top-base pointer
 * arithmetic and the arg's type tag. */
#define MATH_ONEARG(fn_name, cfunc)                                          \
    static int LuaMath##fn_name(void* L) {                                    \
        char* Lc   = (char*)L;                                                \
        char* base = *(char**)(Lc + LUA_OFF_BASE);                            \
        char* top  = *(char**)(Lc + LUA_OFF_TOP);                             \
        float x;                                                              \
        if (!base || (top - base) < TVALUE_SIZE) return 0;                    \
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;        \
        x = *(float*)base;                                                    \
        *(float*)top                    = (float)cfunc(x);                    \
        *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;                        \
        *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;                  \
        return 1;                                                             \
    }

/* Two-arg → one-return single-precision math wrapper. */
#define MATH_TWOARG(fn_name, cfunc)                                          \
    static int LuaMath##fn_name(void* L) {                                    \
        char* Lc   = (char*)L;                                                \
        char* base = *(char**)(Lc + LUA_OFF_BASE);                            \
        char* top  = *(char**)(Lc + LUA_OFF_TOP);                             \
        float x, y;                                                           \
        if (!base || (top - base) < TVALUE_SIZE * 2) return 0;                \
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;        \
        if (*(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET) != LUA_TNUMBER)    \
            return 0;                                                         \
        x = *(float*)base;                                                    \
        y = *(float*)(base + TVALUE_SIZE);                                    \
        *(float*)top                    = (float)cfunc(x, y);                 \
        *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;                        \
        *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;                  \
        return 1;                                                             \
    }

MATH_ONEARG(Sin,   sinf)
MATH_ONEARG(Cos,   cosf)
MATH_ONEARG(Tan,   tanf)
MATH_ONEARG(Asin,  asinf)
MATH_ONEARG(Acos,  acosf)
MATH_ONEARG(Atan,  atanf)
MATH_ONEARG(Sinh,  sinhf)
MATH_ONEARG(Cosh,  coshf)
MATH_ONEARG(Tanh,  tanhf)
MATH_ONEARG(Sqrt,  sqrtf)
MATH_ONEARG(Log,   logf)
MATH_ONEARG(Log10, log10f)

MATH_TWOARG(Atan2, atan2f)
MATH_TWOARG(Fmod,  fmodf)

/* ldexp(x, e) — e is naturally an int; Lua passes a number, cast internally. */
static int LuaMathLdexp(void* L) {
    char* Lc; char* base; char* top; float x; int e;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 2) return 0;
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE * 2)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    if (*(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    x = *(float*)base;
    e = (int)*(float*)(base + TVALUE_SIZE);
    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE)) return 0;
    *(float*)top                    = ldexpf(x, e);
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;
    return 1;
}

/* modf(x) → integer_part, fractional_part. Two-return. */
static int LuaMathModf(void* L) {
    char* Lc; char* base; char* top; float x, ipart, fpart;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    x = *(float*)base;
    fpart = modff(x, &ipart);
    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE * 2)) return 0;
    *(float*)top                                     = ipart;
    *(int*)(top + TVALUE_TT_OFFSET)                  = LUA_TNUMBER;
    *(float*)(top + TVALUE_SIZE)                     = fpart;
    *(int*)(top + TVALUE_SIZE + TVALUE_TT_OFFSET)    = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)                      = top + TVALUE_SIZE * 2;
    return 2;
}

/* frexp(x) → mantissa, exponent. Two-return. */
static int LuaMathFrexp(void* L) {
    char* Lc; char* base; char* top; float x, mant; int expo;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    x = *(float*)base;
    mant = frexpf(x, &expo);
    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE * 2)) return 0;
    *(float*)top                                     = mant;
    *(int*)(top + TVALUE_TT_OFFSET)                  = LUA_TNUMBER;
    *(float*)(top + TVALUE_SIZE)                     = (float)expo;
    *(int*)(top + TVALUE_SIZE + TVALUE_TT_OFFSET)    = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)                      = top + TVALUE_SIZE * 2;
    return 2;
}

/* random() → float 0..1
 * random(n) → int 1..n
 * random(m, n) → int m..n
 * Matches stock Lua 5.1 semantics, backed by CRT rand(). */
static int LuaMathRandom(void* L) {
    char* Lc; char* base; char* top;
    int nargs;
    float result;

    if (!L || !LooksLikeLuaState(L)) return 0;
    nargs = m2_lua_nargs(L);
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);

    if (nargs == 0) {
        result = (float)rand() / (float)RAND_MAX;
    } else if (nargs == 1) {
        int upper;
        if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
        upper = (int)*(float*)base;
        if (upper < 1) return 0;
        result = (float)(1 + rand() % upper);
    } else {
        int lo, hi;
        if (!base || !SafeProbe(base, TVALUE_SIZE * 2)) return 0;
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
        if (*(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
        lo = (int)*(float*)base;
        hi = (int)*(float*)(base + TVALUE_SIZE);
        if (hi < lo) return 0;
        result = (float)(lo + rand() % (hi - lo + 1));
    }

    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE)) return 0;
    *(float*)top                    = result;
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;
    return 1;
}

/* randomseed(x) → seed the CRT rand() from a number. No return. */
static int LuaMathRandomseed(void* L) {
    char* base;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    base = *(char**)((char*)L + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    srand((unsigned int)*(float*)base);
    return 0;
}

static const luaL_Reg math_lib[] = {
    {"sin",        LuaMathSin},
    {"cos",        LuaMathCos},
    {"tan",        LuaMathTan},
    {"asin",       LuaMathAsin},
    {"acos",       LuaMathAcos},
    {"atan",       LuaMathAtan},
    {"atan2",      LuaMathAtan2},
    {"sinh",       LuaMathSinh},
    {"cosh",       LuaMathCosh},
    {"tanh",       LuaMathTanh},
    {"sqrt",       LuaMathSqrt},
    {"log",        LuaMathLog},
    {"log10",      LuaMathLog10},
    {"fmod",       LuaMathFmod},
    {"ldexp",      LuaMathLdexp},
    {"modf",       LuaMathModf},
    {"frexp",      LuaMathFrexp},
    {"random",     LuaMathRandom},
    {"randomseed", LuaMathRandomseed},
    {NULL, NULL}
};

static void RegisterMathLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "math";
    const luaL_Reg* table = math_lib;

    __asm__ volatile (
        "push %2\n\t"
        "call *%3\n\t"
        "add $4, %%esp\n\t"
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    static int logged = 0;
    if (!logged) { logged = 1; m2_logf("[*] lua_bridge: Registered 19 math.* functions globally"); }
}

/* ------------------------------------------------------------------------ *
 * Polyfill — Lua-side patch for the two things luaL_register can't give
 * us: constants (math.pi, math.huge) and the missing base function
 * assert. Runs as a small Lua chunk right after RegisterMathLib in every
 * place the register calls happen, so a _G wipe recovers both the
 * functions AND these polyfills on the next pump batch.
 *
 * Idempotent (each define is `if not ... then ... end`), so the cost of
 * running it twice is a compile+pcall of a tiny chunk (~150 µs); at the
 * measured 113 pumps/sec stress ceiling that's ~2% CPU. At realistic
 * REPL rates (<10 pumps/sec) it's negligible.
 * ------------------------------------------------------------------------ */
static const char kPolyfillChunk[] =
    "if math then "
    "  if not math.pi   then math.pi   = 3.14159265358979323846 end "
    "  if not math.huge then math.huge = 1e308 end "
    "end "
    "if not _G.assert then "
    "  _G.assert = function(v, msg) "
    /* level=2 skips the assert function frame so the error message
     * points at the caller of assert (matching stock Lua semantics),
     * not at this polyfill chunk. Critical for debuggable script code. */
    "    if not v then error(msg or 'assertion failed!', 2) end "
    "    return v "
    "  end "
    "end";

static void RunPolyfill(void* L) {
    char buf[512];
    if (!L || !LooksLikeLuaState(L)) return;
    /* No t_inBridgeExec guard here — callers that need re-entry safety
     * (PumpQueue) sit around this, but the polyfill itself is a leaf
     * LuaDoString that saves/restores top+base cleanly. Nesting a leaf
     * inside PumpQueue's LuaDoString would be a problem, but we run it
     * BEFORE the user-chunk LuaDoString, so no nesting. */
    buf[0] = '\0';
    LuaDoString(L, kPolyfillChunk, sizeof(kPolyfillChunk) - 1, buf, sizeof(buf));

    /* Log honestly on first run: LuaDoString writes "[compile] ..." for
     * compile errors and "[bridge] ..." for internal LuaDoString bail-outs
     * (empty chunk, bad L, etc). Either at buf[0] means the polyfill
     * silently didn't apply, and shipping a broken chunk with a "polyfill
     * applied" log line is exactly the kind of silent failure that hides
     * bugs from the next contributor. Note: "[runtime]" on success is
     * expected (Pandemic's pcall leaves stack junk in slot 0), so we do
     * NOT treat it as failure — genuine runtime errors would show up in
     * dev testing when the buggy chunk is first written. */
    int failed = (strncmp(buf, "[compile]", 9) == 0)
              || (strncmp(buf, "[bridge]",  8) == 0);
    static int logged_ok = 0;
    static int logged_fail = 0;
    if (failed) {
        if (!logged_fail) {
            logged_fail = 1;
            m2_logf("[!] lua_bridge: polyfill FAILED to apply: %s", buf);
        }
    } else if (!logged_ok) {
        logged_ok = 1;
        m2_logf("[*] lua_bridge: polyfill applied (math.pi, math.huge, assert)");
    }
}

/* ------------------------------------------------------------------------ *
 * WebSocket transport
 *
 * A browser can't open raw TCP, but it can open a WebSocket, which is
 * just an HTTP upgrade + a framed byte stream. The queue/pump/executor
 * is transport-agnostic, so WS only touches the accept branch and the
 * output fanout. Raw-TCP clients are unaffected.
 *
 * Wire contract (JSON text frames — one message = one request):
 *   client -> bridge   {"id":"q17abc","code":"<lua source>"}
 *   bridge -> client   {"type":"ack","id":"q17abc","status":"queued"}
 *   bridge -> client   {"type":"log","line":"…a Loader.Printf line…"}
 *   bridge -> client   {"type":"ws","line":"…a Loader.WsSend line…"}
 *
 * Results come back via a Lua-side wrapper: the client wraps user code
 * so that after execution it emits a nonce-tagged line via
 * Loader.WsSend (the hidden channel — WS-only, never logged). The
 * client matches its tag on the {type:"ws"} feed. No result-routing
 * plumbing in C; the id lives in Lua space. Same tag trick tools/
 * lua_repl.py uses, just off a WS feed instead of the log file.
 *
 * Only one WS client (or one raw-TCP client) is served at a time. That
 * matches the existing listener's design and keeps the fanout trivial:
 * Loader.Printf / Loader.WsSend check g_wsClient under a mutex and
 * write to that one socket. Multi-client fanout is a future upgrade.
 * ------------------------------------------------------------------------ */

/* GUID from RFC 6455 §1.3 — concatenated with the client's key to
 * derive the Sec-WebSocket-Accept header. */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Frame opcodes we care about. */
#define WS_OP_CONT   0x0
#define WS_OP_TEXT   0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

/* Cap for a single incoming WS message. Matches the raw-TCP chunk_buf
 * (1 MB) so users can send equivalently large chunks. */
#define WS_MAX_MSG   (1024 * 1024)

/* ------------------------------------------------------------------------ *
 * SHA-1 via BCrypt (Windows Vista+). The one-shot BCryptHash isn't in
 * older MinGW bcrypt.h, so use the three-call sequence
 * (CreateHash → HashData → FinishHash → DestroyHash) which is present
 * on every bcrypt version.
 * ------------------------------------------------------------------------ */
static int ws_sha1(const void* in, size_t in_len, unsigned char out[20]) {
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    int ok = 0;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (st < 0 || !hAlg) return 0;
    st = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (st < 0 || !hHash) goto out;
    st = BCryptHashData(hHash, (PUCHAR)in, (ULONG)in_len, 0);
    if (st < 0) goto out;
    st = BCryptFinishHash(hHash, out, 20, 0);
    if (st < 0) goto out;
    ok = 1;
out:
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ------------------------------------------------------------------------ *
 * Base64 via CryptBinaryToStringA. For our fixed 20-byte SHA-1 input,
 * output is exactly 28 chars + NUL — but we pass a big enough buffer
 * anyway and let the API report the length. NOCRLF because we're
 * emitting into an HTTP header, not a MIME body.
 * ------------------------------------------------------------------------ */
static int ws_base64(const void* in, size_t in_len, char* out, size_t out_cap) {
    DWORD cchOut = (DWORD)out_cap;
    if (!CryptBinaryToStringA((const BYTE*)in, (DWORD)in_len,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              out, &cchOut)) return 0;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Blocking send-all wrapper — WS frames are contiguous byte streams;
 * a short send from the OS means we loop until the whole frame is out
 * or the socket dies. Returns 1 on full send, 0 on error/disconnect.
 * ------------------------------------------------------------------------ */
static int ws_send_all(SOCKET c, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    size_t off = 0;
    while (off < len) {
        int n = send(c, p + off, (int)(len - off), 0);
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

/* Blocking recv-exact wrapper. Returns 1 on full read, 0 on
 * error/disconnect. */
static int ws_recv_all(SOCKET c, void* buf, size_t len) {
    char* p = (char*)buf;
    size_t off = 0;
    while (off < len) {
        int n = recv(c, p + off, (int)(len - off), 0);
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Send a server frame (unmasked). opcode = WS_OP_TEXT / WS_OP_PONG /
 * WS_OP_CLOSE. Payload len chooses 7 / 16 / 64-bit length encoding per
 * RFC 6455 §5.2. Returns 1 on success, 0 on socket error.
 *
 * Not thread-safe on its own — WS output paths (server thread, game
 * thread fanouts) synchronize on g_wsClientMtx before calling this so
 * two writers can't interleave frame bytes.
 * ------------------------------------------------------------------------ */
static int ws_send_frame(SOCKET c, int opcode, const void* payload, size_t len) {
    unsigned char hdr[14];
    size_t hdr_len;

    hdr[0] = (unsigned char)(0x80 | (opcode & 0x0F));       /* FIN | opcode */

    if (len < 126) {
        hdr[1] = (unsigned char)len;
        hdr_len = 2;
    } else if (len < 65536) {
        hdr[1] = 126;
        hdr[2] = (unsigned char)((len >> 8) & 0xFF);
        hdr[3] = (unsigned char)(len & 0xFF);
        hdr_len = 4;
    } else {
        uint64_t L = (uint64_t)len;
        hdr[1] = 127;
        hdr[2] = (unsigned char)((L >> 56) & 0xFF);
        hdr[3] = (unsigned char)((L >> 48) & 0xFF);
        hdr[4] = (unsigned char)((L >> 40) & 0xFF);
        hdr[5] = (unsigned char)((L >> 32) & 0xFF);
        hdr[6] = (unsigned char)((L >> 24) & 0xFF);
        hdr[7] = (unsigned char)((L >> 16) & 0xFF);
        hdr[8] = (unsigned char)((L >> 8) & 0xFF);
        hdr[9] = (unsigned char)(L & 0xFF);
        hdr_len = 10;
    }

    if (!ws_send_all(c, hdr, hdr_len)) return 0;
    if (len > 0 && !ws_send_all(c, payload, len)) return 0;
    return 1;
}

/* Send a WS text frame. Convenience wrapper. */
static int ws_send_text(SOCKET c, const void* payload, size_t len) {
    return ws_send_frame(c, WS_OP_TEXT, payload, len);
}

/* ------------------------------------------------------------------------ *
 * Receive one full text message. Assembles continuation frames if any,
 * auto-handles ping (replies with pong) and close (sends close back
 * and returns 0). Returns:
 *   >0 = payload length in bytes (written to out, NUL-terminated)
 *   0  = connection closed cleanly (client sent close or hit socket EOF)
 *   -1 = protocol error / malformed frame / oversize
 * ------------------------------------------------------------------------ */
static int ws_recv_message(SOCKET c, char* out, size_t out_cap) {
    size_t total = 0;
    int    first_opcode = -1;

    for (;;) {
        unsigned char hdr[2];
        int    fin;
        int    opcode;
        int    masked;
        size_t plen;
        unsigned char mask[4];

        if (!ws_recv_all(c, hdr, 2)) return 0;
        fin    = (hdr[0] & 0x80) != 0;
        opcode =  hdr[0] & 0x0F;
        masked = (hdr[1] & 0x80) != 0;
        plen   =  hdr[1] & 0x7F;

        if (plen == 126) {
            unsigned char ext[2];
            if (!ws_recv_all(c, ext, 2)) return 0;
            plen = ((size_t)ext[0] << 8) | (size_t)ext[1];
        } else if (plen == 127) {
            unsigned char ext[8];
            uint64_t L = 0;
            int i;
            if (!ws_recv_all(c, ext, 8)) return 0;
            for (i = 0; i < 8; ++i) L = (L << 8) | ext[i];
            if (L > (uint64_t)WS_MAX_MSG) return -1;
            plen = (size_t)L;
        }

        /* Per RFC 6455 §5.1, clients MUST mask. Reject unmasked
         * client frames — the alternative is silent corruption. */
        if (!masked) return -1;
        if (!ws_recv_all(c, mask, 4)) return 0;

        /* Control frames (opcode >= 0x8) can be interleaved with a
         * fragmented data message and have their own payload. Handle
         * them fully here (auto-pong / close), then continue the loop
         * to collect the outer data message. */
        if (opcode >= 0x8) {
            unsigned char cpl[125];        /* control frames are <= 125 bytes */
            size_t i;
            if (plen > sizeof(cpl)) return -1;
            if (plen > 0 && !ws_recv_all(c, cpl, plen)) return 0;
            for (i = 0; i < plen; ++i) cpl[i] ^= mask[i & 3];

            if (opcode == WS_OP_PING) {
                EnterCriticalSection(&g_wsClientMtx);
                ws_send_frame(c, WS_OP_PONG, cpl, plen);
                LeaveCriticalSection(&g_wsClientMtx);
                continue;
            }
            if (opcode == WS_OP_CLOSE) {
                EnterCriticalSection(&g_wsClientMtx);
                ws_send_frame(c, WS_OP_CLOSE, cpl, plen);  /* echo back per §5.5.1 */
                LeaveCriticalSection(&g_wsClientMtx);
                return 0;
            }
            /* WS_OP_PONG: nothing to do — we never originate pings. */
            continue;
        }

        /* Data frame. First fragment sets the opcode; continuations
         * must use WS_OP_CONT. */
        if (first_opcode == -1) {
            first_opcode = opcode;
            if (opcode != WS_OP_TEXT && opcode != WS_OP_BINARY) return -1;
        } else {
            if (opcode != WS_OP_CONT) return -1;
        }

        if (plen > 0) {
            size_t i;
            if (total + plen >= out_cap) return -1;
            if (!ws_recv_all(c, out + total, plen)) return 0;
            for (i = 0; i < plen; ++i) out[total + i] ^= mask[i & 3];
            total += plen;
        }

        if (fin) {
            out[total] = '\0';
            return (int)total;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * Handshake: parse an HTTP GET, extract Sec-WebSocket-Key, respond
 * with 101 Switching Protocols. `peek` holds bytes already read from
 * the socket (up to peek_len); everything up through the terminating
 * "\r\n\r\n" must be present or we bail. Returns 1 on 101 sent, 0 on
 * malformed / not a WS upgrade / socket error.
 * ------------------------------------------------------------------------ */
static int ws_do_handshake(SOCKET c, const char* peek, size_t peek_len) {
    char req[8192];
    size_t rlen = 0;
    const char* key_hdr;
    const char* key_start;
    const char* key_end;
    char key[128];
    size_t key_len;
    unsigned char sha[20];
    char accept[64];
    char concat[256];
    size_t concat_len;
    char resp[512];
    int resp_len;

    /* Seed the request buffer with what's already been peeked, then
     * read the rest up to \r\n\r\n. */
    if (peek_len >= sizeof(req)) return 0;
    memcpy(req, peek, peek_len);
    rlen = peek_len;

    while (rlen + 1 < sizeof(req)) {
        int n;
        req[rlen] = '\0';
        if (rlen >= 4 && strstr(req, "\r\n\r\n")) break;
        n = recv(c, req + rlen, (int)(sizeof(req) - rlen - 1), 0);
        if (n <= 0) return 0;
        rlen += (size_t)n;
    }
    req[rlen] = '\0';

    /* Locate the Sec-WebSocket-Key header (case-insensitive per RFC
     * 2616; we use _strnicmp for a simple substring pass). */
    {
        const char* p = req;
        const char* needle = "Sec-WebSocket-Key:";
        size_t nlen = strlen(needle);
        key_hdr = NULL;
        while (*p) {
            if (_strnicmp(p, needle, nlen) == 0) { key_hdr = p + nlen; break; }
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
        }
        if (!key_hdr) return 0;
    }
    while (*key_hdr == ' ' || *key_hdr == '\t') key_hdr++;
    key_start = key_hdr;
    key_end = key_start;
    while (*key_end && *key_end != '\r' && *key_end != '\n') key_end++;
    key_len = (size_t)(key_end - key_start);
    if (key_len == 0 || key_len >= sizeof(key)) return 0;
    memcpy(key, key_start, key_len);
    key[key_len] = '\0';

    /* Sec-WebSocket-Accept = base64(sha1(key + WS_GUID)) */
    concat_len = key_len + strlen(WS_GUID);
    if (concat_len >= sizeof(concat)) return 0;
    memcpy(concat, key, key_len);
    memcpy(concat + key_len, WS_GUID, strlen(WS_GUID));
    if (!ws_sha1(concat, concat_len, sha)) return 0;
    if (!ws_base64(sha, 20, accept, sizeof(accept))) return 0;

    resp_len = _snprintf_s(resp, sizeof(resp), _TRUNCATE,
                           "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n"
                           "\r\n",
                           accept);
    if (resp_len <= 0) return 0;
    return ws_send_all(c, resp, (size_t)resp_len);
}

/* ------------------------------------------------------------------------ *
 * JSON — minimal helpers, scoped to exactly what the wire contract
 * needs. Not a full parser: we look up two known string keys ("id",
 * "code") and unescape their values; nothing else is exercised.
 * ------------------------------------------------------------------------ */

/* Skip JSON whitespace at *p (advances the pointer in-place). */
static void js_skip_ws(const char** p, const char* end) {
    while (*p < end) {
        char ch = **p;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') (*p)++;
        else return;
    }
}

/* Parse a JSON string starting at **p (must be pointing at '"').
 * Writes unescaped bytes to out (up to out_cap-1), NUL-terminates, and
 * advances *p to just past the closing quote. Returns bytes written,
 * or -1 on malformed / overflow. Handles \" \\ \/ \n \r \t \b \f and
 * \uXXXX for basic Latin (>0xFF is transcoded to '?' — the bridge
 * doesn't need Unicode fidelity for our two fields). */
static int js_parse_string(const char** p, const char* end, char* out, size_t out_cap) {
    size_t o = 0;
    if (*p >= end || **p != '"') return -1;
    (*p)++;
    while (*p < end) {
        char ch = **p;
        if (ch == '"') { (*p)++; if (o < out_cap) out[o] = '\0'; return (int)o; }
        if (ch == '\\') {
            (*p)++;
            if (*p >= end) return -1;
            {
                char esc = **p;
                (*p)++;
                if (o + 1 >= out_cap) return -1;
                switch (esc) {
                    case '"':  out[o++] = '"';  break;
                    case '\\': out[o++] = '\\'; break;
                    case '/':  out[o++] = '/';  break;
                    case 'n':  out[o++] = '\n'; break;
                    case 'r':  out[o++] = '\r'; break;
                    case 't':  out[o++] = '\t'; break;
                    case 'b':  out[o++] = '\b'; break;
                    case 'f':  out[o++] = '\f'; break;
                    case 'u': {
                        unsigned int v = 0;
                        int i;
                        if (*p + 4 > end) return -1;
                        for (i = 0; i < 4; ++i) {
                            char h = (*p)[i];
                            v <<= 4;
                            if (h >= '0' && h <= '9') v |= (h - '0');
                            else if (h >= 'a' && h <= 'f') v |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') v |= (h - 'A' + 10);
                            else return -1;
                        }
                        (*p) += 4;
                        out[o++] = (v <= 0xFF) ? (char)v : '?';
                        break;
                    }
                    default: return -1;
                }
            }
        } else {
            if (o + 1 >= out_cap) return -1;
            out[o++] = ch;
            (*p)++;
        }
    }
    return -1;
}

/* Extract id and code from {"id":"…","code":"…"}. Whitespace-tolerant.
 * Non-string fields and other keys are silently skipped. Returns 1 on
 * success (both fields found), 0 otherwise. */
static int ws_parse_request(const char* body, size_t body_len,
                            char* id_out, size_t id_cap,
                            char* code_out, size_t code_cap) {
    const char* p   = body;
    const char* end = body + body_len;
    int have_id = 0, have_code = 0;

    js_skip_ws(&p, end);
    if (p >= end || *p != '{') return 0;
    p++;

    for (;;) {
        char key[32];
        int kl;

        js_skip_ws(&p, end);
        if (p >= end) return 0;
        if (*p == '}') { p++; break; }

        kl = js_parse_string(&p, end, key, sizeof(key));
        if (kl < 0) return 0;
        js_skip_ws(&p, end);
        if (p >= end || *p != ':') return 0;
        p++;
        js_skip_ws(&p, end);

        if (strcmp(key, "id") == 0) {
            int r = js_parse_string(&p, end, id_out, id_cap);
            if (r < 0) return 0;
            have_id = 1;
        } else if (strcmp(key, "code") == 0) {
            int r = js_parse_string(&p, end, code_out, code_cap);
            if (r < 0) return 0;
            have_code = 1;
        } else {
            /* Skip an unknown value. We only need strings in practice,
             * but handle numbers / booleans / null defensively. */
            if (*p == '"') {
                char sink[256];
                if (js_parse_string(&p, end, sink, sizeof(sink)) < 0) return 0;
            } else {
                while (p < end && *p != ',' && *p != '}') p++;
            }
        }

        js_skip_ws(&p, end);
        if (p >= end) return 0;
        if (*p == ',') { p++; continue; }
        if (*p == '}') { p++; break; }
        return 0;
    }

    return have_id && have_code;
}

/* Escape a string into JSON: outputs to *dst (advanced in-place) up to
 * dst_end. Backslash / quote / control chars are escaped per RFC 8259.
 * Non-ASCII bytes are passed through raw (the wire is UTF-8; the
 * upstream data is already valid UTF-8 in practice — Loader.Printf
 * output is ASCII/Latin plus whatever mods pass through). Returns 1
 * on success, 0 on buffer overflow. */
static int js_escape_into(const char* src, size_t src_len, char** dst, char* dst_end) {
    size_t i;
    char* d = *dst;
    for (i = 0; i < src_len; ++i) {
        unsigned char ch = (unsigned char)src[i];
        if (ch == '\\' || ch == '"') {
            if (d + 2 > dst_end) return 0;
            *d++ = '\\'; *d++ = (char)ch;
        } else if (ch == '\n') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'n'; }
          else if (ch == '\r') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'r'; }
          else if (ch == '\t') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 't'; }
          else if (ch == '\b') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'b'; }
          else if (ch == '\f') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'f'; }
          else if (ch < 0x20) {
            if (d + 6 > dst_end) return 0;
            _snprintf_s(d, 7, _TRUNCATE, "\\u%04x", ch);
            d += 6;
        } else {
            if (d + 1 > dst_end) return 0;
            *d++ = (char)ch;
        }
    }
    *dst = d;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Broadcast helpers — called from the game thread inside Loader.Printf
 * and Loader.WsSend. Both take g_wsClientMtx (which also serializes
 * frame writes against the socket thread's own sends). If no client is
 * connected, no-op. If send fails, close the socket immediately so
 * the server thread's recv sees EOF and clears g_wsClient properly.
 * ------------------------------------------------------------------------ */
static void ws_broadcast_typed_line(const char* type, const char* line, size_t line_len) {
    char buf[2560];              /* enough for a full 2 KB Loader.Printf line + envelope */
    char* d = buf;
    char* de = buf + sizeof(buf);
    size_t prefix_len;
    size_t suffix_len;
    const char* prefix_a = "{\"type\":\"";
    const char* prefix_b = "\",\"line\":\"";
    const char* suffix   = "\"}";
    SOCKET s;

    /* Fast bail before we do any work if no WS client is connected. */
    if (!g_wsClientMtxInit) return;
    EnterCriticalSection(&g_wsClientMtx);
    s = g_wsClient;
    if (s == INVALID_SOCKET) { LeaveCriticalSection(&g_wsClientMtx); return; }

    prefix_len = strlen(prefix_a);
    if (d + prefix_len > de) goto out;
    memcpy(d, prefix_a, prefix_len); d += prefix_len;

    {
        size_t tlen = strlen(type);
        if (d + tlen > de) goto out;
        memcpy(d, type, tlen); d += tlen;
    }

    prefix_len = strlen(prefix_b);
    if (d + prefix_len > de) goto out;
    memcpy(d, prefix_b, prefix_len); d += prefix_len;

    if (!js_escape_into(line, line_len, &d, de)) goto out;

    suffix_len = strlen(suffix);
    if (d + suffix_len > de) goto out;
    memcpy(d, suffix, suffix_len); d += suffix_len;

    if (!ws_send_text(s, buf, (size_t)(d - buf))) {
        /* Send failed — client disconnected mid-write. Close the
         * socket so the server thread's recv wakes up. */
        closesocket(s);
        g_wsClient = INVALID_SOCKET;
    }

out:
    LeaveCriticalSection(&g_wsClientMtx);
}

/* ------------------------------------------------------------------------ *
 * Loader.WsSend(str, ...) — the HIDDEN channel. Same join semantics as
 * Loader.Printf (tab-separated string args), but NEVER writes the log
 * file. Broadcasts each call as {type:"ws",line:"…"} to the connected
 * WS client if any; no-op otherwise. This is what tagged results ride
 * on: the client wraps user code so the tagged reply lands here,
 * invisible to lua_loader_printf.log.
 * ------------------------------------------------------------------------ */
static int LuaLoaderWsSend(void* L) {
    char msg[2048];
    int  joined = m2_lua_join_strings(L, msg, (int)sizeof(msg) - 2);
    if (joined <= 0) return 0;
    ws_broadcast_typed_line("ws", msg, strlen(msg));
    return 0;
}

/* ------------------------------------------------------------------------ *
 * WS session loop. One WS client at a time. Receives JSON messages,
 * parses {id, code}, queues code, sends the ack immediately, then
 * loops. Log/ws-send fanout happens on the game thread via
 * ws_broadcast_typed_line — this thread only handles the input side.
 *
 * The pump path's result_buf still appends to g_outBuf (the raw-TCP
 * output channel) but we don't forward that to the WS client (result
 * routing goes via Loader.WsSend from the Lua wrapper). We do drain
 * g_outBuf silently so it can't grow unbounded across many chunks.
 * ------------------------------------------------------------------------ */
static void ws_serve_client(SOCKET c) {
    char msg[WS_MAX_MSG];
    char id[128];
    char* code = NULL;
    const size_t code_cap = WS_MAX_MSG;

    code = (char*)malloc(code_cap);
    if (!code) { m2_logf("[!] lua_bridge: ws: OOM allocating code buffer"); return; }

    EnterCriticalSection(&g_wsClientMtx);
    g_wsClient = c;
    LeaveCriticalSection(&g_wsClientMtx);
    m2_logf("[*] lua_bridge: ws: client connected");

    for (;;) {
        int r;
        char ack[192];
        int  ack_len;

        /* Discard any pending raw-TCP output that accumulated during
         * this session — the WS client uses Loader.WsSend for results,
         * not the raw-TCP result_buf. Prevents unbounded growth of
         * g_outBuf across long WS sessions. */
        EnterCriticalSection(&g_outMtx);
        if (g_outBuf_len > 0) {
            g_outBuf_len = 0;
            if (g_outBuf) g_outBuf[0] = '\0';
        }
        LeaveCriticalSection(&g_outMtx);

        r = ws_recv_message(c, msg, sizeof(msg));
        if (r <= 0) break;                        /* clean close or error */

        id[0] = '\0';
        code[0] = '\0';
        if (!ws_parse_request(msg, (size_t)r, id, sizeof(id), code, code_cap)) {
            m2_logf("[!] lua_bridge: ws: rejected malformed request (%d bytes)", r);
            continue;
        }

        InQueuePush(code, strlen(code));
        m2_logf("[+] lua_bridge: ws: queued chunk (id=%s, %zu bytes)", id, strlen(code));

        ack_len = _snprintf_s(ack, sizeof(ack), _TRUNCATE,
                              "{\"type\":\"ack\",\"id\":\"%s\",\"status\":\"queued\"}", id);
        if (ack_len > 0) {
            EnterCriticalSection(&g_wsClientMtx);
            if (!ws_send_text(c, ack, (size_t)ack_len)) {
                LeaveCriticalSection(&g_wsClientMtx);
                break;
            }
            LeaveCriticalSection(&g_wsClientMtx);
        }
    }

    EnterCriticalSection(&g_wsClientMtx);
    if (g_wsClient == c) g_wsClient = INVALID_SOCKET;
    LeaveCriticalSection(&g_wsClientMtx);
    m2_logf("[*] lua_bridge: ws: client disconnected");
    free(code);
}

/* ------------------------------------------------------------------------ *
 * TCP REPL server
 *
 * Protocol (matches tools/lua_repl.py and tools/lua_console.py in the
 * upstream Merc2Reborn project):
 *   - Client connects to g_repl_host:g_repl_port.
 *   - Client sends one or more lines, terminated by a line containing
 *     literal "<<<RUN>>>". The lines preceding the marker form the
 *     chunk to execute.
 *   - Server queues the chunk and replies "[queued]" immediately.
 *   - Whenever a pump source fires, the queued chunk runs against the
 *     captured L. The result is written back as one or more lines,
 *     followed by a line containing "<<<END>>>".
 *
 * When g_ws_enabled=1 (the default), the first bytes of each accepted
 * connection are peeked. If they start with "GET ", the connection is
 * upgraded to WebSocket via ws_do_handshake + ws_serve_client. Anything
 * else falls through to the raw-TCP loop below, unchanged.
 * ------------------------------------------------------------------------ */
#define BRIDGE_SENTINEL   "<<<RUN>>>"
#define BRIDGE_END_MARKER "<<<END>>>"

static DWORD WINAPI BridgeServerThread(LPVOID arg) {
    WSADATA w;
    SOCKET srv, c;
    struct sockaddr_in addr;
    BOOL reuse = TRUE;
    (void)arg;

    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[!] lua_bridge: WSAStartup failed");
        return 1;
    }
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) {
        m2_logf("[!] lua_bridge: socket() failed GLE=%lu", (unsigned long)WSAGetLastError());
        return 1;
    }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)g_repl_port);
    inet_pton(AF_INET, g_repl_host, &addr.sin_addr);
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 1) != 0) {
        m2_logf("[!] lua_bridge: bind/listen on %s:%d failed GLE=%lu",
                g_repl_host, g_repl_port, (unsigned long)WSAGetLastError());
        closesocket(srv);
        return 1;
    }
    m2_logf("[*] lua_bridge: listening on %s:%d", g_repl_host, g_repl_port);

    for (;;) {
        char rx[65536];  /* per-line receive buffer; a single line longer
                          * than this wedges the recv loop (recv asks for
                          * 0 more bytes and breaks). 64 KB comfortably
                          * covers realistic Lua chunk lines. */
        char chunk_buf[1048576];  /* 1 MB — matches FixedTString.data */
        size_t chunk_len = 0;
        fd_set fds;
        struct timeval tv;
        int r;
        const char* nl;
        const char* p;
        size_t rx_len = 0;

        c = accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) continue;

        /* Discard any pending raw-TCP output that leaked in from a
         * previous session. The bridge is single-client, so anything
         * in g_outBuf at accept-time is stale — most commonly the
         * result_buf of a chunk a WS client queued then disconnected
         * before its pump run. Cross-session leakage would confuse a
         * fresh raw-TCP client that expects its first byte to be its
         * own [queued] ack. */
        EnterCriticalSection(&g_outMtx);
        if (g_outBuf_len > 0) {
            g_outBuf_len = 0;
            if (g_outBuf) g_outBuf[0] = '\0';
        }
        LeaveCriticalSection(&g_outMtx);

        /* WebSocket peek-and-branch. MSG_PEEK doesn't consume the bytes,
         * so on a match ws_do_handshake starts fresh recv()s that see
         * the full request. Non-match falls through to the raw-TCP
         * loop below with an untouched socket buffer. */
        if (g_ws_enabled) {
            char wsPeek[16];
            int  pn = recv(c, wsPeek, (int)sizeof(wsPeek), MSG_PEEK);
            if (pn >= 4 && memcmp(wsPeek, "GET ", 4) == 0) {
                if (ws_do_handshake(c, NULL, 0)) {
                    ws_serve_client(c);
                } else {
                    m2_logf("[!] lua_bridge: ws: handshake failed");
                }
                closesocket(c);
                continue;
            }
        }

        for (;;) {
            /* Flush pending output */
            EnterCriticalSection(&g_outMtx);
            if (g_outBuf_len > 0) {
                size_t off = 0;
                int send_failed = 0;
                while (off < g_outBuf_len) {
                    int sent = send(c, g_outBuf + off, (int)(g_outBuf_len - off), 0);
                    if (sent <= 0) { send_failed = 1; break; }
                    off += (size_t)sent;
                }
                g_outBuf_len = 0;
                if (g_outBuf) g_outBuf[0] = '\0';
                if (send_failed) { LeaveCriticalSection(&g_outMtx); break; }
            }
            LeaveCriticalSection(&g_outMtx);

            FD_ZERO(&fds);
            FD_SET(c, &fds);
            tv.tv_sec = 0; tv.tv_usec = 50000;
            r = select(0, &fds, NULL, NULL, &tv);
            if (r < 0) break;
            if (r == 0) continue;

            {
                int n = recv(c, rx + rx_len, (int)(sizeof(rx) - rx_len - 1), 0);
                if (n <= 0) break;
                rx_len += (size_t)n;
                rx[rx_len] = '\0';
            }

            /* Process complete lines */
            p = rx;
            while ((nl = (const char*)memchr(p, '\n', rx + rx_len - p)) != NULL) {
                size_t line_len = (size_t)(nl - p);
                /* Strip trailing \r if present */
                if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
                if (line_len == sizeof(BRIDGE_SENTINEL) - 1 &&
                    memcmp(p, BRIDGE_SENTINEL, line_len) == 0) {
                    /* Submit accumulated chunk */
                    if (chunk_len > 0) {
                        m2_logf("[+] lua_bridge: queued chunk (%zu bytes)", chunk_len);
                        InQueuePush(chunk_buf, chunk_len);
                        OutAppend("[queued]", 8);
                    }
                    chunk_len = 0;
                } else {
                    /* Append line + newline to chunk */
                    if (chunk_len + line_len + 1 < sizeof(chunk_buf)) {
                        memcpy(chunk_buf + chunk_len, p, line_len);
                        chunk_len += line_len;
                        chunk_buf[chunk_len++] = '\n';
                    }
                }
                p = nl + 1;
            }
            /* Shift unconsumed bytes to front */
            {
                size_t consumed = (size_t)(p - rx);
                if (consumed > 0 && consumed < rx_len) {
                    memmove(rx, rx + consumed, rx_len - consumed);
                }
                rx_len -= consumed;
                rx[rx_len] = '\0';
            }
        }

        closesocket(c);
    }
}

/* ------------------------------------------------------------------------ *
 * INI config
 * ------------------------------------------------------------------------ */
/* m2_ini_parse's callback signature is (ud, key, value) — the parser
 * strips section headers internally and never surfaces them, so we
 * dispatch on the key name alone. Our two keys (`host` and `port`)
 * are unique across the INI's sections so this is fine. */
static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;
    if (_stricmp(key, "host") == 0) {
        strncpy(g_repl_host, value, sizeof(g_repl_host) - 1);
        g_repl_host[sizeof(g_repl_host) - 1] = 0;
    } else if (_stricmp(key, "port") == 0) {
        g_repl_port = atoi(value);
        if (g_repl_port <= 0 || g_repl_port > 65535) g_repl_port = 27050;
    } else if (_stricmp(key, "loader_enabled") == 0) {
        g_loader_enabled = atoi(value);
    } else if (_stricmp(key, "loader_onboot") == 0) {
        g_loader_onboot = atoi(value);
    } else if (_stricmp(key, "loader_onload") == 0) {
        g_loader_onload = atoi(value);
    } else if (_stricmp(key, "loader_delay_ms") == 0) {
        g_loader_delay_ms = atoi(value);
        if (g_loader_delay_ms < 0) g_loader_delay_ms = 0;
    } else if (_stricmp(key, "loader_onkey_cooldown_ms") == 0) {
        g_loader_onkey_cooldown_ms = atoi(value);
        if (g_loader_onkey_cooldown_ms < 0) g_loader_onkey_cooldown_ms = 0;
    } else if (_stricmp(key, "watchdog_stuck_ms") == 0) {
        g_watchdog_stuck_ms = atoi(value);
        if (g_watchdog_stuck_ms < 0) g_watchdog_stuck_ms = 0;
    } else if (_stricmp(key, "websocket_enabled") == 0) {
        g_ws_enabled = atoi(value);
    }
}

/* Baked-in defaults, written to disk if the .ini is missing. Keeps the
 * .asi self-sufficient — users can drop the .asi alone and get a
 * commented, editable config on first launch. */
static const char kDefaultIni[] =
    "; lua-bridge configuration.\n"
    "; Drop this next to lua_bridge.asi in your game folder.\n"
    "\n"
    "[repl]\n"
    "; Host to bind the REPL listener on. 127.0.0.1 = localhost-only,\n"
    "; which is what you want unless you're routing through a tunnel.\n"
    "host = 127.0.0.1\n"
    "\n"
    "; Port for the REPL listener. Matches the default the upstream\n"
    "; tools/lua_repl.py and tools/lua_console.py expect.\n"
    "port = 27050\n"
    "\n"
    "[loader]\n"
    "; Enable or disable the native Lua Loader (1 = enabled, 0 = disabled)\n"
    "loader_enabled = 1\n"
    "\n"
    "; Load scripts in scripts/OnBoot/ once captured (1 = enabled, 0 = disabled)\n"
    "loader_onboot = 1\n"
    "\n"
    "; Load scripts in scripts/OnLoad/ once game enters world (1 = enabled, 0 = disabled)\n"
    "loader_onload = 1\n"
    "\n"
    "; Delay (in milliseconds) between executing consecutive scripts\n"
    "loader_delay_ms = 50\n"
    "\n"
    "; Minimum time (in milliseconds) between the SAME OnKey script re-firing.\n"
    "; Prevents human hammer-tapping the hotkey from queueing multiple back-to-back\n"
    "; runs of the same script, which can crash non-reentrant scripts (menus,\n"
    "; state-mutating cheats, etc). First throttle per script is logged so users\n"
    "; can see it kick in; subsequent throttles are silent to avoid log spam.\n"
    "; Set to 0 to disable the cooldown entirely.\n"
    "loader_onkey_cooldown_ms = 250\n"
    "\n"
    "; Watchdog: if the queue has pending chunks and no pump progress happens\n"
    "; for this many milliseconds (while the game is actively running detours),\n"
    "; a background thread force-resets the bridge's stuck-state candidates\n"
    "; (hotWork, t_inBridgeExec, g_LuaState, seen-set) and logs a comprehensive\n"
    "; diagnostic line. Set to 0 to disable the watchdog entirely.\n"
    "watchdog_stuck_ms = 8000\n"
    "\n"
    "; WebSocket transport (1 = enabled, 0 = disabled). When enabled, the same\n"
    "; listener speaks either raw TCP (existing lua_repl.py / lua_console.py\n"
    "; protocol) or WebSocket — auto-detected from the first bytes. Browser\n"
    "; clients (tools/ess-bridge.js) connect via WS and receive structured\n"
    "; JSON messages: {type:\"ack\"}, {type:\"log\"} (mirrors Loader.Printf),\n"
    "; and {type:\"ws\"} (the hidden Loader.WsSend channel). Disable this if\n"
    "; you want the bridge locked to raw-TCP only.\n"
    "websocket_enabled = 1\n";

static void EnsureIniDefault(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) { fclose(f); return; }        /* user's file wins */
    f = fopen(path, "w");
    if (!f) return;
    fputs(kDefaultIni, f);
    fclose(f);
    m2_logf("[*] lua_bridge: wrote default %s", path);
}

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "lua_bridge_DEV.ini", ini_path, sizeof(ini_path));
    EnsureIniDefault(ini_path);
    m2_ini_parse(ini_path, OnIniKV, NULL);
}

/* ------------------------------------------------------------------------ *
 * Init
 * ------------------------------------------------------------------------ */
static DWORD WINAPI WorkerThread(LPVOID arg) {
    HMODULE mod;
    BYTE* base;
    int hooks_armed = 0;
    int t;

    typedef struct HookSpec {
        DWORD     rva;
        LPVOID    detour;
        LPVOID*   orig;
        const char* name;
        HookKind  kind;
    } HookSpec;
    HookSpec specs[3];

    (void)arg;

    LoadConfig();
    if (g_loader_enabled) {
        EnsureLoaderDirectories();
    }
    InitializeCriticalSection(&g_inMtx);
    InitializeCriticalSection(&g_outMtx);
    InitializeCriticalSection(&g_keyEventMtx);
    g_keyEventMtxInit = 1;
    InitChunkSource();
    InitKeyboardStateTString();
    InitKeyEventsTString();
    InitLoaderPrintfLog();
    InitDataDict();

    mod = GetModuleHandleA(NULL);
    if (!mod) {
        m2_logf("[!] lua_bridge: GetModuleHandle(NULL) returned NULL");
        return 1;
    }
    base = (BYTE*)mod;

    g_rvas = SelectRvas(mod);

    /* Same SecuROM-unpack-wait pattern Merc2Fix uses on the noop stub. */
    {
        BYTE* probe = base + g_rvas->noop_stub;
        for (t = 0; t < 400; t++) {
            int nz = 0, i;
            for (i = 0; i < 8; i++) if (probe[i]) { nz = 1; break; }
            if (nz) break;
            Sleep(25);
        }
    }

    p_luaB_loadstring = (lua_CFunction_t)(base + g_rvas->luaB_loadstring);
    p_luaB_pcall      = (lua_CFunction_t)(base + g_rvas->luaB_pcall);
    m2_logf("[*] lua_bridge: executor armed (loadstring=%p, pcall=%p)",
            p_luaB_loadstring, p_luaB_pcall);

    specs[0].rva = g_rvas->noop_stub;
    specs[0].detour = (LPVOID)&DetourNoopStub;
    specs[0].orig = (LPVOID*)&fpOriginal_NoopStub;
    specs[0].name = "noop-stub (print/SendEvent_*/...)";
    specs[0].kind = HOOK_NOOP_STUB;

    specs[1].rva = g_rvas->luaB_type;
    specs[1].detour = (LPVOID)&DetourLuaType;
    specs[1].orig = (LPVOID*)&fpOriginal_luaB_type;
    specs[1].name = "luaB_type";
    specs[1].kind = HOOK_NORMAL_FUNC;

    specs[2].rva = g_rvas->CreateTextWidget;
    specs[2].detour = (LPVOID)&DetourCreateTextWidget;
    specs[2].orig = (LPVOID*)&fpOriginal_CreateTextWidget;
    specs[2].name = "CreateTextWidget";
    specs[2].kind = HOOK_NORMAL_FUNC;

    /* NOTE: luaL_register hook intentionally omitted — see commented
     * block above. Bridge works without it; we just lose the
     * print/next/tostring hijack and the registration-table dump. */

    for (t = 0; t < (int)(sizeof(specs)/sizeof(specs[0])); ++t) {
        LPVOID target = (LPVOID)(base + specs[t].rva);
        if (!ValidateHookTarget(target, specs[t].kind)) {
            m2_logf("[!] lua_bridge: RVA 0x%X (%s) failed prologue validation — skipping",
                    specs[t].rva, specs[t].name);
            continue;
        }
        if (!m2_hook_attach(target, specs[t].detour, specs[t].orig)) {
            m2_logf("[!] lua_bridge: m2_hook_attach(%s) failed", specs[t].name);
            continue;
        }
        m2_logf("[*] lua_bridge: hook armed on %s (RVA 0x%X -> %p)",
                specs[t].name, specs[t].rva, target);
        hooks_armed++;
    }

    if (hooks_armed == 0) {
        m2_logf("[!] lua_bridge: 0 hooks armed — bridge disabled for this binary. "
                "REPL will NOT be started.");
        return 0;
    }

    /* Initialize the WS-client mutex before spawning any thread that
     * might touch g_wsClient (the server thread updates it on
     * connect/disconnect; game-thread Loader.Printf/WsSend read it
     * for fanout). Safe to always init even when g_ws_enabled=0 — the
     * mutex is cheap and the fanout still checks g_wsClient itself. */
    if (!g_wsClientMtxInit) {
        InitializeCriticalSection(&g_wsClientMtx);
        g_wsClientMtxInit = 1;
    }
    CreateThread(NULL, 0, BridgeServerThread, NULL, 0, NULL);
    CreateThread(NULL, 0, LoaderKeyEventThread, NULL, 0, NULL);
    m2_logf("[*] lua_bridge: key-event sampler armed (~60 Hz, %d-slot ring)",
            KEYEVENT_BUFFER_SIZE);
    if (g_watchdog_stuck_ms > 0) {
        /* Seed timestamps to "now" so the very first watchdog wake sees
         * coherent since_X deltas instead of "now - 0" (a huge number that
         * makes since_progress look like a stall the moment PendingScripts
         * first goes nonzero). g_bridgeExecStartTick stays 0 = not executing. */
        DWORD boot_tick = GetTickCount();
        g_lastDetourFireTick    = boot_tick;
        g_lastPumpAttemptTick   = boot_tick;
        g_lastPumpProgressTick  = boot_tick;
        CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
        m2_logf("[*] lua_bridge: watchdog armed (stuck threshold %d ms)",
                g_watchdog_stuck_ms);
    } else {
        m2_logf("[*] lua_bridge: watchdog disabled (watchdog_stuck_ms = 0)");
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        m2_log_init(g_hModule);
        m2_logf("==========================================");
        m2_logf("[*] lua_bridge loading");
        m2_logf("==========================================");
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
