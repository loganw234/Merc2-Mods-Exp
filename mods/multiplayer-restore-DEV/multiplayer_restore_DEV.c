/* multiplayer_restore.c — restores Mercenaries 2 online multiplayer.
 *
 * Ported from Merc2Reborn's Merc2Fix ASI to the mercs2-qol-mods SDK
 * (https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).
 *
 * What it does:
 *
 *   1. DNS redirect — intercepts ws2_32 gethostbyname / getaddrinfo /
 *      GetAddrInfoW and routes *.ea.com / *.gamespy.com / fesl* to
 *      the configured private server (default refesl.live, resolved
 *      at startup).
 *
 *   2. FESL CA pubkey patch — single 128-byte write into the game's
 *      .rdata at FESL_CA_KEY_RVA, replaying the MLoader patch so the
 *      game's SSL stack accepts the private server's cert chain. The
 *      write is gated on a poll loop that waits for SecuROM to
 *      finish unpacking that section, mirroring what MLoader does.
 *
 * Historical note: earlier revisions of this port also included a
 * WinVerifyTrust cert-blob blindfold and a Win32/CRT clock spoof
 * (pinning time to 2012-06-15 to keep OpenSSL's expiry check happy).
 * Both were removed after live testing showed the CA key patch alone
 * is sufficient to let the private server's cert chain validate — the
 * belt-and-braces layers were experimentation-era scaffolding.
 *
 * What it does NOT do:
 *
 *   - No Lua bridge / executor / REPL. That tier lives in Merc2Fix
 *     proper and is intentionally out of scope for this port.
 *   - No UDP relay client. The relay runs server-side; the client
 *     just routes its packets to whatever IP/port Theater hands
 *     back, which the DNS redirect already takes care of.
 *
 * Most users will not need to forward any ports.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "m2_log.h"
#include "m2_hook.h"
#include "m2_ini.h"

/* Link with -lws2_32 (see Makefile). On MSVC builds, the old
 * `#pragma comment(lib, ...)` would do this automatically; we pass
 * it on the link command line instead so MinGW agrees. */

/* ======================================================================== *
 * Status: PROOF-OF-CONCEPT — this port has NOT been built or test-run
 * against the mercs2-qol-mods framework. The author drafted it without
 * the SDK build environment (MinGW, pmc_bb.dll runtime, etc.) set up
 * locally. The underlying *approach* is validated:
 *
 *   * The standalone Merc2Fix.asi (which this is ported from) was run
 *     against a mercs2-securom-bypass-patched Mercenaries2.exe. Hooks
 *     armed, multiplayer worked end-to-end, no anti-tamper trips.
 *     (The companion Lua bridge correctly aborted itself via its RVA
 *     prologue check, as expected — that side is out of scope for
 *     this multiplayer-only port.)
 *
 * What that means: the hooking model and CA key patch behave on the
 * bypass target. The architecture is sound.
 *
 * Remaining open question:
 *
 *   FESL_CA_KEY_RVA below (0x768378) was extracted from MLoader's
 *   dump against the archive.org English retail build. The bypass
 *   tool swaps the import table cruise.dll -> pmc_bb.dll (same name
 *   length, no shift) and edits .text to strip the DRM validation;
 *   it most likely does not resize .rdata, so the offset should be
 *   stable on the bypass target — but please verify before shipping.
 *   30-second check: dump the first 16 bytes at this RVA in your
 *   live process and confirm they look like a 128-byte placeholder
 *   (mostly zeros or a single repeated pattern), not real engine
 *   data. If real data is there, the offset moved.
 *
 * Notes that aren't blockers:
 *
 *   * The SDK's m2_hook.h warning about .rdata anti-tamper writes
 *     does not appear to apply to the bypass target (SecuROM is
 *     stripped, pmc_bb.dll explicitly doesn't do integrity checks).
 *     Our PatchFeslCAKey still keeps a short unpack-wait poll as a
 *     no-op safety net for users running this on a different (e.g.
 *     archive.org or MLoader-cracked) binary — exits on the first
 *     iteration when bytes are already in plaintext.
 * ======================================================================== */

#define FESL_CA_KEY_RVA  0x768378u
static const BYTE kFeslCAKeyPayload[128] = {
    0xDA, 0x02, 0xD3, 0x80, 0xD0, 0xAB, 0x67, 0x88,
    0x6D, 0x2B, 0x11, 0x17, 0x7E, 0xFF, 0x4F, 0x1F,
    0xBA, 0x80, 0xA3, 0x07, 0x0E, 0x8F, 0x03, 0x6D,
    0xEE, 0x9D, 0xC0, 0xF3, 0x0B, 0xF8, 0xB8, 0x05,
    0x16, 0x16, 0x4D, 0xC0, 0xD4, 0x82, 0x7F, 0x47,
    0xA4, 0x8A, 0x3B, 0xCA, 0x12, 0x9D, 0xD2, 0x9D,
    0x19, 0x61, 0xD8, 0x56, 0x61, 0x47, 0xA5, 0x88,
    0xDC, 0x24, 0x8F, 0x90, 0xC9, 0xA4, 0x1C, 0xBF,
    0xF8, 0x57, 0xE0, 0x2F, 0x47, 0x78, 0x2E, 0xAE,
    0x5A, 0x70, 0xE5, 0x55, 0xBA, 0xDD, 0x36, 0xE1,
    0x6C, 0x17, 0x93, 0x31, 0xE4, 0xF9, 0x22, 0x03,
    0x81, 0x69, 0x98, 0xC8, 0x2E, 0xDF, 0xBE, 0x0E,
    0x33, 0x9D, 0xC3, 0xE0, 0xC0, 0x20, 0x85, 0x52,
    0xCD, 0x3F, 0x05, 0xF5, 0xCB, 0x41, 0x2F, 0x67,
    0x10, 0x91, 0x6A, 0xD1, 0x59, 0xDA, 0xC1, 0x23,
    0x3E, 0x71, 0x08, 0x9F, 0x20, 0xD4, 0x3D, 0x6D,
};

static char g_server_ip[64]   = "refesl.live";   /* overridden by INI */
static int  g_hook_dns        = 1;               /* overridden by INI */
static int  g_patch_ca        = 1;               /* overridden by INI */
static int  g_patch_bversion  = 1;               /* overridden by INI */
static int  g_target_bversion = 1555000000;      /* overridden by INI */
static HMODULE g_hModule      = NULL;

/* ------------------------------------------------------------------------ *
 * INI config — server IP + hook toggles.
 * ------------------------------------------------------------------------ */

/* m2_ini_parse's callback signature is (ud, key, value) — the parser
 * strips section headers internally and never surfaces them, so we
 * dispatch on the key name alone. */
static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;
    if (_stricmp(key, "ip") == 0) {
        strncpy(g_server_ip, value, sizeof(g_server_ip) - 1);
        g_server_ip[sizeof(g_server_ip) - 1] = 0;
    } else if (_stricmp(key, "hook_dns") == 0) {
        g_hook_dns = m2_ini_bool(value);
    } else if (_stricmp(key, "patch_ca") == 0) {
        g_patch_ca = m2_ini_bool(value);
    } else if (_stricmp(key, "patch_bversion") == 0) {
        g_patch_bversion = m2_ini_bool(value);
    } else if (_stricmp(key, "bversion") == 0) {
        g_target_bversion = atoi(value);
    }
}

/* Baked-in defaults, written to disk if the .ini is missing. Keeps the
 * .asi self-sufficient — users can drop the .asi alone and get a
 * commented, editable config on first launch. */
static const char kDefaultIni[] =
    "; multiplayer-restore configuration.\n"
    "; Drop this next to multiplayer_restore.asi in your game folder.\n"
    "\n"
    "[server]\n"
    "; Hostname or dotted-quad of the FESL server to redirect EA traffic to.\n"
    "; The default points at the public Merc2Reborn relay run by loganw.\n"
    "; Override only if you're hosting your own server (see\n"
    "; https://github.com/loganw234/Mercenaries2 for setup notes).\n"
    "ip = refesl.live\n"
    "\n"
    "[compat]\n"
    "; 1 = patch the b-version check to advertise a specific build version.\n"
    "; 0 = leave the b-version check alone.\n"
    "patch_bversion = 1\n"
    "\n"
    "; The specific build version integer to advertise to the FESL server.\n"
    "; Default: 1555000000\n"
    "bversion = 1555000000\n"
    "\n"
    "[debug]\n"
    "; WARNING: Do not modify the settings below unless you are positive\n"
    "; about what you are doing. These are toggles for individual hooks.\n"
    "hook_dns = 1\n"
    "patch_ca = 1\n";

static void EnsureIniDefault(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) { fclose(f); return; }
    f = fopen(path, "w");
    if (!f) return;
    fputs(kDefaultIni, f);
    fclose(f);
    m2_logf("[*] multiplayer_restore: wrote default %s", path);
}

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "multiplayer_restore_DEV.ini", ini_path, sizeof(ini_path));
    EnsureIniDefault(ini_path);
    m2_ini_parse(ini_path, OnIniKV, NULL);
}

/* ------------------------------------------------------------------------ *
 * DNS — resolve the configured server address once at startup so we don't
 * recursively call the hooked resolvers later.
 * ------------------------------------------------------------------------ */

static char g_resolved_ip[64] = "127.0.0.1";  /* updated by ResolveServer */

static void ResolveServer(void) {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[!] WSAStartup failed; falling back to %s", g_resolved_ip);
        return;
    }
    /* If the INI value already looks like a dotted-quad, skip DNS. */
    struct in_addr probe;
    if (inet_pton(AF_INET, g_server_ip, &probe) == 1) {
        strncpy(g_resolved_ip, g_server_ip, sizeof(g_resolved_ip) - 1); g_resolved_ip[sizeof(g_resolved_ip) - 1] = 0;
        m2_logf("[*] Using server IP from config: %s", g_resolved_ip);
        WSACleanup();
        return;
    }
    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_server_ip, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in* a = (struct sockaddr_in*)res->ai_addr;
        const char* dotted = inet_ntoa(a->sin_addr);
        if (dotted) { strncpy(g_resolved_ip, dotted, sizeof(g_resolved_ip) - 1); g_resolved_ip[sizeof(g_resolved_ip) - 1] = 0; }
        freeaddrinfo(res);
        m2_logf("[+] Resolved %s -> %s", g_server_ip, g_resolved_ip);
    } else {
        m2_logf("[!] Failed to resolve %s; falling back to %s",
                g_server_ip, g_resolved_ip);
    }
    WSACleanup();
}

static int IsTargetHost(const char* host) {
    if (!host) return 0;
    return strstr(host, "ea.com")      != NULL
        || strstr(host, "gamespy.com") != NULL
        || strstr(host, "fesl")        != NULL;
}

static void NarrowFromWide(const wchar_t* w, char* out, size_t out_max) {
    size_t i = 0;
    if (!w || !out || out_max == 0) return;
    for (; w[i] && i + 1 < out_max; ++i) out[i] = (char)(w[i] & 0xFF);
    out[i] = 0;
}

/* ------------------------------------------------------------------------ *
 * Detours
 * ------------------------------------------------------------------------ */

typedef struct hostent* (WINAPI* GETHOSTBYNAME_FN)(const char*);
typedef int (WSAAPI* GETADDRINFO_FN)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WSAAPI* GETADDRINFOW_FN)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);

static GETHOSTBYNAME_FN  o_gethostbyname = NULL;
static GETADDRINFO_FN    o_getaddrinfo   = NULL;
static GETADDRINFOW_FN   o_getaddrinfow  = NULL;

static struct hostent* WINAPI d_gethostbyname(const char* name) {
    if (name && IsTargetHost(name)) {
        m2_logf("[+] (gethostbyname) %s -> %s", name, g_resolved_ip);
        return o_gethostbyname(g_resolved_ip);
    }
    return o_gethostbyname(name);
}

static int WSAAPI d_getaddrinfo(PCSTR node, PCSTR svc,
                                const ADDRINFOA* hints, PADDRINFOA* res) {
    if (node && IsTargetHost(node)) {
        m2_logf("[+] (getaddrinfo) %s -> %s", node, g_resolved_ip);
        return o_getaddrinfo(g_resolved_ip, svc, hints, res);
    }
    return o_getaddrinfo(node, svc, hints, res);
}

static int WSAAPI d_getaddrinfow(PCWSTR node, PCWSTR svc,
                                 const ADDRINFOW* hints, PADDRINFOW* res) {
    if (node) {
        char nn[256]; NarrowFromWide(node, nn, sizeof(nn));
        if (IsTargetHost(nn)) {
            wchar_t wip[64];
            for (size_t i = 0; i < sizeof(g_resolved_ip) && g_resolved_ip[i]; ++i) {
                wip[i] = (wchar_t)g_resolved_ip[i];
                wip[i+1] = 0;
            }
            m2_logf("[+] (GetAddrInfoW) %s -> %s", nn, g_resolved_ip);
            return o_getaddrinfow(wip, svc, hints, res);
        }
    }
    return o_getaddrinfow(node, svc, hints, res);
}

/* ------------------------------------------------------------------------ *
 * FESL CA key patch — the single .rdata write
 * ------------------------------------------------------------------------ */

static int PatchFeslCAKey(void) {
    HMODULE mod = GetModuleHandleA(NULL);
    if (!mod) {
        m2_logf("[!] PatchFeslCAKey: Host module not loaded");
        return 0;
    }
    BYTE* target = (BYTE*)mod + FESL_CA_KEY_RVA;

    /* Wait up to ~5 s for SecuROM to unpack .rdata. The check is
     * "first 16 bytes are non-zero" — same heuristic MLoader uses. */
    for (int tries = 0; tries < 200; tries++) {
        int nonzero = 0;
        for (int i = 0; i < 16; i++) {
            if (target[i] != 0) { nonzero = 1; break; }
        }
        if (nonzero) break;
        Sleep(25);
    }

    if (memcmp(target, kFeslCAKeyPayload, sizeof(kFeslCAKeyPayload)) == 0) {
        m2_logf("[*] FESL CA key already matches payload (MLoader present?) — skipped");
        return 1;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, sizeof(kFeslCAKeyPayload),
                        PAGE_READWRITE, &oldProtect)) {
        m2_logf("[!] PatchFeslCAKey: VirtualProtect failed, GLE=%lu", GetLastError());
        return 0;
    }
    memcpy(target, kFeslCAKeyPayload, sizeof(kFeslCAKeyPayload));
    DWORD tmp = 0;
    VirtualProtect(target, sizeof(kFeslCAKeyPayload), oldProtect, &tmp);

    m2_logf("[+] FESL CA key patched at RVA 0x%X (%u bytes)",
            FESL_CA_KEY_RVA, (unsigned)sizeof(kFeslCAKeyPayload));
    return 1;
}

/* FNV-1a 64-bit hashing helper. */
static uint64_t Fnv1a64(const void* data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t* b = (const uint8_t*)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= b[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

/* Memory safety prober. */
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

/* Dynamically determines the correct B-version check instruction RVA in the binary. */
static DWORD GetBVersionRva(HMODULE mod) {
    BYTE* base = (BYTE*)mod;

    // 1. Try dynamic fingerprint matching first (from RVA 0x11000 FNV-1a hash)
    if (SafeProbe(base + 0x11000, 0x1000)) {
        uint64_t fp = Fnv1a64(base + 0x11000, 0x1000);
        m2_logf("[*] GetBVersionRva: binary fingerprint = 0x%016llX", fp);
        if (fp == 0xB79E4DD22A4BFCB3ULL) {
            m2_logf("[*] GetBVersionRva: matched Retail (v1.1)");
            return 0x4448E8;
        } else if (fp == 0x1942B494FF9F4DB3ULL) {
            m2_logf("[*] GetBVersionRva: matched Bypass (v1.1_bypass)");
            return 0x444688;
        }
    }

    // 2. Fallback heuristic: Probe both known target code offsets for the signature bytes
    // Pattern: 8B 54 24 18 52 (mov edx, [esp+18h]; push edx)
    const BYTE kPattern[5] = {0x8B, 0x54, 0x24, 0x18, 0x52};

    if (SafeProbe(base + 0x444688, 5) && memcmp(base + 0x444688, kPattern, 5) == 0) {
        m2_logf("[*] GetBVersionRva: matched Bypass signature at RVA 0x444688");
        return 0x444688;
    }
    if (SafeProbe(base + 0x4448E8, 5) && memcmp(base + 0x4448E8, kPattern, 5) == 0) {
        m2_logf("[*] GetBVersionRva: matched Retail signature at RVA 0x4448E8");
        return 0x4448E8;
    }

    m2_logf("[!] GetBVersionRva: could not find valid B-version check signature");
    return 0;
}

static int PatchBVersion(void) {
    HMODULE mod = GetModuleHandleA(NULL);
    if (!mod) {
        m2_logf("[!] PatchBVersion: Host module not loaded");
        return 0;
    }
    
    DWORD rva = GetBVersionRva(mod);
    if (rva == 0) {
        m2_logf("[!] PatchBVersion: Aborting patch due to unknown binary signature");
        return 0;
    }
    
    BYTE* target = (BYTE*)mod + rva;

    /* Original instruction bytes: 
     * 8B 54 24 18     mov edx, [esp+18h]
     * 52              push edx
     * 
     * Target replacement bytes (Push g_target_bversion):
     * 68 [4 bytes of value]  push imm32
     */
    BYTE kPatchPayload[5];
    kPatchPayload[0] = 0x68; // push imm32
    memcpy(&kPatchPayload[1], &g_target_bversion, sizeof(g_target_bversion));

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, sizeof(kPatchPayload), PAGE_READWRITE, &oldProtect)) {
        m2_logf("[!] PatchBVersion: VirtualProtect failed, GLE=%lu", GetLastError());
        return 0;
    }
    
    memcpy(target, kPatchPayload, sizeof(kPatchPayload));
    DWORD tmp = 0;
    VirtualProtect(target, sizeof(kPatchPayload), oldProtect, &tmp);

    m2_logf("[+] B-version check patched to always return %d (VA 0x%p)", g_target_bversion, target);
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Hook arming
 * ------------------------------------------------------------------------ */

static int HookApi(const char* module, const char* fn,
                   void* detour, void** orig, int required) {
    HMODULE m = GetModuleHandleA(module);
    if (!m) m = LoadLibraryA(module);
    if (!m) {
        if (required) {
            m2_logf("[!] HookApi: failed to load module %s", module);
        }
        return 0;
    }
    void* p = (void*)GetProcAddress(m, fn);
    if (!p) {
        if (required) {
            m2_logf("[!] HookApi: export %s not found in %s", fn, module);
        }
        return 0;
    }
    if (m2_hook_attach(p, detour, orig) == 0) {
        m2_logf("[!] HookApi: failed to attach hook for %s!%s", module, fn);
        return 0;
    }
    m2_logf("[*] hooked %s!%s -> %p", module, fn, p);
    return 1;
}

static DWORD WINAPI WorkerThread(LPVOID arg) {
    (void)arg;

    LoadConfig();

    /* 1. Apply B-version patch immediately to beat the connection initialization race condition */
    if (g_patch_bversion) {
        PatchBVersion();
    } else {
        m2_logf("[*] B-version patch disabled by config");
    }

    if (g_hook_dns) {
        ResolveServer();
    } else {
        m2_logf("[*] DNS resolution skipped (DNS redirect disabled)");
    }

    if (!m2_hook_init()) {
        m2_logf("[!] m2_hook_init failed; aborting");
        return 1;
    }

    /* 2. DNS redirect. */
    if (g_hook_dns) {
        HookApi("ws2_32.dll", "gethostbyname",   (void*)d_gethostbyname,   (void**)&o_gethostbyname,   1);
        HookApi("ws2_32.dll", "getaddrinfo",     (void*)d_getaddrinfo,     (void**)&o_getaddrinfo,     1);
        HookApi("ws2_32.dll", "GetAddrInfoW",    (void*)d_getaddrinfow,    (void**)&o_getaddrinfow,    1);
    } else {
        m2_logf("[*] DNS redirect hook disabled by config");
    }

    /* 3. FESL CA pubkey patch — runs after hooks so any logging from
     *    the wait loop goes through the live logger. */
    if (g_patch_ca) {
        PatchFeslCAKey();
    } else {
        m2_logf("[*] FESL CA key patch disabled by config");
    }

    m2_logf("[*] multiplayer-restore: armed. Server target = %s", g_resolved_ip);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        m2_log_init(g_hModule);
        m2_logf("==========================================");
        m2_logf("[*] multiplayer-restore loading");
        m2_logf("==========================================");
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
