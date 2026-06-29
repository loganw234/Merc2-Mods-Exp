#include "m2_hook.h"
#include "MinHook.h"

int m2_hook_init(void) {
    MH_STATUS st = MH_Initialize();
    return (st == MH_OK || st == MH_ERROR_ALREADY_INITIALIZED) ? 1 : 0;
}

int m2_hook_attach(void* target, void* detour, void** orig) {
    if (!m2_hook_init()) return 0;
    if (MH_CreateHook(target, detour, orig) != MH_OK) return 0;
    if (MH_EnableHook(target) != MH_OK) return 0;
    return 1;
}
