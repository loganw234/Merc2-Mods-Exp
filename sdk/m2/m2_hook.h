/* m2_hook.h — thin wrapper over MinHook for SecuROM-safe .text detours.
 *
 * The cracked Mercs2 EXE tolerates .text MinHook detours but anti-tampers .rdata
 * writes, so all runtime patching goes through MinHook. This wrapper makes init
 * idempotent (multiple SDK modules can call it) and gives a one-call attach.
 */
#ifndef M2_HOOK_H
#define M2_HOOK_H

/* Initialize MinHook once (tolerates already-initialized). Returns 1 on success. */
int m2_hook_init(void);

/* Create + enable a detour at `target`, storing the trampoline (call-original) in
 * *orig. Returns 1 on success. `orig` may be NULL if the original is never called. */
int m2_hook_attach(void* target, void* detour, void** orig);

#endif /* M2_HOOK_H */
