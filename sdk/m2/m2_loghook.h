/* m2_loghook.h — shared subscription to the game's log stream.
 *
 * The SDK's single event source for "what did the game just say"; m2_loadtrigger
 * is built on it and mods can listen directly.
 *
 * Source selection (see m2_loghook_install):
 *   - If pmc_bb.dll is loaded, it already owns the log-stub hook and writes every
 *     line to pmc_blackbox.log — we TAIL that file (pure consumer; we never touch
 *     the stub, so we can't shadow pmc_bb's logger).
 *   - Otherwise we MinHook the shared no-op log stub (M2_LOG_STUB_VA) ourselves,
 *     chaining the trampoline. Every Lua print / Debug.Printf / stripped subsystem
 *     log line funnels through it; string args are joined into a message.
 */
#ifndef M2_LOGHOOK_H
#define M2_LOGHOOK_H

/* Called on the game thread for each captured log line (NUL-terminated message,
 * string args tab-joined). Keep it cheap and non-reentrant — do not call back
 * into anything that itself logs. */
typedef void (*m2_log_listener)(const char* msg, void* ud);

/* Register a listener. Returns 1 on success, 0 if the table is full. Register
 * before m2_loghook_install(). */
int m2_loghook_add_listener(m2_log_listener cb, void* ud);

/* MinHook the log stub and begin dispatching. Idempotent. Returns 1 on success. */
int m2_loghook_install(void);

#endif /* M2_LOGHOOK_H */
