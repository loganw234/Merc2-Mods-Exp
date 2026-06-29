/* m2_loadtrigger.h — fire callbacks as the world load crosses loadprobe milestones.
 *
 * Reuses loadprobe's world-load ladder (sdk/m2/load_ladder.gen.h, generated from
 * its phases.rs — the single source of truth) to turn the live log stream into
 * load-progress events. A mod registers a callback for a phase index and it fires
 * the moment the load first reaches that phase (or any later one).
 *
 * Phase indices come from the generated header, e.g.:
 *   10  WORLD LOAD START   ("Loading vz level with vz masterscript")
 *   M2_PHASE_ENTERED_WORLD_IDX (11)  Player spawn
 *   M2_PHASE_REACHED_WORLD_IDX (20)  World fully loaded (GlobalExit)
 *
 * NOTE: phases 0–1 are pmc_bb's own instrumentation, not game output, so they
 * never fire for a standalone ASI watching the game log. Phases 2–20 are
 * game-emitted and are the ones mods care about.
 */
#ifndef M2_LOADTRIGGER_H
#define M2_LOADTRIGGER_H

#include "load_ladder.gen.h"

/* Fired once when the load first reaches the registered target phase. `reached_idx`
 * is the phase index whose marker actually appeared (>= the registered target). */
typedef void (*m2_phase_cb)(int reached_idx, void* ud);

/* Register a callback to fire when the load reaches >= target_idx. Returns 1 on
 * success. Register before m2_loadtrigger_install(). */
int m2_loadtrigger_on_phase(int target_idx, m2_phase_cb cb, void* ud);

/* Begin tracking: subscribes to the shared log hook and installs it. Idempotent. */
int m2_loadtrigger_install(void);

/* Highest phase index reached so far (-1 before any). */
int m2_loadtrigger_current_phase(void);

/* Human-readable phase name for an index, or "?" if out of range. */
const char* m2_loadtrigger_phase_name(int idx);

#endif /* M2_LOADTRIGGER_H */
