#include "m2_loadtrigger.h"
#include "m2_loghook.h"
#include <windows.h>
#include <string.h>

#define MAX_TRIGGERS 32

typedef struct {
    int target_idx;
    m2_phase_cb cb;
    void* ud;
    int fired;
} Trigger;

static Trigger g_triggers[MAX_TRIGGERS];
static int g_triggerCount = 0;
static volatile LONG g_maxPhase = -1;

int m2_loadtrigger_on_phase(int target_idx, m2_phase_cb cb, void* ud) {
    if (!cb || g_triggerCount >= MAX_TRIGGERS) return 0;
    if (target_idx < 0 || target_idx >= M2_LADDER_COUNT) return 0;
    g_triggers[g_triggerCount].target_idx = target_idx;
    g_triggers[g_triggerCount].cb = cb;
    g_triggers[g_triggerCount].ud = ud;
    g_triggers[g_triggerCount].fired = 0;
    g_triggerCount++;
    return 1;
}

int m2_loadtrigger_current_phase(void) {
    return (int)g_maxPhase;
}

const char* m2_loadtrigger_phase_name(int idx) {
    int i;
    for (i = 0; i < M2_LADDER_COUNT; i++)
        if (k_m2_ladder[i].idx == idx) return k_m2_ladder[i].name;
    return "?";
}

/* Highest ladder phase whose marker appears in `msg` (case-sensitive substring,
 * matching loadprobe's report.rs), or -1 if none. */
static int MatchPhase(const char* msg) {
    int best = -1, i, j;
    for (i = 0; i < M2_LADDER_COUNT; i++) {
        const M2LoadPhase* ph = &k_m2_ladder[i];
        for (j = 0; j < ph->match_count; j++) {
            if (strstr(msg, ph->matches[j])) {
                if (ph->idx > best) best = ph->idx;
                break;
            }
        }
    }
    return best;
}

static void OnLogLine(const char* msg, void* ud) {
    int matched, i;
    (void)ud;

    matched = MatchPhase(msg);
    if (matched < 0) return;
    if (matched <= (int)g_maxPhase) return;   /* monotonic: only advance forward */
    g_maxPhase = matched;

    for (i = 0; i < g_triggerCount; i++) {
        if (!g_triggers[i].fired && g_triggers[i].target_idx <= matched) {
            g_triggers[i].fired = 1;
            g_triggers[i].cb(matched, g_triggers[i].ud);
        }
    }
}

int m2_loadtrigger_install(void) {
    if (!m2_loghook_add_listener(OnLogLine, NULL)) return 0;
    return m2_loghook_install();
}
