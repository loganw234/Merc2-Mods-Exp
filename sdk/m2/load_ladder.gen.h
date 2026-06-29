/* AUTO-GENERATED from loadprobe by sdk/gen_ladder.py — DO NOT EDIT. */
/* Source of truth: ../mercenaries-game/tools/wad_simulator/crates/loadprobe/src/phases.rs */
#ifndef M2_LOAD_LADDER_GEN_H
#define M2_LOAD_LADDER_GEN_H

#define M2_LADDER_COUNT 21
#define M2_PHASE_REACHED_WORLD_IDX 20
#define M2_PHASE_ENTERED_WORLD_IDX 11

typedef struct {
    int idx;
    const char* name;
    const char* const* matches;
    int match_count;
} M2LoadPhase;

static const char* const k_m2_phase_0_matches[] = { "PMC Blackbox v3" };
static const char* const k_m2_phase_1_matches[] = { "render-instance pool initialized" };
static const char* const k_m2_phase_2_matches[] = { "SoundShellBootstrap.Init" };
static const char* const k_m2_phase_3_matches[] = { "Top of ShellBootstrap::Init()" };
static const char* const k_m2_phase_4_matches[] = { "Attempting to play movie", "Playing EA", "Playing Pandemic" };
static const char* const k_m2_phase_5_matches[] = { "All movies complete" };
static const char* const k_m2_phase_6_matches[] = { "StartPrecache()" };
static const char* const k_m2_phase_7_matches[] = { "Shell music started" };
static const char* const k_m2_phase_8_matches[] = { "Shell exited" };
static const char* const k_m2_phase_9_matches[] = { "GameBootstrap - bailing because finished shell" };
static const char* const k_m2_phase_10_matches[] = { "Loading vz level with vz masterscript" };
static const char* const k_m2_phase_11_matches[] = { "CreatePlayerCharacter" };
static const char* const k_m2_phase_12_matches[] = { "STATE_WAITFORGAME (refcount=" };
static const char* const k_m2_phase_13_matches[] = { "GlobalEnter - Begin" };
static const char* const k_m2_phase_14_matches[] = { "Staging Act" };
static const char* const k_m2_phase_15_matches[] = { "Setting flow data (" };
static const char* const k_m2_phase_16_matches[] = { "STATE_WAITFORSTREAMING (refcount=" };
static const char* const k_m2_phase_17_matches[] = { "GlobalEnter - Complete" };
static const char* const k_m2_phase_18_matches[] = { "Enabling " };
static const char* const k_m2_phase_19_matches[] = { "Dynamically imported module" };
static const char* const k_m2_phase_20_matches[] = { "GlobalExit - Complete" };

static const M2LoadPhase k_m2_ladder[M2_LADDER_COUNT] = {
    { 0, "Process init", k_m2_phase_0_matches, 1 },
    { 1, "Pool/hooks armed", k_m2_phase_1_matches, 1 },
    { 2, "Shell sound init", k_m2_phase_2_matches, 1 },
    { 3, "Shell init", k_m2_phase_3_matches, 1 },
    { 4, "Intro movies", k_m2_phase_4_matches, 3 },
    { 5, "Movies complete", k_m2_phase_5_matches, 1 },
    { 6, "Precache", k_m2_phase_6_matches, 1 },
    { 7, "Soundbanks ready", k_m2_phase_7_matches, 1 },
    { 8, "Shell exit", k_m2_phase_8_matches, 1 },
    { 9, "Game bootstrap", k_m2_phase_9_matches, 1 },
    { 10, "WORLD LOAD START", k_m2_phase_10_matches, 1 },
    { 11, "Player spawn", k_m2_phase_11_matches, 1 },
    { 12, "WAITFORGAME", k_m2_phase_12_matches, 1 },
    { 13, "GlobalEnter begin", k_m2_phase_13_matches, 1 },
    { 14, "Act staging", k_m2_phase_14_matches, 1 },
    { 15, "Mission flow data", k_m2_phase_15_matches, 1 },
    { 16, "Streaming (WAITFORSTREAMING)", k_m2_phase_16_matches, 1 },
    { 17, "GlobalEnter complete", k_m2_phase_17_matches, 1 },
    { 18, "World entities online", k_m2_phase_18_matches, 1 },
    { 19, "Module/job imports", k_m2_phase_19_matches, 1 },
    { 20, "World fully loaded (GlobalExit)", k_m2_phase_20_matches, 1 },
};

#endif /* M2_LOAD_LADDER_GEN_H */
