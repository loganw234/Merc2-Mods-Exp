/* m2_ini.h — minimal INI reader for Mercs2 ASI mods.
 *
 * Callback-per-key parser. Strips `;`/`#` comments, `[section]` headers, and
 * surrounding whitespace; splits on the first `=`. No allocations beyond a single
 * file read. Designed for small mod config files.
 */
#ifndef M2_INI_H
#define M2_INI_H

/* Called once per `key = value` line (both trimmed, NUL-terminated). */
typedef void (*m2_ini_kv)(void* ud, const char* key, const char* value);

/* Parse the INI at `path`. Returns 1 if the file was read, 0 if missing/unreadable. */
int m2_ini_parse(const char* path, m2_ini_kv cb, void* ud);

/* Convenience parsers for callback bodies. */
int  m2_ini_bool(const char* value);            /* "1"/"true"/"on"/"yes" -> 1 */
int  m2_ini_int(const char* value, int fallback);

#endif /* M2_INI_H */
