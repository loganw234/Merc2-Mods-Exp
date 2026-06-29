/* m2_log.h — per-module file logging for Mercs2 ASI mods.
 *
 * Opens "<module>.log" next to the loaded .asi and provides printf-style logging.
 * One logger per process module; SDK internals log through the same sink.
 */
#ifndef M2_LOG_H
#define M2_LOG_H

#include <windows.h>

/* Open <module>.log next to the given module (typically the mod's HINSTANCE). */
void m2_log_init(HMODULE module);

/* Append a line (CRLF added automatically). No-op if not initialized. */
void m2_logf(const char* fmt, ...);

/* Build "<module dir>\<filename>" into out. Useful for .ini paths etc. */
void m2_module_path(HMODULE module, const char* filename, char* out, int out_size);

void m2_log_close(void);

#endif /* M2_LOG_H */
