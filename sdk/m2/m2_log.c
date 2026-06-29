#include "m2_log.h"
#include <string.h>
#include <stdarg.h>

static HANDLE g_logFile = INVALID_HANDLE_VALUE;

void m2_module_path(HMODULE module, const char* filename, char* out, int out_size) {
    char dir[MAX_PATH];
    char* slash;
    GetModuleFileNameA(module, dir, MAX_PATH);
    slash = strrchr(dir, '\\');
    if (!slash) slash = strrchr(dir, '/');
    if (slash) *(slash + 1) = '\0'; else dir[0] = '\0';
    lstrcpynA(out, dir, out_size);
    if ((int)strlen(out) + (int)strlen(filename) < out_size)
        strcat(out, filename);
}

void m2_log_init(HMODULE module) {
    char path[MAX_PATH];
    char* dot;
    GetModuleFileNameA(module, path, MAX_PATH);
    dot = strrchr(path, '.');
    if (dot) strcpy(dot, ".log");
    else strcat(path, ".log");
    g_logFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void m2_logf(const char* fmt, ...) {
    char buf[1536];
    int len;
    va_list ap;
    DWORD written;
    if (g_logFile == INVALID_HANDLE_VALUE) return;
    va_start(ap, fmt);
    len = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (len <= 0) return;
    if (len > (int)sizeof(buf) - 2) len = (int)sizeof(buf) - 2;
    buf[len] = '\r';
    buf[len + 1] = '\n';
    WriteFile(g_logFile, buf, len + 2, &written, NULL);
    FlushFileBuffers(g_logFile);
}

void m2_log_close(void) {
    if (g_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
}
