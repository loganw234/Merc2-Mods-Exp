#include "m2_ini.h"
#include <windows.h>
#include <string.h>

static char* trim(char* s) {
    char* end;
    while (*s == ' ' || *s == '\t') s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return s;
}

int m2_ini_bool(const char* value) {
    return (lstrcmpiA(value, "1") == 0 || lstrcmpiA(value, "true") == 0 ||
            lstrcmpiA(value, "on") == 0 || lstrcmpiA(value, "yes") == 0) ? 1 : 0;
}

int m2_ini_int(const char* value, int fallback) {
    int v = 0, i = 0, neg = 0, any = 0;
    if (value[0] == '-') { neg = 1; i = 1; }
    for (; value[i] >= '0' && value[i] <= '9'; i++) { v = v * 10 + (value[i] - '0'); any = 1; }
    if (!any) return fallback;
    return neg ? -v : v;
}

int m2_ini_parse(const char* path, m2_ini_kv cb, void* ud) {
    HANDLE hf;
    DWORD size, read = 0;
    char* data;
    char* line;

    hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    size = GetFileSize(hf, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > (1u << 20)) {
        CloseHandle(hf);
        return 0;
    }
    data = (char*)HeapAlloc(GetProcessHeap(), 0, size + 1);
    if (!data) { CloseHandle(hf); return 0; }
    if (!ReadFile(hf, data, size, &read, NULL)) read = 0;
    data[read] = '\0';
    CloseHandle(hf);

    line = data;
    while (line && *line) {
        char* next = strchr(line, '\n');
        char* comment;
        char* eq;
        if (next) *next = '\0';

        comment = strpbrk(line, ";#");
        if (comment) *comment = '\0';
        line = trim(line);
        if (line[0] == '\0' || line[0] == '[') {
            line = next ? next + 1 : NULL;
            continue;
        }
        eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            cb(ud, trim(line), trim(eq + 1));
        }
        line = next ? next + 1 : NULL;
    }
    HeapFree(GetProcessHeap(), 0, data);
    return 1;
}
