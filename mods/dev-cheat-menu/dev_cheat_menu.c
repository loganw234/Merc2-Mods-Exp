/* dev_cheat_menu.c — ASI mod to open the developer cheat menu via lua-bridge connection.
 *
 * Authored entirely by u/Kunster_ on r/MercenariesGames.
 *
 * This mod listens for a hotkey (default: INSERT) and sends a Lua script to
 * the running lua-bridge server to trigger the in-game developer cheat menu.
 *
 * Configurable via dev_cheat_menu.ini.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "m2.h"

/* The Lua script to trigger the developer cheat menu, provided by u/Kunster_ */
static const char* kCheatMenuScript =
    "pcall(function()\n"
    "    if type(Hud) == \"table\" and type(Hud.ClassyText) == \"table\" and type(Hud.ClassyText.ShowText) == \"function\" then\n"
    "        Hud.ClassyText.ShowText(Hud.ClassyText, {\n"
    "            sText = \"Dev Cheat Menu Opening... Do Not Press Again!\",\n"
    "            nDuration = 5\n"
    "        })\n"
    "    end\n"
    "end)\n"
    "\n"
    "local f = nil\n"
    "local src = \"none\"\n"
    "\n"
    "-- First try the globally exported cheat interface.\n"
    "if type(Cheat) == \"table\"\n"
    "and type(Cheat.DisplayOptions) == \"function\" then\n"
    "    f = Cheat.DisplayOptions\n"
    "    src = \"Cheat.DisplayOptions\"\n"
    "end\n"
    "\n"
    "-- Then check whether the cheat-bootstrap module is already resident.\n"
    "local m = nil\n"
    "if type(_MODULES) == \"table\" then\n"
    "    m = _MODULES.mrxcheatbootstrap\n"
    "end\n"
    "\n"
    "if type(f) ~= \"function\" and type(m) == \"table\" then\n"
    "    if type(m.DisplayOptions) == \"function\" then\n"
    "        f = m.DisplayOptions\n"
    "        src = \"_MODULES.mrxcheatbootstrap.DisplayOptions\"\n"
    "    elseif type(m._DisplayRootDialog) == \"function\" then\n"
    "        f = m._DisplayRootDialog\n"
    "        src = \"_MODULES.mrxcheatbootstrap._DisplayRootDialog\"\n"
    "    end\n"
    "end\n"
    "\n"
    "-- If necessary, import the retail cheat-bootstrap script.\n"
    "if type(f) ~= \"function\" and type(import) == \"function\" then\n"
    "    pcall(import, \"mrxcheatbootstrap\")\n"
    "    -- Importing may create the global Cheat table.\n"
    "    if type(Cheat) == \"table\"\n"
    "    and type(Cheat.DisplayOptions) == \"function\" then\n"
    "        f = Cheat.DisplayOptions\n"
    "        src = \"import -> Cheat.DisplayOptions\"\n"
    "    end\n"
    "    -- Or it may only register the resident module.\n"
    "    if type(_MODULES) == \"table\" then\n"
    "        m = _MODULES.mrxcheatbootstrap or m\n"
    "    end\n"
    "    if type(f) ~= \"function\" and type(m) == \"table\" then\n"
    "        if type(m.DisplayOptions) == \"function\" then\n"
    "            f = m.DisplayOptions\n"
    "            src = \"import -> _MODULES.mrxcheatbootstrap.DisplayOptions\"\n"
    "        elseif type(m._DisplayRootDialog) == \"function\" then\n"
    "            f = m._DisplayRootDialog\n"
    "            src = \"import -> _MODULES.mrxcheatbootstrap._DisplayRootDialog\"\n"
    "        end\n"
    "    end\n"
    "end\n"
    "\n"
    "if type(f) ~= \"function\" then\n"
    "    error(\n"
    "        \"Native cheat menu is unavailable. \" ..\n"
    "        \"Cheat.DisplayOptions=\" ..\n"
    "        type(type(Cheat) == \"table\" and Cheat.DisplayOptions or nil) ..\n"
    "        \", mrxcheatbootstrap=\" ..\n"
    "        type(m)\n"
    "    )\n"
    "end\n"
    "\n"
    "local ok, result = pcall(f)\n"
    "if not ok then\n"
    "    error(\n"
    "        \"Opening the cheat menu through \" ..\n"
    "        src ..\n"
    "        \" failed: \" ..\n"
    "        tostring(result)\n"
    "    )\n"
    "end\n"
    "return result\n";

static HMODULE g_hModule     = NULL;
static char g_bridge_host[64] = "127.0.0.1";
static int g_bridge_port     = 27050;
static int g_activation_key  = VK_INSERT;

/* Helper to parse custom activation keys by name or virtual key codes. */
static int ParseKey(const char* value) {
    if (!value || !value[0]) return VK_INSERT;

    if (lstrcmpiA(value, "insert") == 0 || lstrcmpiA(value, "ins") == 0) {
        return VK_INSERT;
    }
    if (lstrcmpiA(value, "delete") == 0 || lstrcmpiA(value, "del") == 0) {
        return VK_DELETE;
    }
    if (lstrcmpiA(value, "home") == 0) {
        return VK_HOME;
    }
    if (lstrcmpiA(value, "end") == 0) {
        return VK_END;
    }
    if (lstrcmpiA(value, "pgup") == 0 || lstrcmpiA(value, "pageup") == 0) {
        return VK_PRIOR;
    }
    if (lstrcmpiA(value, "pgdn") == 0 || lstrcmpiA(value, "pagedown") == 0) {
        return VK_NEXT;
    }
    if (lstrcmpiA(value, "f1") == 0) return VK_F1;
    if (lstrcmpiA(value, "f2") == 0) return VK_F2;
    if (lstrcmpiA(value, "f3") == 0) return VK_F3;
    if (lstrcmpiA(value, "f4") == 0) return VK_F4;
    if (lstrcmpiA(value, "f5") == 0) return VK_F5;
    if (lstrcmpiA(value, "f6") == 0) return VK_F6;
    if (lstrcmpiA(value, "f7") == 0) return VK_F7;
    if (lstrcmpiA(value, "f8") == 0) return VK_F8;
    if (lstrcmpiA(value, "f9") == 0) return VK_F9;
    if (lstrcmpiA(value, "f10") == 0) return VK_F10;
    if (lstrcmpiA(value, "f11") == 0) return VK_F11;
    if (lstrcmpiA(value, "f12") == 0) return VK_F12;

    /* Hex codes (e.g. 0x2D) */
    if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        int val = 0;
        int i;
        for (i = 2; value[i] != '\0'; i++) {
            char c = value[i];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            val = (val << 4) | d;
        }
        return val > 0 ? val : VK_INSERT;
    }

    /* Decimal code */
    return m2_ini_int(value, VK_INSERT);
}

static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;

    if (_stricmp(key, "host") == 0) {
        strncpy(g_bridge_host, value, sizeof(g_bridge_host) - 1);
        g_bridge_host[sizeof(g_bridge_host) - 1] = 0;
    } else if (_stricmp(key, "port") == 0) {
        int p = atoi(value);
        if (p > 0 && p <= 65535) g_bridge_port = p;
    } else if (_stricmp(key, "key") == 0) {
        g_activation_key = ParseKey(value);
    }
}

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "dev_cheat_menu.ini", ini_path, sizeof(ini_path));
    if (!m2_ini_parse(ini_path, OnIniKV, NULL)) {
        m2_logf("[*] dev-cheat-menu: No config found. Using defaults (127.0.0.1:27050, Key: INSERT)");
    } else {
        m2_logf("[*] dev-cheat-menu: Config loaded (Target: %s:%d, Key Code: 0x%02X)",
                g_bridge_host, g_bridge_port, g_activation_key);
    }
}

static int SendLuaCommand(const char* host, int port, const char* script) {
    WSADATA w;
    SOCKET s;
    struct sockaddr_in addr;
    int connected = 0;
    int success = 0;

    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[!] dev-cheat-menu: WSAStartup failed");
        return 0;
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        m2_logf("[!] dev-cheat-menu: socket() failed GLE=%lu", (unsigned long)WSAGetLastError());
        WSACleanup();
        return 0;
    }

    /* Configure timeout to prevent thread blocking */
    DWORD timeout = 1500; /* 1.5 seconds */
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        m2_logf("[!] dev-cheat-menu: Invalid host: %s", host);
        closesocket(s);
        WSACleanup();
        return 0;
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        connected = 1;
    } else {
        m2_logf("[!] dev-cheat-menu: Connect failed to %s:%d. Is lua-bridge active? GLE=%lu",
                host, port, (unsigned long)WSAGetLastError());
    }

    if (connected) {
        int len = (int)strlen(script);
        int sent = 0;
        int send_err = 0;

        /* Send Lua payload */
        while (sent < len) {
            int n = send(s, script + sent, len - sent, 0);
            if (n <= 0) {
                m2_logf("[!] dev-cheat-menu: Send payload failed GLE=%lu", (unsigned long)WSAGetLastError());
                send_err = 1;
                break;
            }
            sent += n;
        }

        /* Send the terminal sentinel */
        if (!send_err) {
            const char* sentinel = "\n<<<RUN>>>\n";
            int sent_len = (int)strlen(sentinel);
            int sent_run = 0;
            while (sent_run < sent_len) {
                int n = send(s, sentinel + sent_run, sent_len - sent_run, 0);
                if (n <= 0) {
                    send_err = 1;
                    break;
                }
                sent_run += n;
            }
        }

        /* Read response to verify registration/queueing */
        if (!send_err) {
            char rx[256];
            int rx_len = 0;
            for (;;) {
                int n = recv(s, rx + rx_len, sizeof(rx) - rx_len - 1, 0);
                if (n <= 0) break;
                rx_len += n;
                rx[rx_len] = '\0';
                if (strstr(rx, "[queued]")) {
                    success = 1;
                    break;
                }
            }
        }
    }

    closesocket(s);
    WSACleanup();
    return success;
}

static DWORD WINAPI WorkerThread(LPVOID arg) {
    (void)arg;

    LoadConfig();
    m2_logf("[*] dev-cheat-menu: Monitoring key code 0x%02X for activation.", g_activation_key);
    m2_logf("[*] dev-cheat-menu: Note: The lua-bridge mod is a dependency and must run on port %d.", g_bridge_port);

    for (;;) {
        Sleep(100);

        /* Only intercept input when the game window is actually in foreground */
        HWND hwnd = GetForegroundWindow();
        if (hwnd) {
            DWORD proc_id = 0;
            GetWindowThreadProcessId(hwnd, &proc_id);
            if (proc_id == GetCurrentProcessId()) {
                /* Check if configured key is pressed */
                if (GetAsyncKeyState(g_activation_key) & 0x8000) {
                    m2_logf("[*] dev-cheat-menu: Key pressed! Sending menu script to lua-bridge.");

                    if (SendLuaCommand(g_bridge_host, g_bridge_port, kCheatMenuScript)) {
                        m2_logf("[+] dev-cheat-menu: Script successfully sent and queued in lua-bridge.");
                    } else {
                        m2_logf("[!] dev-cheat-menu: Failed to queue script in lua-bridge.");
                    }

                    /* Debounce: wait until key is released */
                    while (GetAsyncKeyState(g_activation_key) & 0x8000) {
                        Sleep(50);
                    }
                }
            }
        }
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);

        m2_log_init(g_hModule);
        m2_logf("==================================================");
        m2_logf("[*] dev_cheat_menu.asi loaded (PID %lu)", (unsigned long)GetCurrentProcessId());
        m2_logf("==================================================");

        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        m2_logf("[*] dev_cheat_menu.asi unloaded");
        m2_log_close();
    }
    return TRUE;
}
