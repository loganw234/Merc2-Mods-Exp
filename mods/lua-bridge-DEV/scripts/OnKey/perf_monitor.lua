local KEYVAL = "F5"
-- perf_monitor.lua
-- Toggle the debug overlay as a perf HUD. One-shot: each press takes a
-- fresh snapshot. Press F5 again for a new reading, or to hide.

_G.PerfMon_On      = not _G.PerfMon_On
_G.PerfMon_Refresh = (_G.PerfMon_Refresh or 0) + 1

if _G.PerfMon_On then
    -- Force a GC so the reading reflects live objects.
    collectgarbage("collect")
    local mem_kb  = collectgarbage("count")
    local mem_int = mem_kb - (mem_kb % 1)  -- truncate; string.format not guaranteed

    -- Individual sends. The overlay's parser doesn't handle batched
    -- multi-line payloads well; one connect+send+close per command.
    Tcp.Send("127.0.0.1", 27051, "CLEAR_ALL\n")
    Tcp.Send("127.0.0.1", 27051, "COLOR Title FFFF00\n")
    Tcp.Send("127.0.0.1", 27051, "SET Title == Perf Monitor ==\n")
    Tcp.Send("127.0.0.1", 27051, "SET LuaMem " .. mem_int .. " KB (post-GC)\n")
    Tcp.Send("127.0.0.1", 27051, "SET Refresh #" .. _G.PerfMon_Refresh .. " (press F5 to refresh)\n")
    Tcp.Send("127.0.0.1", 27051, "SHOW\n")

    if Loader and Loader.Printf then
        Loader.Printf("[perf_monitor] shown  refresh=#" .. _G.PerfMon_Refresh ..
                      " lua_mem=" .. mem_int .. "KB")
    end
else
    Tcp.Send("127.0.0.1", 27051, "HIDE\n")
    if Loader and Loader.Printf then
        Loader.Printf("[perf_monitor] hidden refresh=#" .. _G.PerfMon_Refresh)
    end
end
