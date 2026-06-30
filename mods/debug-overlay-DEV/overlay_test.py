"""Smoke-test the debug-overlay TCP command server."""
import socket
import time

HOST, PORT = "127.0.0.1", 27051

def send(cmds, expect_reply=False, timeout=2.0):
    """Send commands and optionally wait for a reply line."""
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        payload = "\n".join(cmds) + "\n"
        s.sendall(payload.encode("utf-8"))
        if expect_reply:
            s.settimeout(timeout)
            try:
                data = s.recv(64).decode("utf-8", "replace").strip()
                return data
            except socket.timeout:
                return "(no reply within %.1fs)" % timeout
    finally:
        s.close()
    return None

def main():
    print("[1] PING to confirm server is listening...")
    try:
        reply = send(["PING"], expect_reply=True)
        print(f"    -> {reply!r}")
    except OSError as e:
        print(f"    connect failed: {e}")
        print(f"    is debug_overlay.asi loaded and listening on {HOST}:{PORT}?")
        return 1

    print("\n[2] Setting a few labels — should appear top-left in game...")
    send([
        "SET fps 60",
        "SET cash 1141700",
        "SET player_pos 3789.3, 450.1, -3881.2",
        "SET hooks 5/5",
        "SET bridge_queue 0",
    ])
    print("    sent 5 labels. Check the game window — labels should be visible now.")
    print("    (pausing 4 seconds so you can confirm)")
    time.sleep(4)

    print("\n[3] Coloring 'fps' red and 'bridge_queue' yellow...")
    send(["COLOR fps FF4040", "COLOR bridge_queue FFFF00"])
    time.sleep(3)

    print("\n[4] Updating 'fps' to a new value 5 times to simulate live data...")
    for i, v in enumerate([58, 61, 60, 59, 60]):
        send([f"SET fps {v}"])
        time.sleep(0.5)
    print("    'fps' should have ticked 58 -> 61 -> 60 -> 59 -> 60")

    print("\n[5] Toggling HIDE then SHOW...")
    send(["HIDE"])
    print("    HIDE sent — overlay should disappear")
    time.sleep(2)
    send(["SHOW"])
    print("    SHOW sent — overlay should reappear")
    time.sleep(2)

    print("\n[6] Removing one label ('cash') with CLEAR...")
    send(["CLEAR cash"])
    print("    'cash' line should be gone; box should auto-shrink")
    time.sleep(3)

    print("\n[7] Adding 'side_label' to demonstrate insertion order...")
    send(["SET side_label appended-at-end"])
    print("    should appear at the bottom (insertion order preserved)")
    time.sleep(3)

    print("\n[8] CLEAR_ALL — overlay should empty out completely.")
    send(["CLEAR_ALL"])
    print("\n[done]")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
