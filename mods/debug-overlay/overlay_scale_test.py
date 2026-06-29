"""Scale-test the debug-overlay by sending increasing number of entries."""
import socket
import time

HOST, PORT = "127.0.0.1", 27051

def send(cmds):
    """Send commands over TCP and close the socket."""
    s = socket.create_connection((HOST, PORT), timeout=2.0)
    try:
        payload = "\n".join(cmds) + "\n"
        s.sendall(payload.encode("utf-8"))
    finally:
        s.close()

def main():
    sizes = [2, 4, 8, 16, 32, 64, 128]
    
    print("Starting scale test for Debug_Overlay...")
    print(f"Connecting to debug overlay on {HOST}:{PORT}")
    
    try:
        # Initial ping/clear
        send(["CLEAR_ALL"])
    except OSError as e:
        print(f"Connection failed: {e}")
        print("Make sure the game is running with debug-overlay active.")
        return 1

    for count in sizes:
        print(f"\n[+] Sending {count} entries...")
        
        # Build the command list: first clear previous entries, then set new ones
        cmds = ["CLEAR_ALL"]
        for i in range(1, count + 1):
            cmds.append(f"SET Item_{i:03d} Value_Data_{i:03d}")
        
        try:
            send(cmds)
            print(f"    Sent {count} entries successfully.")
        except OSError as e:
            print(f"    Failed to send command chunk: {e}")
            break
            
        print("    Waiting 5 seconds before next scale step...")
        time.sleep(5)
        
    print("\nScale test sequence completed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
