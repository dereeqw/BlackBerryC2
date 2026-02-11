#!/usr/bin/env python3
# BlackBerry - BlackBerry TLS Proxy GUI

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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

# ---------------- Configuración Mejorada ----------------
LISTEN_HOST = '0.0.0.0'
DEFAULT_PORT = 9948
TARGET_HOST, TARGET_PORT = '127.0.0.1', 9949
script_dir = os.path.dirname(__file__)
CERTFILE, KEYFILE = f'{script_dir}/cert/BlackBerry_Server.crt', f'{script_dir}/cert/BlackBerry_Server.key'
BUFFER_SIZE = 8192

# Configuración anti-DoS mejorada
MAX_ACTIVE_IPS = 50
MAX_CONN_PER_SEC = 3
MAX_CONN_PER_IP = 5
MAX_HALF_OPEN = 20
BLACKLIST_DURATION = 7200
WHITELIST_DURATION = 3600
SYN_FLOOD_THRESHOLD = 10
RATE_LIMIT_WINDOW = 60

# Keep-alive optimizado
KEEPALIVE_TIME = 7200
KEEPALIVE_INTVL = 75
KEEPALIVE_PROBES = 9
TCP_USER_TIMEOUT = 30000

# Configuración de logs
LOG_SERVER_FILE = f'{script_dir}/logs/BlackBerryServer.log'
LOG_PROXY_FILE = f'{script_dir}/logs/BlackBerryTLSProxy.log'
LOG_TRAFFIC_FILE = f'{script_dir}/logs/BlackBerryTraffic.log'

# Estructuras de datos thread-safe mejoradas
active_connections = {}
connection_stats = defaultdict(lambda: {
    'count': 0, 'last_conn': 0, 'half_open': 0,
    'syn_count': 0, 'bytes_sent': 0, 'bytes_recv': 0
})
conn_times = defaultdict(lambda: deque(maxlen=100))
blacklist = {}
whitelist = {}
syn_tracking = defaultdict(lambda: deque(maxlen=50))
state_lock = threading.RLock()

# Logger mejorado
logger = logging.getLogger("BlackBerryLogger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler = logging.FileHandler(LOG_PROXY_FILE, encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Logger para tráfico
traffic_logger = logging.getLogger("TrafficLogger")
traffic_logger.setLevel(logging.INFO)
traffic_handler = logging.FileHandler(LOG_TRAFFIC_FILE, encoding='utf-8')
traffic_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
traffic_logger.addHandler(traffic_handler)

# Control global del proxy
proxy_running = False
server_socket = None

# Variables globales para monitoreo de tráfico
traffic_monitoring = False
show_hex_format = True
show_plaintext = True
traffic_buffer = deque(maxlen=1000)

# ---------------- Funciones de Protección DoS ----------------

def calculate_connection_fingerprint(addr, user_agent=None):
    ip, port = addr
    data = f"{ip}:{port}"
    if user_agent:
        data += f":{user_agent}"
    return hashlib.md5(data.encode()).hexdigest()[:16]

def is_syn_flood_attack(ip):
    now = time.time()
    with state_lock:
        syn_times = syn_tracking[ip]
        while syn_times and now - syn_times[0] > RATE_LIMIT_WINDOW:
            syn_times.popleft()
        if len(syn_times) > SYN_FLOOD_THRESHOLD:
            return True
        syn_times.append(now)
        return False

def apply_advanced_socket_options(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_TIME)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTVL)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_PROBES)
        if hasattr(socket, 'TCP_USER_TIMEOUT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, TCP_USER_TIMEOUT)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        sock.settimeout(30.0)
    except Exception as e:
        logger.warning(f"No se pudieron aplicar algunas opciones de socket: {e}")

def is_connection_allowed(ip, port):
    now = time.time()
    with state_lock:
        if ip in blacklist and blacklist[ip] > now:
            return False, "IP en blacklist"
        is_whitelisted = ip in whitelist and whitelist[ip] > now
        stats = connection_stats[ip]
        if is_syn_flood_attack(ip):
            blacklist[ip] = now + BLACKLIST_DURATION
            return False, "Detectado SYN flood"
        active_count = len(active_connections.get(ip, []))
        max_conn = MAX_CONN_PER_IP * 2 if is_whitelisted else MAX_CONN_PER_IP
        if active_count >= max_conn:
            return False, f"Máximo conexiones por IP ({active_count}/{max_conn})"
        total_active = sum(len(conns) for conns in active_connections.values())
        if total_active >= MAX_ACTIVE_IPS * MAX_CONN_PER_IP:
            if not is_whitelisted:
                return False, "Máximo conexiones globales alcanzado"
        times = conn_times[ip]
        times.append(now)
        while times and now - times[0] > 1:
            times.popleft()
        max_rate = MAX_CONN_PER_SEC * 2 if is_whitelisted else MAX_CONN_PER_SEC
        if len(times) > max_rate:
            blacklist[ip] = now + BLACKLIST_DURATION
            return False, f"Rate limit excedido ({len(times)}/{max_rate})"
        stats['count'] += 1
        stats['last_conn'] = now
        return True, "Conexión permitida"

def register_connection(ip, conn):
    with state_lock:
        if ip not in active_connections:
            active_connections[ip] = []
        active_connections[ip].append(conn)

def unregister_connection(ip, conn):
    with state_lock:
        if ip in active_connections:
            try:
                active_connections[ip].remove(conn)
                if not active_connections[ip]:
                    del active_connections[ip]
            except ValueError:
                pass

def promote_to_whitelist(ip):
    now = time.time()
    with state_lock:
        stats = connection_stats[ip]
        if (stats['count'] > 50 and
            stats.get('bytes_sent', 0) > 1024*1024 and
            ip not in blacklist):
            whitelist[ip] = now + WHITELIST_DURATION
            logger.info(f"IP {ip} promovida a whitelist")

# -------- Funciones para manejar logs en GUI --------
def read_log_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            return ''.join(lines[-10000:]) if len(lines) > 10000 else ''.join(lines)
    except Exception as e:
        return f"[ERROR leyendo {filepath}: {e}]"

def clear_log_file(filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.truncate(0)
        return True
    except Exception as e:
        logger.error(f"Error limpiando log {filepath}: {e}")
        return False

# -------- Funciones de Monitoreo de Tráfico --------

def format_data_hex(data, max_bytes=256):
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    else:
        truncated = False
    
    lines = []
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f"{i:04x}: {hex_part:<48} |{ascii_part}|")
    
    result = '\n'.join(lines)
    if truncated:
        result += f"\n... [truncado a {max_bytes} bytes]"
    
    return result

def format_data_plaintext(data, max_bytes=512):
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    else:
        truncated = False
    
    try:
        text = data.decode('utf-8', errors='replace')
    except:
        text = data.decode('latin-1', errors='replace')
    
    printable_text = ''
    for char in text:
        if ord(char) < 32 or ord(char) == 127:
            printable_text += f'\\x{ord(char):02x}'
        else:
            printable_text += char
    
    if truncated:
        printable_text += f"\n... [truncado a {max_bytes} bytes]"
    
    return printable_text

def log_traffic_data(direction, src_label, dst_label, data, ip):
    if not traffic_monitoring or not data:
        return
    
    timestamp = time.strftime('%H:%M:%S.%f')[:-3]
    header = f"[{timestamp}] {direction} {src_label} → {dst_label} ({len(data)} bytes)"
    
    content_parts = [header]
    
    if show_hex_format:
        content_parts.append("=== HEX FORMAT ===")
        content_parts.append(format_data_hex(data))
        content_parts.append("")
    
    if show_plaintext:
        content_parts.append("=== PLAINTEXT FORMAT ===")
        content_parts.append(format_data_plaintext(data))
        content_parts.append("")
    
    content_parts.append("-" * 80)
    traffic_entry = '\n'.join(content_parts)
    
    traffic_buffer.append(traffic_entry)
    
    try:
        traffic_logger.info(f"{direction} {src_label}→{dst_label} {len(data)}B")
    except:
        pass

# -------- GUI Mejorada con Monitoreo --------
class BlackBerryGUI:
    def __init__(self, root):
        self.root = root
        root.title("BlackBerry TLS Proxy - Enhanced Traffic Monitor")
        root.geometry("1200x800")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        self.setup_proxy_tab()
        self.setup_traffic_tab()
        self.setup_stats_tab()
        self.setup_log_server_tab()
        self.setup_log_proxy_tab()

        self.running = False
        self.server_thread = None
        self.stats_thread = None

        self.update_display()

    def setup_proxy_tab(self):
        self.tab_proxy = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_proxy, text="Proxy Control")

        config_frame = ttk.LabelFrame(self.tab_proxy, text="Configuración")
        config_frame.pack(pady=10, padx=10, fill='x')

        self.port_frame = ttk.Frame(config_frame)
        self.port_frame.pack(pady=5, padx=5, anchor='w')

        ttk.Label(self.port_frame, text="Puerto Proxy:").pack(side='left')
        self.port_entry = ttk.Entry(self.port_frame, width=8)
        self.port_entry.pack(side='left', padx=(5, 20))
        self.port_entry.insert(0, str(DEFAULT_PORT))

        self.btn_start = ttk.Button(self.port_frame, text="Iniciar Proxy", command=self.start_proxy)
        self.btn_start.pack(side='left', padx=5)

        self.btn_stop = ttk.Button(self.port_frame, text="Detener Proxy", command=self.stop_proxy, state='disabled')
        self.btn_stop.pack(side='left', padx=5)

        status_frame = ttk.LabelFrame(self.tab_proxy, text="Estado del Sistema")
        status_frame.pack(pady=5, padx=10, fill='x')

        self.info_label = ttk.Label(status_frame, text="Estado: Detenido", font=("Arial", 12, "bold"))
        self.info_label.pack(pady=5)

        self.connections_label = ttk.Label(status_frame, text="Conexiones activas: 0")
        self.connections_label.pack()

        self.protection_label = ttk.Label(status_frame, text="Protección DoS: Activa")
        self.protection_label.pack()

        ttk.Label(self.tab_proxy, text="Log de Actividad:", font=("Arial", 10, "bold")).pack(anchor='w', padx=10, pady=(10,0))
        self.status_box = scrolledtext.ScrolledText(self.tab_proxy, state='disabled', height=20)
        self.status_box.pack(fill='both', expand=True, padx=10, pady=5)

    def setup_traffic_tab(self):
        self.tab_traffic = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_traffic, text="Traffic Monitor")

        controls_frame = ttk.LabelFrame(self.tab_traffic, text="Controles de Monitoreo")
        controls_frame.pack(pady=10, padx=10, fill='x')

        controls_row1 = ttk.Frame(controls_frame)
        controls_row1.pack(pady=5, fill='x')

        self.monitor_var = tk.BooleanVar()
        self.monitor_check = ttk.Checkbutton(
            controls_row1, 
            text="Activar Monitoreo de Tráfico", 
            variable=self.monitor_var,
            command=self.toggle_traffic_monitoring
        )
        self.monitor_check.pack(side='left', padx=5)

        self.btn_clear_traffic = ttk.Button(
            controls_row1, 
            text="Limpiar Monitor", 
            command=self.clear_traffic_monitor
        )
        self.btn_clear_traffic.pack(side='left', padx=10)

        self.btn_export_traffic = ttk.Button(
            controls_row1, 
            text="Exportar Tráfico", 
            command=self.export_traffic
        )
        self.btn_export_traffic.pack(side='left', padx=5)

        controls_row2 = ttk.Frame(controls_frame)
        controls_row2.pack(pady=5, fill='x')

        self.hex_var = tk.BooleanVar(value=True)
        self.hex_check = ttk.Checkbutton(
            controls_row2, 
            text="Mostrar formato HEX", 
            variable=self.hex_var,
            command=self.update_format_options
        )
        self.hex_check.pack(side='left', padx=5)

        self.plaintext_var = tk.BooleanVar(value=True)
        self.plaintext_check = ttk.Checkbutton(
            controls_row2, 
            text="Mostrar texto plano", 
            variable=self.plaintext_var,
            command=self.update_format_options
        )
        self.plaintext_check.pack(side='left', padx=5)

        self.monitor_status_label = ttk.Label(controls_row2, text="Estado: Inactivo", foreground='red')
        self.monitor_status_label.pack(side='right', padx=10)

        traffic_label = ttk.Label(self.tab_traffic, text="Tráfico en Tiempo Real:", font=("Arial", 10, "bold"))
        traffic_label.pack(anchor='w', padx=10, pady=(10,0))

        self.traffic_text = scrolledtext.ScrolledText(
            self.tab_traffic, 
            state='disabled', 
            height=30, 
            font=('Courier', 10)
        )
        self.traffic_text.pack(fill='both', expand=True, padx=10, pady=5)

        stats_frame = ttk.Frame(self.tab_traffic)
        stats_frame.pack(pady=5, padx=10, fill='x')

        self.traffic_stats_label = ttk.Label(stats_frame, text="Paquetes capturados: 0 | Buffer: 0/1000")
        self.traffic_stats_label.pack(side='left')

    def setup_stats_tab(self):
        self.tab_stats = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_stats, text="Estadísticas")

        metrics_frame = ttk.LabelFrame(self.tab_stats, text="Métricas de Protección")
        metrics_frame.pack(pady=10, padx=10, fill='x')

        self.blocked_label = ttk.Label(metrics_frame, text="IPs Bloqueadas: 0")
        self.blocked_label.pack(anchor='w', padx=10, pady=2)

        self.whitelist_label = ttk.Label(metrics_frame, text="IPs en Whitelist: 0")
        self.whitelist_label.pack(anchor='w', padx=10, pady=2)

        self.syn_attacks_label = ttk.Label(metrics_frame, text="Ataques SYN detectados: 0")
        self.syn_attacks_label.pack(anchor='w', padx=10, pady=2)

        ttk.Label(self.tab_stats, text="Estadísticas Detalladas:", font=("Arial", 10, "bold")).pack(anchor='w', padx=10, pady=(10,0))
        self.stats_text = scrolledtext.ScrolledText(self.tab_stats, state='disabled', height=25)
        self.stats_text.pack(fill='both', expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(self.tab_stats)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Limpiar Blacklist", command=self.clear_blacklist).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Exportar Stats", command=self.export_stats).pack(side='left', padx=5)

    def setup_log_server_tab(self):
        self.tab_log_server = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log_server, text="Log Server")

        self.log_server_text = scrolledtext.ScrolledText(self.tab_log_server, state='disabled')
        self.log_server_text.pack(fill='both', expand=True, padx=10, pady=5)

        self.btn_clear_server = ttk.Button(self.tab_log_server, text="Limpiar Log Server", command=self.clear_server_log)
        self.btn_clear_server.pack(pady=5)

    def setup_log_proxy_tab(self):
        self.tab_log_proxy = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log_proxy, text="Log Proxy")

        self.log_proxy_text = scrolledtext.ScrolledText(self.tab_log_proxy, state='disabled')
        self.log_proxy_text.pack(fill='both', expand=True, padx=10, pady=5)

        self.btn_clear_proxy = ttk.Button(self.tab_log_proxy, text="Limpiar Log Proxy", command=self.clear_proxy_log)
        self.btn_clear_proxy.pack(pady=5)

    def toggle_traffic_monitoring(self):
        global traffic_monitoring
        traffic_monitoring = self.monitor_var.get()
        
        if traffic_monitoring:
            self.monitor_status_label.config(text="Estado: ACTIVO", foreground='green')
            self.log("Monitoreo de tráfico ACTIVADO")
        else:
            self.monitor_status_label.config(text="Estado: Inactivo", foreground='red')
            self.log("Monitoreo de tráfico DESACTIVADO")

    def update_format_options(self):
        global show_hex_format, show_plaintext
        show_hex_format = self.hex_var.get()
        show_plaintext = self.plaintext_var.get()
        
        if not show_hex_format and not show_plaintext:
            self.hex_var.set(True)
            show_hex_format = True
            messagebox.showinfo("Info", "Al menos un formato debe estar seleccionado")

    def clear_traffic_monitor(self):
        traffic_buffer.clear()
        self.traffic_text.configure(state='normal')
        self.traffic_text.delete(1.0, tk.END)
        self.traffic_text.configure(state='disabled')
        self.log("Monitor de tráfico limpiado")

    def export_traffic(self):
        if not traffic_buffer:
            messagebox.showinfo("Info", "No hay datos de tráfico para exportar")
            return
        
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"{script_dir}/traffic_export_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=== EXPORTACIÓN DE TRÁFICO BLACKBERRY PROXY ===\n")
                f.write(f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Paquetes capturados: {len(traffic_buffer)}\n")
                f.write("=" * 80 + "\n\n")
                
                for entry in traffic_buffer:
                    f.write(entry + "\n\n")
            
            self.log(f"Tráfico exportado a {filename}")
            messagebox.showinfo("Éxito", f"Tráfico exportado a:\n{filename}")
            
        except Exception as e:
            self.log(f"Error exportando tráfico: {e}")
            messagebox.showerror("Error", f"No se pudo exportar el tráfico:\n{e}")

    def update_traffic_display(self):
        if not traffic_monitoring:
            return
        
        try:
            if traffic_buffer:
                self.traffic_text.configure(state='normal')
                self.traffic_text.delete(1.0, tk.END)
                recent_entries = list(traffic_buffer)[-50:]
                
                for entry in recent_entries:
                    self.traffic_text.insert(tk.END, entry + "\n")
                
                self.traffic_text.configure(state='disabled')
                self.traffic_text.see(tk.END)
            
            packets_captured = len(traffic_buffer)
            buffer_usage = f"{packets_captured}/1000"
            self.traffic_stats_label.config(text=f"Paquetes capturados: {packets_captured} | Buffer: {buffer_usage}")
            
        except Exception as e:
            logger.error(f"Error actualizando display de tráfico: {e}")

    def log(self, text):
        def update_gui():
            self.status_box.configure(state='normal')
            self.status_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {text}\n")
            lines = self.status_box.get("1.0", tk.END).split('\n')
            if len(lines) > 1000:
                self.status_box.delete("1.0", f"{len(lines)-1000}.0")
            self.status_box.configure(state='disabled')
            self.status_box.see(tk.END)

        if threading.current_thread() == threading.main_thread():
            update_gui()
        else:
            self.root.after(0, update_gui)

        logger.info(text)

    def start_proxy(self):
        if self.running:
            messagebox.showinfo("Info", "El proxy ya está en ejecución.")
            return

        try:
            port = int(self.port_entry.get())
            if not (1 <= port <= 65535):
                raise ValueError("Puerto fuera de rango")
        except ValueError:
            messagebox.showerror("Error", "Por favor ingrese un puerto válido entre 1 y 65535")
            return

        global LISTEN_PORT
        LISTEN_PORT = port

        self.info_label.config(text=f"Estado: Iniciando proxy en puerto {LISTEN_HOST}:{LISTEN_PORT}...")
        self.port_entry.config(state='disabled')
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')

        self.running = True
        self.server_thread = threading.Thread(target=start_proxy_server, args=(self.log,), daemon=True)
        self.server_thread.start()

        self.stats_thread = threading.Thread(target=self.cleanup_stats, daemon=True)
        self.stats_thread.start()

        self.log("Proxy iniciado con protección DoS avanzada y monitoreo de tráfico")

    def stop_proxy(self):
        if not self.running:
            messagebox.showinfo("Info", "El proxy no está en ejecución.")
            return

        self.log("Deteniendo proxy...")
        stop_proxy_server()
        self.running = False
        self.info_label.config(text="Estado: Detenido")
        self.port_entry.config(state='normal')
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        
        self.monitor_var.set(False)
        self.toggle_traffic_monitoring()
        
        self.log("Proxy detenido correctamente")

    def cleanup_stats(self):
        while self.running:
            time.sleep(300)
            now = time.time()

            with state_lock:
                expired_blacklist = [ip for ip, exp_time in blacklist.items() if exp_time <= now]
                for ip in expired_blacklist:
                    del blacklist[ip]
                    self.log(f"IP {ip} removida de blacklist")

                expired_whitelist = [ip for ip, exp_time in whitelist.items() if exp_time <= now]
                for ip in expired_whitelist:
                    del whitelist[ip]

                old_stats = [ip for ip, stats in connection_stats.items()
                           if now - stats.get('last_conn', 0) > 3600]
                for ip in old_stats:
                    if ip not in active_connections:
                        del connection_stats[ip]
                        conn_times.pop(ip, None)
                        syn_tracking.pop(ip, None)

    def update_display(self):
        try:
            if self.running:
                active_count = sum(len(conns) for conns in active_connections.values())
                current_port = self.port_entry.get() if hasattr(self, 'port_entry') else str(DEFAULT_PORT)
                self.info_label.config(text=f"Estado: Ejecutándose en {LISTEN_HOST}:{current_port}")
                self.connections_label.config(text=f"Conexiones activas: {active_count}")
            else:
                self.info_label.config(text="Estado: Detenido")
                self.connections_label.config(text="Conexiones activas: 0")

            with state_lock:
                self.blocked_label.config(text=f"IPs Bloqueadas: {len(blacklist)}")
                self.whitelist_label.config(text=f"IPs en Whitelist: {len(whitelist)}")

                now = time.time()
                recent_attacks = sum(1 for ip, times in syn_tracking.items()
                                   if times and now - times[-1] < 300)
                self.syn_attacks_label.config(text=f"Ataques SYN detectados (5min): {recent_attacks}")

            self.update_detailed_stats()
            self.update_logs()
            self.update_traffic_display()

        except Exception as e:
            logger.error(f"Error actualizando display: {e}")

        self.root.after(3000, self.update_display)

    def update_detailed_stats(self):
        try:
            stats_text = "=== ESTADÍSTICAS DEL SISTEMA ===\n\n"

            with state_lock:
                now = time.time()

                top_ips = sorted(connection_stats.items(),
                               key=lambda x: x[1]['count'], reverse=True)[:10]

                stats_text += "TOP 10 IPs POR CONEXIONES:\n"
                for ip, stats in top_ips:
                    status = "WHITELIST" if ip in whitelist else "BLACKLIST" if ip in blacklist else "NORMAL"
                    stats_text += f"{status} {ip}: {stats['count']} conexiones, "
                    stats_text += f"{stats.get('bytes_sent', 0)//1024}KB enviados\n"

                stats_text += f"\nIPs EN BLACKLIST ({len(blacklist)}):\n"
                for ip, exp_time in list(blacklist.items())[:10]:
                    remaining = max(0, int(exp_time - now))
                    stats_text += f"BLOCK {ip} - Expira en {remaining//60}min {remaining%60}s\n"

                stats_text += f"\nIPs EN WHITELIST ({len(whitelist)}):\n"
                for ip, exp_time in list(whitelist.items())[:10]:
                    remaining = max(0, int(exp_time - now))
                    stats_text += f"ALLOW {ip} - Expira en {remaining//60}min {remaining%60}s\n"

                stats_text += f"\nCONEXIONES ACTIVAS POR IP:\n"
                for ip, conns in active_connections.items():
                    stats_text += f"ACTIVE {ip}: {len(conns)} conexiones activas\n"

            self.stats_text.configure(state='normal')
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, stats_text)
            self.stats_text.configure(state='disabled')
            self.stats_text.see(tk.END)

        except Exception as e:
            logger.error(f"Error actualizando estadísticas detalladas: {e}")

    def update_logs(self):
        try:
            server_log = read_log_file(LOG_SERVER_FILE)
            self.log_server_text.configure(state='normal')
            self.log_server_text.delete(1.0, tk.END)
            self.log_server_text.insert(tk.END, server_log)
            self.log_server_text.configure(state='disabled')
            self.log_server_text.see(tk.END)

            proxy_log = read_log_file(LOG_PROXY_FILE)
            self.log_proxy_text.configure(state='normal')
            self.log_proxy_text.delete(1.0, tk.END)
            self.log_proxy_text.insert(tk.END, proxy_log)
            self.log_proxy_text.configure(state='disabled')
            self.log_proxy_text.see(tk.END)

        except Exception as e:
            logger.error(f"Error actualizando logs: {e}")

    def clear_blacklist(self):
        if messagebox.askyesno("Confirmar", "¿Seguro que deseas limpiar la blacklist completa?"):
            with state_lock:
                cleared_count = len(blacklist)
                blacklist.clear()
            self.log(f"Blacklist limpiada - {cleared_count} IPs liberadas")

    def export_stats(self):
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"{script_dir}/stats_export_{timestamp}.txt"

            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=== EXPORTACIÓN DE ESTADÍSTICAS BLACKBERRY PROXY ===\n")
                f.write(f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                with state_lock:
                    f.write(f"IPs en Blacklist: {len(blacklist)}\n")
                    f.write(f"IPs en Whitelist: {len(whitelist)}\n")
                    f.write(f"Conexiones activas totales: {sum(len(conns) for conns in active_connections.values())}\n\n")

                    f.write("ESTADÍSTICAS POR IP:\n")
                    for ip, stats in connection_stats.items():
                        f.write(f"{ip}: {stats}\n")

            self.log(f"Estadísticas exportadas a {filename}")
            messagebox.showinfo("Éxito", f"Estadísticas exportadas a:\n{filename}")

        except Exception as e:
            self.log(f"Error exportando estadísticas: {e}")
            messagebox.showerror("Error", f"No se pudieron exportar las estadísticas:\n{e}")

    def clear_server_log(self):
        if messagebox.askyesno("Confirmar", "¿Seguro que deseas limpiar el Log Server?"):
            if clear_log_file(LOG_SERVER_FILE):
                self.log("Log Server limpiado correctamente")
            else:
                messagebox.showerror("Error", "No se pudo limpiar el Log Server.")

    def clear_proxy_log(self):
        if messagebox.askyesno("Confirmar", "¿Seguro que deseas limpiar el Log Proxy?"):
            if clear_log_file(LOG_PROXY_FILE):
                self.log("Log Proxy limpiado correctamente")
            else:
                messagebox.showerror("Error", "No se pudo limpiar el Log Proxy.")

# -------- Funciones del servidor --------

def forward_data_optimized(src, dst, src_label, dst_label, log_func, ip):
    bytes_transferred = 0
    last_activity = time.time()
    packets_logged = 0

    try:
        while True:
            ready = select.select([src], [], [], 30.0)
            if not ready[0]:
                if time.time() - last_activity > 300:
                    log_func(f"Timeout por inactividad: {src_label}")
                    break
                continue

            try:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    log_func(f"Conexión cerrada por peer: {src_label}")
                    break

                if traffic_monitoring and data:
                    direction = "CLIENT→BACKEND" if "Cliente" in src_label else "BACKEND→CLIENT"
                    log_traffic_data(direction, src_label, dst_label, data, ip)
                    packets_logged += 1

                sent = 0
                while sent < len(data):
                    try:
                        chunk_sent = dst.send(data[sent:])
                        if chunk_sent == 0:
                            raise ConnectionError("Socket connection broken")
                        sent += chunk_sent
                    except socket.error as e:
                        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            time.sleep(0.001)
                            continue
                        raise

                bytes_transferred += len(data)
                last_activity = time.time()

                if bytes_transferred % (BUFFER_SIZE * 10) == 0:
                    monitor_info = f" [Monitor: {packets_logged} paquetes]" if traffic_monitoring else ""
                    log_func(f"{src_label}→{dst_label}: {bytes_transferred//1024}KB transferidos{monitor_info}")

                with state_lock:
                    if dst_label.startswith("Backend"):
                        connection_stats[ip]['bytes_sent'] += len(data)
                    else:
                        connection_stats[ip]['bytes_recv'] += len(data)

                if bytes_transferred > 1024*1024:
                    promote_to_whitelist(ip)

            except socket.timeout:
                continue
            except socket.error as e:
                if e.errno in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                    log_func(f"Conexión perdida: {src_label} ({e})")
                else:
                    log_func(f"Error socket {src_label}: {e}")
                break
            except Exception as e:
                log_func(f"Error inesperado {src_label}: {e}")
                break

    except Exception as e:
        log_func(f"Error crítico en forward {src_label}: {e}")

    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                sock.close()
            except:
                pass

        monitor_summary = f" | {packets_logged} paquetes monitoreados" if traffic_monitoring else ""
        log_func(f"Forward completado {src_label}→{dst_label}: {bytes_transferred//1024}KB total{monitor_summary}")
        return bytes_transferred

def create_backend_connection(target_host, target_port, retries=3, log_func=None):
    for attempt in range(retries):
        try:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            apply_advanced_socket_options(backend_sock)

            backend_sock.settimeout(15.0)
            backend_sock.connect((target_host, target_port))

            backend_sock.settimeout(None)

            if log_func:
                log_func(f"Conexión backend establecida ({attempt+1}/{retries})")

            return backend_sock

        except Exception as e:
            if log_func:
                log_func(f"Intento {attempt+1}/{retries} fallido: {e}")

            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 10))
            else:
                raise ConnectionError(f"No se pudo conectar al backend después de {retries} intentos")

def handle_client_enhanced(client_conn, client_addr, ssl_context, log_func):
    ip, port = client_addr
    client_label = f"Cliente({ip}:{port})"
    backend_label = f"Backend({TARGET_HOST}:{TARGET_PORT})"

    allowed, reason = is_connection_allowed(ip, port)
    if not allowed:
        log_func(f"Conexión rechazada {client_label}: {reason}")
        try:
            client_conn.close()
        except:
            pass
        return

    register_connection(ip, client_conn)
    log_func(f"Nueva conexión aceptada: {client_label}")

    tls_conn = None
    backend_sock = None

    try:
        apply_advanced_socket_options(client_conn)

        try:
            client_conn.settimeout(30.0)
            tls_conn = ssl_context.wrap_socket(client_conn, server_side=True)
            tls_conn.settimeout(None)
            apply_advanced_socket_options(tls_conn)
            log_func(f"Handshake TLS completado: {client_label}")

        except ssl.SSLError as e:
            log_func(f"Error TLS {client_label}: {e}")
            with state_lock:
                connection_stats[ip]['ssl_errors'] = connection_stats[ip].get('ssl_errors', 0) + 1
                if connection_stats[ip]['ssl_errors'] > 5:
                    blacklist[ip] = time.time() + BLACKLIST_DURATION
                    log_func(f"IP {ip} bloqueada por errores SSL repetidos")
            return

        try:
            backend_sock = create_backend_connection(TARGET_HOST, TARGET_PORT, log_func=log_func)
            monitor_status = " [MONITOR ACTIVO]" if traffic_monitoring else ""
            log_func(f"Túnel establecido: {client_label} ⟷ {backend_label}{monitor_status}")

        except Exception as e:
            log_func(f"Error conectando backend para {client_label}: {e}")
            return

        client_to_backend = threading.Thread(
            target=forward_data_optimized,
            args=(tls_conn, backend_sock, client_label, backend_label, log_func, ip),
            daemon=True,
            name=f"C2B-{ip}"
        )

        backend_to_client = threading.Thread(
            target=forward_data_optimized,
            args=(backend_sock, tls_conn, backend_label, client_label, log_func, ip),
            daemon=True,
            name=f"B2C-{ip}"
        )

        client_to_backend.start()
        backend_to_client.start()

        client_to_backend.join(timeout=3600)
        backend_to_client.join(timeout=3600)

        log_func(f"Túnel cerrado: {client_label}")

    except Exception as e:
        log_func(f"Error manejando cliente {client_label}: {e}")

    finally:
        unregister_connection(ip, client_conn)

        for conn in (tls_conn, backend_sock, client_conn):
            if conn:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    conn.close()
                except:
                    pass

def start_proxy_server(log_func):
    global proxy_running, server_socket, LISTEN_PORT

    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        log_func(f"Certificados TLS no encontrados: {CERTFILE}, {KEYFILE}")
        return

    proxy_running = True

    try:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        ssl_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION

        log_func("Contexto TLS configurado correctamente")

    except Exception as e:
        log_func(f"Error configurando TLS: {e}")
        return

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        if hasattr(socket, 'TCP_DEFER_ACCEPT'):
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_DEFER_ACCEPT, 1)

        if hasattr(socket, 'SO_ACCEPTFILTER'):
            try:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTFILTER, b'httpready')
            except:
                pass

        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(128)

        server_socket.settimeout(1.0)

        monitor_info = " | Monitoreo de tráfico disponible" if True else ""
        log_func(f"Servidor iniciado en {LISTEN_HOST}:{LISTEN_PORT}{monitor_info}")
        log_func("Protecciones activas: Anti-SYN flood, Rate limiting, IP blacklisting")

    except Exception as e:
        log_func(f"Error iniciando servidor: {e}")
        proxy_running = False
        return

    start_time = time.time()
    connections_handled = 0
    last_report = time.time()

    while proxy_running:
        try:
            try:
                client_conn, client_addr = server_socket.accept()
                connections_handled += 1

            except socket.timeout:
                continue
            except socket.error as e:
                if e.errno == errno.EBADF and not proxy_running:
                    break
                log_func(f"Error en accept(): {e}")
                continue
            except Exception as e:
                log_func(f"Error inesperado en accept(): {e}")
                continue

            client_thread = threading.Thread(
                target=handle_client_enhanced,
                args=(client_conn, client_addr, ssl_context, log_func),
                daemon=True,
                name=f"Client-{client_addr[0]}-{connections_handled}"
            )
            client_thread.start()

            now = time.time()
            if now - last_report > 300:
                uptime = int(now - start_time)
                active_count = sum(len(conns) for conns in active_connections.values())
                traffic_status = f", {len(traffic_buffer)} paquetes capturados" if traffic_monitoring else ""

                report = (f"Estadísticas ({uptime//3600}h {(uptime%3600)//60}m): "
                         f"{connections_handled} conexiones manejadas, "
                         f"{active_count} activas, "
                         f"{len(blacklist)} IPs bloqueadas{traffic_status}")
                log_func(report)

                last_report = now

        except KeyboardInterrupt:
            log_func("Interrupción por teclado recibida")
            break
        except Exception as e:
            log_func(f"Error crítico en bucle principal: {e}")
            time.sleep(1)

    log_func("Cerrando servidor...")
    if server_socket:
        try:
            server_socket.close()
        except:
            pass

    total_uptime = int(time.time() - start_time)
    final_report = (f"Resumen final: {connections_handled} conexiones en "
                   f"{total_uptime//3600}h {(total_uptime%3600)//60}m")
    
    if traffic_monitoring:
        final_report += f", {len(traffic_buffer)} paquetes capturados"
    
    log_func(final_report)

def stop_proxy_server():
    global proxy_running, server_socket, traffic_monitoring

    proxy_running = False
    traffic_monitoring = False

    if server_socket:
        try:
            server_socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            server_socket.close()
        except:
            pass
        server_socket = None

    with state_lock:
        for ip, conns in list(active_connections.items()):
            for conn in conns[:]:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                except:
                    pass
            active_connections[ip].clear()
        active_connections.clear()

# -------- Función principal GUI --------
def lanzar_gui_proxy():
    os.makedirs(f"{script_dir}/logs", exist_ok=True)
    os.makedirs(f"{script_dir}/cert", exist_ok=True)

    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        print(f"ADVERTENCIA: Certificados TLS no encontrados:")
        print(f"   - {CERTFILE}")
        print(f"   - {KEYFILE}")
        print("   El proxy no podrá iniciarse sin certificados válidos.")

    root = tk.Tk()
    try:
        app = BlackBerryGUI(root)
        root.protocol("WM_DELETE_WINDOW", lambda: (stop_proxy_server(), root.destroy()))
        root.mainloop()
    except Exception as e:
        logger.error(f"Error crítico en GUI: {e}")
        print(f"Error crítico: {e}")
    finally:
        stop_proxy_server()

if __name__ == '__main__':
    lanzar_gui_proxy()