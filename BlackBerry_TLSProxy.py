#!/usr/bin/env python3

# BlackBerry - BlackBerry TLS Proxy Module (Sin GUI - Importable)
# Copyright (c) 2025 Moicano9949
# Licencia: Uso no comercial, con permiso de modificación y redistribución

import threading
import logging
import ssl
import socket
import time
import select
import signal
import sys
from collections import defaultdict, deque
import os
import hashlib
import errno

# ---------------- Configuración Global ----------------
DEFAULT_CONFIG = {
    'listen_host': '0.0.0.0',
    'listen_port': 9948,
    'target_host': '127.0.0.1',
    'target_port': 9949,
    'certfile': None,  # Se auto-detecta si es None
    'keyfile': None,   # Se auto-detecta si es None
    'buffer_size': 8192,
    'max_active_ips': 50,
    'max_conn_per_sec': 3,
    'max_conn_per_ip': 5,
    'blacklist_duration': 7200,
    'whitelist_duration': 3600,
    'syn_flood_threshold': 10,
    'rate_limit_window': 60,
    'log_file': None,  # Se auto-detecta si es None
    'log_level': logging.INFO,
    'enable_console_log': False
}

# ---------------- Clase Principal del Proxy ----------------

class BlackBerryProxy:
    """
    Proxy TLS BlackBerry con protección anti-DoS
    
    Ejemplo de uso:
        from blackberry_proxy_daemon import BlackBerryProxy
        
        # Inicializar con configuración por defecto
        proxy = BlackBerryProxy()
        
        # O con configuración personalizada
        proxy = BlackBerryProxy(
            listen_port=8443,
            target_host='192.168.1.100',
            target_port=9949
        )
        
        # Iniciar el proxy
        proxy.start()
        
        # Detener el proxy
        proxy.stop()
        
        # Obtener estadísticas
        stats = proxy.get_stats()
    """
    
    def __init__(self, **kwargs):
        """
        Inicializa el proxy con configuración personalizada
        
        Args:
            listen_host (str): Host de escucha (default: '0.0.0.0')
            listen_port (int): Puerto de escucha (default: 9948)
            target_host (str): Host destino (default: '127.0.0.1')
            target_port (int): Puerto destino (default: 9949)
            certfile (str): Ruta al certificado TLS
            keyfile (str): Ruta a la clave privada TLS
            log_file (str): Ruta al archivo de log
            log_level (int): Nivel de logging (default: logging.INFO)
            enable_console_log (bool): Habilitar salida por consola
        """
        # Configuración
        self.config = DEFAULT_CONFIG.copy()
        self.config.update(kwargs)
        
        # Auto-detectar rutas si no se especifican
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        if self.config['certfile'] is None:
            self.config['certfile'] = f"{self.script_dir}/cert/BlackBerry_Server.crt"
        
        if self.config['keyfile'] is None:
            self.config['keyfile'] = f"{self.script_dir}/cert/BlackBerry_Server.key"
        
        if self.config['log_file'] is None:
            self.config['log_file'] = f"{self.script_dir}/logs/BlackBerryDaemon.log"
        
        # Estructuras de datos
        self.active_connections = {}
        self.connection_stats = defaultdict(lambda: {
            'count': 0, 'last_conn': 0, 'bytes_sent': 0, 'bytes_recv': 0
        })
        self.conn_times = defaultdict(lambda: deque(maxlen=100))
        self.blacklist = {}
        self.whitelist = {}
        self.syn_tracking = defaultdict(lambda: deque(maxlen=50))
        self.state_lock = threading.RLock()
        
        # Control
        self.proxy_running = False
        self.server_socket = None
        self.server_thread = None
        self.cleanup_thread = None
        self.start_time = None
        self.connections_handled = 0
        
        # Logger
        self._setup_logger()
        
        # Crear directorios necesarios
        os.makedirs(os.path.dirname(self.config['log_file']), exist_ok=True)
        os.makedirs(os.path.dirname(self.config['certfile']), exist_ok=True)
    
    def _setup_logger(self):
        """Configura el sistema de logging"""
        self.logger = logging.getLogger(f"BlackBerryProxy-{id(self)}")
        self.logger.setLevel(self.config['log_level'])
        self.logger.handlers.clear()
        
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        
        # Handler para archivo
        file_handler = logging.FileHandler(self.config['log_file'], encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Handler para consola (opcional)
        if self.config['enable_console_log']:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
    
    # ---------------- Métodos de Protección DoS ----------------
    
    def _is_syn_flood_attack(self, ip):
        """Detecta ataques SYN flood"""
        now = time.time()
        with self.state_lock:
            syn_times = self.syn_tracking[ip]
            while syn_times and now - syn_times[0] > self.config['rate_limit_window']:
                syn_times.popleft()
            if len(syn_times) > self.config['syn_flood_threshold']:
                return True
            syn_times.append(now)
            return False
    
    def _apply_socket_options(self, sock):
        """Aplica opciones avanzadas de socket"""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 7200)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 75)
            if hasattr(socket, 'TCP_KEEPCNT'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 9)
            if hasattr(socket, 'TCP_USER_TIMEOUT'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30000)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            sock.settimeout(30.0)
        except Exception as e:
            self.logger.warning(f"Error aplicando opciones de socket: {e}")
    
    def _is_connection_allowed(self, ip, port):
        """Verifica si una conexión debe ser permitida"""
        now = time.time()
        with self.state_lock:
            if ip in self.blacklist and self.blacklist[ip] > now:
                return False, "IP en blacklist"
            
            is_whitelisted = ip in self.whitelist and self.whitelist[ip] > now
            stats = self.connection_stats[ip]
            
            if self._is_syn_flood_attack(ip):
                self.blacklist[ip] = now + self.config['blacklist_duration']
                return False, "Detectado SYN flood"
            
            active_count = len(self.active_connections.get(ip, []))
            max_conn = self.config['max_conn_per_ip'] * 2 if is_whitelisted else self.config['max_conn_per_ip']
            
            if active_count >= max_conn:
                return False, f"Máximo conexiones por IP"
            
            total_active = sum(len(conns) for conns in self.active_connections.values())
            if total_active >= self.config['max_active_ips'] * self.config['max_conn_per_ip']:
                if not is_whitelisted:
                    return False, "Máximo conexiones globales"
            
            times = self.conn_times[ip]
            times.append(now)
            while times and now - times[0] > 1:
                times.popleft()
            
            max_rate = self.config['max_conn_per_sec'] * 2 if is_whitelisted else self.config['max_conn_per_sec']
            if len(times) > max_rate:
                self.blacklist[ip] = now + self.config['blacklist_duration']
                return False, f"Rate limit excedido"
            
            stats['count'] += 1
            stats['last_conn'] = now
            
            return True, "Conexión permitida"
    
    def _register_connection(self, ip, conn):
        """Registra una conexión activa"""
        with self.state_lock:
            if ip not in self.active_connections:
                self.active_connections[ip] = []
            self.active_connections[ip].append(conn)
    
    def _unregister_connection(self, ip, conn):
        """Desregistra una conexión"""
        with self.state_lock:
            if ip in self.active_connections:
                try:
                    self.active_connections[ip].remove(conn)
                    if not self.active_connections[ip]:
                        del self.active_connections[ip]
                except ValueError:
                    pass
    
    def _promote_to_whitelist(self, ip):
        """Promueve IP a whitelist si es confiable"""
        now = time.time()
        with self.state_lock:
            stats = self.connection_stats[ip]
            if (stats['count'] > 50 and
                stats.get('bytes_sent', 0) > 1024*1024 and
                ip not in self.blacklist):
                self.whitelist[ip] = now + self.config['whitelist_duration']
                self.logger.info(f"IP {ip} promovida a whitelist")
    
    # ---------------- Métodos de Forwarding ----------------
    
    def _forward_data(self, src, dst, src_label, dst_label, ip):
        """Reenvía datos entre sockets"""
        bytes_transferred = 0
        last_activity = time.time()
        
        try:
            while self.proxy_running:
                ready = select.select([src], [], [], 30.0)
                if not ready[0]:
                    if time.time() - last_activity > 300:
                        self.logger.debug(f"Timeout: {src_label}")
                        break
                    continue
                
                try:
                    data = src.recv(self.config['buffer_size'])
                    if not data:
                        break
                    
                    sent = 0
                    while sent < len(data):
                        try:
                            chunk_sent = dst.send(data[sent:])
                            if chunk_sent == 0:
                                raise ConnectionError("Socket broken")
                            sent += chunk_sent
                        except socket.error as e:
                            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                                time.sleep(0.001)
                                continue
                            raise
                    
                    bytes_transferred += len(data)
                    last_activity = time.time()
                    
                    with self.state_lock:
                        if "Backend" in dst_label:
                            self.connection_stats[ip]['bytes_sent'] += len(data)
                        else:
                            self.connection_stats[ip]['bytes_recv'] += len(data)
                    
                    if bytes_transferred > 1024*1024:
                        self._promote_to_whitelist(ip)
                
                except socket.timeout:
                    continue
                except socket.error as e:
                    if e.errno in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                        self.logger.debug(f"Conexión perdida: {src_label}")
                    break
                except Exception as e:
                    self.logger.warning(f"Error en forward {src_label}: {e}")
                    break
        
        except Exception as e:
            self.logger.error(f"Error crítico en forward {src_label}: {e}")
        
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
            
            self.logger.debug(f"Forward {src_label}→{dst_label}: {bytes_transferred//1024}KB")
    
    def _create_backend_connection(self, retries=3):
        """Crea conexión al backend"""
        for attempt in range(retries):
            try:
                backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._apply_socket_options(backend_sock)
                backend_sock.settimeout(15.0)
                backend_sock.connect((self.config['target_host'], self.config['target_port']))
                backend_sock.settimeout(None)
                return backend_sock
            
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(min(2 ** attempt, 10))
                else:
                    raise ConnectionError(f"No se pudo conectar al backend: {e}")
    
    def _handle_client(self, client_conn, client_addr, ssl_context):
        """Maneja una conexión de cliente"""
        ip, port = client_addr
        client_label = f"Nueva conexión TLS: {ip}:{port}"
        backend_label = f"Backend({self.config['target_host']}:{self.config['target_port']})"
        
        allowed, reason = self._is_connection_allowed(ip, port)
        if not allowed:
            self.logger.info(f"Rechazada {client_label}: {reason}")
            try:
                client_conn.close()
            except:
                pass
            return
        
        self._register_connection(ip, client_conn)
        self.logger.info(f"PROXY - {client_label}")
        
        tls_conn = None
        backend_sock = None
        
        try:
            self._apply_socket_options(client_conn)
            
            try:
                client_conn.settimeout(30.0)
                tls_conn = ssl_context.wrap_socket(client_conn, server_side=True)
                tls_conn.settimeout(None)
                self._apply_socket_options(tls_conn)
                self.logger.debug(f"TLS OK: {client_label}")
            
            except ssl.SSLError as e:
                self.logger.warning(f"Error TLS {client_label}: {e}")
                with self.state_lock:
                    self.connection_stats[ip]['ssl_errors'] = self.connection_stats[ip].get('ssl_errors', 0) + 1
                    if self.connection_stats[ip]['ssl_errors'] > 5:
                        self.blacklist[ip] = time.time() + self.config['blacklist_duration']
                return
            
            try:
                backend_sock = self._create_backend_connection()
                self.logger.debug(f"Túnel: {client_label} ⟷ {backend_label}")
            
            except Exception as e:
                self.logger.error(f"Error backend {client_label}: {e}")
                return
            
            c2b = threading.Thread(
                target=self._forward_data,
                args=(tls_conn, backend_sock, client_label, backend_label, ip),
                daemon=True
            )
            
            b2c = threading.Thread(
                target=self._forward_data,
                args=(backend_sock, tls_conn, backend_label, client_label, ip),
                daemon=True
            )
            
            c2b.start()
            b2c.start()
            
            c2b.join(timeout=3600)
            b2c.join(timeout=3600)
            
            self.logger.debug(f"Túnel cerrado: {client_label}")
        
        except Exception as e:
            self.logger.error(f"Error manejando {client_label}: {e}")
        
        finally:
            self._unregister_connection(ip, client_conn)
            
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
    
    # ---------------- Daemon de Limpieza ----------------
    
    def _cleanup_daemon(self):
        """Limpia estadísticas periódicamente"""
        while self.proxy_running:
            time.sleep(300)
            now = time.time()
            
            with self.state_lock:
                # Limpiar blacklist
                expired = [ip for ip, exp in self.blacklist.items() if exp <= now]
                for ip in expired:
                    del self.blacklist[ip]
                    self.logger.info(f"IP {ip} removida de blacklist")
                
                # Limpiar whitelist
                expired = [ip for ip, exp in self.whitelist.items() if exp <= now]
                for ip in expired:
                    del self.whitelist[ip]
                
                # Limpiar estadísticas antiguas
                old = [ip for ip, stats in self.connection_stats.items()
                      if now - stats.get('last_conn', 0) > 3600]
                for ip in old:
                    if ip not in self.active_connections:
                        del self.connection_stats[ip]
                        self.conn_times.pop(ip, None)
                        self.syn_tracking.pop(ip, None)
    
    # ---------------- Servidor Principal ----------------
    
    def _run_server(self):
        """Ejecuta el servidor proxy"""
        if not os.path.exists(self.config['certfile']) or not os.path.exists(self.config['keyfile']):
            self.logger.error(f"Certificados no encontrados")
            self.proxy_running = False
            return
        
        # Configurar SSL
        try:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(
                certfile=self.config['certfile'],
                keyfile=self.config['keyfile']
            )
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            ssl_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION
            self.logger.info("TLS configurado")
        
        except Exception as e:
            self.logger.error(f"Error configurando TLS: {e}")
            self.proxy_running = False
            return
        
        # Crear servidor
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if hasattr(socket, 'SO_REUSEPORT'):
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            if hasattr(socket, 'TCP_DEFER_ACCEPT'):
                self.server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_DEFER_ACCEPT, 1)
            
            self.server_socket.bind((self.config['listen_host'], self.config['listen_port']))
            self.server_socket.listen(128)
            self.server_socket.settimeout(1.0)
            
            self.logger.info(f"Proxy iniciado en {self.config['listen_host']}:{self.config['listen_port']}")
            self.logger.info(f"Target: {self.config['target_host']}:{self.config['target_port']}")
        
        except Exception as e:
            self.logger.error(f"Error iniciando servidor: {e}")
            self.proxy_running = False
            return
        
        # Iniciar daemon de limpieza
        self.cleanup_thread = threading.Thread(target=self._cleanup_daemon, daemon=True)
        self.cleanup_thread.start()
        
        self.start_time = time.time()
        last_report = time.time()
        
        # Bucle principal
        while self.proxy_running:
            try:
                try:
                    client_conn, client_addr = self.server_socket.accept()
                    self.connections_handled += 1
                
                except socket.timeout:
                    continue
                except socket.error as e:
                    if e.errno == errno.EBADF and not self.proxy_running:
                        break
                    self.logger.error(f"Error en accept: {e}")
                    continue
                
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_conn, client_addr, ssl_context),
                    daemon=True
                )
                client_thread.start()
                
                # Reporte periódico
                now = time.time()
                if now - last_report > 600:  # Cada 10 minutos
                    stats = self.get_stats()
                    self.logger.info(
                        f"Stats - Uptime: {stats['uptime_str']} | "
                        f"Conexiones: {stats['connections_handled']} | "
                        f"Activas: {stats['active_connections']} | "
                        f"Bloqueadas: {stats['blacklisted_ips']}"
                    )
                    last_report = now
            
            except Exception as e:
                self.logger.error(f"Error en bucle principal: {e}")
                time.sleep(1)
        
        # Limpieza
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        with self.state_lock:
            for ip, conns in list(self.active_connections.items()):
                for conn in conns[:]:
                    try:
                        conn.close()
                    except:
                        pass
        
        total_uptime = int(time.time() - self.start_time)
        self.logger.info(
            f"Proxy detenido - {self.connections_handled} conexiones en "
            f"{total_uptime//3600}h{(total_uptime%3600)//60}m"
        )
    
    # ---------------- API Pública ----------------
    
    def start(self, blocking=False):
        """
        Inicia el proxy
        
        Args:
            blocking (bool): Si True, ejecuta en el hilo actual (bloqueante)
                           Si False, ejecuta en un hilo separado (no bloqueante)
        
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        """
        if self.proxy_running:
            self.logger.warning("El proxy ya está en ejecución")
            return False
        
        self.proxy_running = True
        
        if blocking:
            self._run_server()
        else:
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            time.sleep(0.5)  # Esperar inicialización
        
        return self.proxy_running
    
    def stop(self):
        """Detiene el proxy"""
        if not self.proxy_running:
            self.logger.warning("El proxy no está en ejecución")
            return False
        
        self.logger.info("Deteniendo proxy...")
        self.proxy_running = False
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
        
        return True
    
    def get_stats(self):
        """
        Obtiene estadísticas del proxy
        
        Returns:
            dict: Diccionario con estadísticas actuales
        """
        with self.state_lock:
            active_count = sum(len(conns) for conns in self.active_connections.values())
            
            uptime = 0
            if self.start_time:
                uptime = int(time.time() - self.start_time)
            
            return {
                'running': self.proxy_running,
                'uptime_seconds': uptime,
                'uptime_str': f"{uptime//3600}h {(uptime%3600)//60}m {uptime%60}s",
                'connections_handled': self.connections_handled,
                'active_connections': active_count,
                'unique_ips': len(self.connection_stats),
                'blacklisted_ips': len(self.blacklist),
                'whitelisted_ips': len(self.whitelist),
                'listen_address': f"{self.config['listen_host']}:{self.config['listen_port']}",
                'target_address': f"{self.config['target_host']}:{self.config['target_port']}"
            }
    
    def get_connection_stats(self):
        """
        Obtiene estadísticas detalladas de conexiones
        
        Returns:
            dict: Diccionario con estadísticas por IP
        """
        with self.state_lock:
            return dict(self.connection_stats)
    
    def clear_blacklist(self):
        """Limpia la lista negra de IPs"""
        with self.state_lock:
            count = len(self.blacklist)
            self.blacklist.clear()
            self.logger.info(f"Blacklist limpiada - {count} IPs liberadas")
            return count
    
    def add_to_blacklist(self, ip, duration=None):
        """
        Añade una IP a la lista negra
        
        Args:
            ip (str): Dirección IP
            duration (int): Duración en segundos (None = usar configuración por defecto)
        """
        if duration is None:
            duration = self.config['blacklist_duration']
        
        with self.state_lock:
            self.blacklist[ip] = time.time() + duration
            self.logger.info(f"IP {ip} añadida a blacklist por {duration}s")
    
    def remove_from_blacklist(self, ip):
        """Remueve una IP de la lista negra"""
        with self.state_lock:
            if ip in self.blacklist:
                del self.blacklist[ip]
                self.logger.info(f"IP {ip} removida de blacklist")
                return True
            return False
    
    def is_running(self):
        """Verifica si el proxy está en ejecución"""
        return self.proxy_running


# ---------------- Funciones de Conveniencia ----------------

def start_proxy(**kwargs):
    """
    Función de conveniencia para iniciar un proxy rápidamente
    
    Args:
        **kwargs: Argumentos de configuración (ver BlackBerryProxy.__init__)
    
    Returns:
        BlackBerryProxy: Instancia del proxy iniciado
    
    Ejemplo:
        proxy = start_proxy(listen_port=8443, target_port=9949)
    """
    proxy = BlackBerryProxy(**kwargs)
    proxy.start(blocking=False)
    return proxy


# ---------------- Ejecución Directa ----------------

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='BlackBerry TLS Proxy Daemon')
    parser.add_argument('--listen-host', default='0.0.0.0', help='Host de escucha')
    parser.add_argument('--listen-port', type=int, default=9948, help='Puerto de escucha')
    parser.add_argument('--target-host', default='127.0.0.1', help='Host destino')
    parser.add_argument('--target-port', type=int, default=9949, help='Puerto destino')
    parser.add_argument('--certfile', help='Ruta al certificado TLS')
    parser.add_argument('--keyfile', help='Ruta a la clave privada')
    parser.add_argument('--log-file', help='Ruta al archivo de log')
    parser.add_argument('--verbose', action='store_true', help='Habilitar salida por consola')
    
    args = parser.parse_args()
    
    config = {
        'listen_host': args.listen_host,
        'listen_port': args.listen_port,
        'target_host': args.target_host,
        'target_port': args.target_port,
        'enable_console_log': args.verbose
    }
    
    if args.certfile:
        config['certfile'] = args.certfile
    if args.keyfile:
        config['keyfile'] = args.keyfile
    if args.log_file:
        config['log_file'] = args.log_file
    
    # Crear proxy
    proxy = BlackBerryProxy(**config)
    
    # Manejador de señales
    def signal_handler(signum, frame):
        print(f"\nSeñal {signum} recibida, deteniendo...")
        proxy.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Iniciar proxy
    print(f"Iniciando BlackBerry Proxy...")
    print(f"Listen: {config['listen_host']}:{config['listen_port']}")
    print(f"Target: {config['target_host']}:{config['target_port']}")
    print(f"Presiona Ctrl+C para detener\n")
    
    proxy.start(blocking=True)