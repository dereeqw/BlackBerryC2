#!/usr/bin/env python3
# auto_scan.py

import socket
import ipaddress
import platform
import subprocess
import sys
import os
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- CONFIG ----------------
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,161,179,9949,9948,443,445,465,587,631,636,993,995,3306,3389,5900,8080,8443]
TIMEOUT = 0.6     # timeout para connect y recv
WORKERS = 200
BANNER_RECV = 2048
SYN_TIMEOUT = 0.7  # tiempo que esperamos por respuesta SYN/ACK en el socket crudo
# ----------------------------------------

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows: no get euid -> treat as non-root/admin for raw socket attempt
        return False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip

def detect_cidr24_from_ip(ip):
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"

def parse_arp_cache():
    arp = {}
    system = platform.system().lower()
    try:
        if system == "linux":
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
            for line in lines:
                cols = line.split()
                if len(cols) >= 4:
                    ip = cols[0]; mac = cols[3]
                    if mac != "00:00:00:00:00:00":
                        arp[ip] = mac
        else:
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            out = p.stdout
            for line in out.splitlines():
                line = line.strip()
                if not line: continue
                parts = line.split()
                ip = None; mac = None
                for token in parts:
                    if token.count(".") == 3 and "(" not in token:
                        # try windows-like ip position
                        if all(c.isdigit() or c == "." for c in token):
                            ip = token
                    if "(" in token and token.count(".") == 3:
                        ip = token.strip("()")
                    if "-" in token and len(token) >= 14:
                        mac = token.replace("-", ":")
                    if token.count(":") == 5 and len(token) >= 17:
                        mac = token
                if ip and mac:
                    arp[ip] = mac
    except Exception:
        pass
    return arp

# ----------------- CHECKSUM HELPERS (TCP/IP) -----------------
def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def build_ip_header(src_ip, dst_ip, total_len):
    version_ihl = (4 << 4) + 5
    tos = 0
    tot_len = total_len
    ident = 54321
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    chk = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, tot_len, ident, flags_frag, ttl, proto, chk, src, dst)
    chk = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, tot_len, ident, flags_frag, ttl, proto, chk, src, dst)
    return ip_header

def build_tcp_header(src_ip, dst_ip, src_port, dst_port, seq=0, flags=0x02, window=5840):
    data_offset = 5 << 4
    urg_ptr = 0
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, 0, data_offset, flags, window, 0, urg_ptr)
    # pseudo header for checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    tcp_checksum = checksum(psh)
    tcp_header = struct.pack('!HHLLBBH', src_port, dst_port, seq, 0, data_offset, flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)
    return tcp_header

# Parse IP/TCP headers from raw packet bytes (simple)
def parse_ip_tcp_packet(packet):
    try:
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ihl = (iph[0] & 0xF) * 4
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        proto = iph[6]
        if proto != socket.IPPROTO_TCP:
            return None
        tcp_header = packet[ihl:ihl+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        src_port = tcph[0]
        dst_port = tcph[1]
        seq = tcph[2]
        doff_reserved = tcph[4]
        flags = tcph[5]
        return {'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port, 'flags': flags}
    except Exception:
        return None

# ----------------- SYN SCAN (Linux, root) -----------------
def syn_scan_one(src_ip, dst_ip, src_port, dst_port, raw_send_sock, raw_recv_sock):
    # build ip+tcp with SYN flag
    tcp = build_tcp_header(src_ip, dst_ip, src_port, dst_port, seq=0, flags=0x02)  # SYN flag=0x02
    total_len = 20 + len(tcp)
    ip_hdr = build_ip_header(src_ip, dst_ip, total_len)
    packet = ip_hdr + tcp
    try:
        raw_send_sock.sendto(packet, (dst_ip, 0))
    except Exception:
        return False
    # listen short time on raw_recv_sock for SYN-ACK from target port
    start = time.time()
    while time.time() - start < SYN_TIMEOUT:
        try:
            packet = raw_recv_sock.recv(65535)
            parsed = parse_ip_tcp_packet(packet)
            if not parsed:
                continue
            if parsed['src_ip'] == dst_ip and parsed['src_port'] == dst_port and parsed['dst_port'] == src_port:
                # flags: check SYN+ACK bits: 0x12 (SYN=2, ACK=16)
                if parsed['flags'] & 0x12 == 0x12:
                    return True
                # RST -> closed
                if parsed['flags'] & 0x04 == 0x04:
                    return False
        except socket.timeout:
            break
        except Exception:
            break
    return False

# ----------------- TCP CONNECT + BANNER -----------------
def tcp_connect_banner(ip, port, timeout=TIMEOUT):
    res = {"open": False, "banner": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        res["open"] = True
        # try send minimal probe for HTTP-like services
        try:
            if port in (80, 8080, 8000, 8008, 8443):
                s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: auto-scan/1.0\r\n\r\n" % ip.encode())
            else:
                # probe newline to coax banner
                s.sendall(b"\r\n")
        except Exception:
            pass
        try:
            data = s.recv(BANNER_RECV)
            if data:
                res["banner"] = data.decode(errors="replace").strip()
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return res

# ----------------- MAIN HOST SCAN LOGIC -----------------
def scan_host(ip, ports, do_syn):
    host_info = {"ip": ip, "hostname": None, "mac": None, "ports": []}
    try:
        host_info["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        host_info["hostname"] = None

    # prepare raw sockets if using syn
    raw_send = raw_recv = None
    src_ip = None
    src_port_base = 40000 + (os.getpid() % 10000)
    if do_syn:
        try:
            src_ip = get_local_ip()
            raw_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_recv.settimeout(SYN_TIMEOUT)
            raw_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception:
            raw_send = raw_recv = None

    for idx, p in enumerate(ports):
        open_port = False
        banner = ""
        if raw_send and raw_recv:
            src_port = src_port_base + (idx % 1000)
            try:
                ok = syn_scan_one(src_ip, ip, src_port, p, raw_send, raw_recv)
                if ok:
                    # make a quick TCP connect to grab banner (we already verified open)
                    tb = tcp_connect_banner(ip, p, timeout=TIMEOUT)
                    open_port = tb["open"]
                    banner = tb["banner"]
                else:
                    open_port = False
            except Exception:
                open_port = False
        else:
            tb = tcp_connect_banner(ip, p, timeout=TIMEOUT)
            if tb["open"]:
                open_port = True
                banner = tb["banner"]

        if open_port:
            host_info["ports"].append({"port": p, "banner": banner})
            print(f"[OPEN] {ip}:{p} -> banner: {banner.splitlines()[0] if banner else '<no banner>'}")
    return host_info

def main():
    print("Auto-scan (SYN if root & Linux, otherwise TCP connect). No files are written.")
    local_ip = get_local_ip()
    print(f"IP local detectada: {local_ip}")
    cidr = detect_cidr24_from_ip(local_ip)
    print(f"Red objetivo: {cidr}")
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    total = len(hosts)
    print(f"Hosts a escanear: {total}")

    arp_cache = parse_arp_cache()
    root = is_root() and platform.system().lower() == "linux"
    if root:
        print("Modo: SYN scan (se requiere root). Se hará connect a puertos abiertos para obtener banners.")
    else:
        print("Modo: TCP connect (no root o no Linux).")

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as exe:
        future_to_ip = {exe.submit(scan_host, str(h), COMMON_PORTS, root): str(h) for h in hosts}
        done = 0
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                info = fut.result()
            except Exception as e:
                info = {"ip": ip, "hostname": None, "mac": None, "ports": []}
            if ip in arp_cache:
                info["mac"] = arp_cache[ip]
            # print compacto por host
            if info["ports"] or info["hostname"] or info.get("mac"):
                hostline = f"\nHost: {info['ip']}"
                if info.get("hostname"):
                    hostline += f" ({info['hostname']})"
                if info.get("mac"):
                    hostline += f" MAC:{info['mac']}"
                print(hostline)
                if info["ports"]:
                    for p in info["ports"]:
                        print(f"  - Puerto {p['port']} abierto. Banner: {p['banner'].splitlines()[0] if p['banner'] else '<no banner>'}")
            done += 1
            sys.stdout.write(f"\rProgreso hosts: {done}/{total}")
            sys.stdout.flush()
    print("\nEscaneo completado.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nEscaneo cancelado por usuario.")
        sys.exit(0)
