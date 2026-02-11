#!/usr/bin/env python3
import os
import subprocess
import readline
from pathlib import Path
import shutil
script_dir = os.path.dirname(__file__)
# ========= CONFIGURACIÓN =========

CERT_DIR = Path(f"{script_dir}/cert")
CERT_DIR.mkdir(exist_ok=True)

# ====== VALIDACIÓN DE EXISTENCIA ======

def check_existing_files():
    files = list(CERT_DIR.glob("*"))
    if files:
        print("[=] La carpeta 'cert/' ya contiene archivos:")
        for f in files:
            print(f" - {f.name}")
        print("\n¿Qué deseas hacer?")
        print(" [1] Eliminar todo y empezar limpio")
        print(" [2] Sobrescribir archivos existentes (riesgo de conflictos)")
        print(" [3] Cancelar")

        choice = input("Elige una opción (1/2/3): ").strip()
        if choice == "1":
            for f in files:
                try:
                    f.unlink()
                except Exception as e:
                    print(f"Error al borrar {f}: {e}")
            print("[-] Carpeta limpiada.")
        elif choice == "2":
            print("[!] Sobrescribiendo archivos existentes...")
        else:
            print("[X] Operación cancelada.")
            exit()

check_existing_files()

# ===== FUNCIONES =====

def ask(prompt, default=None):
    """
    Pregunta al usuario mostrando un valor por defecto.
    Usa readline para precargar el valor si se da default.
    """
    readline.set_startup_hook(lambda: readline.insert_text(default) if default else None)
    try:
        return input(f"{prompt}: ").strip() or default
    finally:
        readline.set_startup_hook()

print("\n=== Generador de Certificados TLS ===\n")

# ========= INPUT DE DATOS =========

C  = ask("Código del país (C) (p.ej. MX, US, ES)", "RU")
ST = ask("Estado o provincia (ST)", "Moscow")
L  = ask("Localidad o ciudad (L)", "Moscow")
O  = ask("Organización (O)", "BlackBerry(Net)")
OU = ask("Unidad organizacional (OU)", "BlackBerry Secure Transport (AES-GCM/TLS)")
CN = ask("Nombre común del servidor (CN)", "localhost")

# subjectAltName - DNS
dns_entries = [ask("Dominio DNS.1", "localhost")]
while True:
    more = ask("¿Agregar otro dominio DNS? (enter para saltar)", "")
    if not more:
        break
    dns_entries.append(more)

# subjectAltName - IP
ip_entries = [ask("Dirección IP.1", "127.0.0.1")]
while True:
    more = ask("¿Agregar otra IP? (enter para saltar)", "")
    if not more:
        break
    ip_entries.append(more)

# ========= INPUT PARA VALIDEZ =========

valid_days_ca = ask(
    "Días de validez para el certificado de la CA "
    "(indica un número entero de días; p.ej. 1024)", 
    "1024"
)
valid_days_server = ask(
    "Días de validez para el certificado del servidor "
    "(indica un número entero de días; p.ej. 365)", 
    "500"
)

# ========= CREAR conf.cnf =========

conf_path = CERT_DIR / "conf.cnf"

alt_dns = "\n".join(
    [f"DNS.{i+1} = {dns}" for i, dns in enumerate(dns_entries)]
)
alt_ips = "\n".join(
    [f"IP.{i+1} = {ip}" for i, ip in enumerate(ip_entries)]
)

conf_content = f"""[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = {C}
ST = {ST}
L  = {L}
O  = {O}
OU = {OU}
CN = {CN}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
{alt_dns}
{alt_ips}
"""

with open(conf_path, "w") as f:
    f.write(conf_content)

# ========= COMANDOS OpenSSL =========

print("\n[/] Generando CA...")
subprocess.run(
    ["openssl", "genrsa", "-out", str(CERT_DIR/"ca.key"), "4096"],
    check=True
)
subprocess.run([
    "openssl", "req", "-x509", "-new", "-nodes",
    "-key", str(CERT_DIR/"ca.key"),
    "-sha256", "-days", valid_days_ca,
    "-out", str(CERT_DIR/"ca.crt"),
    "-subj", f"/C={C}/ST={ST}/L={L}/O={O}/OU={OU}/CN=CA"
], check=True)

print("[+] Generando clave del servidor...")
subprocess.run(
    ["openssl", "genrsa", "-out", str(CERT_DIR/"BlackBerry_Server.key"), "2048"],
    check=True
)

print("[+] Generando CSR del servidor...")
subprocess.run([
    "openssl", "req", "-new",
    "-key", str(CERT_DIR/"BlackBerry_Server.key"),
    "-out", str(CERT_DIR/"BlackBerry_Server.csr"),
    "-config", str(conf_path)
], check=True)

print("[+] Firmando certificado del servidor con CA...")
subprocess.run([
    "openssl", "x509", "-req",
    "-in", str(CERT_DIR/"BlackBerry_Server.csr"),
    "-CA", str(CERT_DIR/"ca.crt"),
    "-CAkey", str(CERT_DIR/"ca.key"),
    "-CAcreateserial",
    "-out", str(CERT_DIR/"BlackBerry_Server.crt"),
    "-days", valid_days_server,
    "-sha256",
    "-extfile", str(conf_path),
    "-extensions", "req_ext"
], check=True)

print("\n[*] Certificado creado exitosamente en la carpeta 'cert/'")
