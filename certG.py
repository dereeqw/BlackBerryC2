#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BlackBerry - certG_Module
import os
import subprocess
import readline
from pathlib import Path
import shutil
import sys
import signal

# ================= CONFIGURACIÓN =================

script_dir = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = Path(f"{script_dir}/cert")
CERT_DIR.mkdir(exist_ok=True)

# ================= CONTROL DE INTERRUPCIONES =================
def handle_interrupt(sig, frame):
    print("\n[X] Interrupción detectada. Saliendo de forma segura...")
    sys.exit(1)

signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)

# ================= FUNCIONES BASE =================

def safe_input(prompt, default=None):
    """Entrada de usuario con soporte para valores por defecto."""
    readline.set_startup_hook(lambda: readline.insert_text(default) if default else None)
    try:
        value = input(f"{prompt}: ").strip()
        return value or default
    except (EOFError, KeyboardInterrupt):
        print("\n[X] Entrada interrumpida por el usuario.")
        sys.exit(1)
    finally:
        readline.set_startup_hook()

def check_existing_files():
    """Verifica si ya existen archivos en cert/ y ofrece opciones."""
    files = list(CERT_DIR.glob("*"))
    if not files:
        return
    print("[=] La carpeta 'cert/' ya contiene archivos:")
    for f in files:
        print(f" - {f.name}")
    print("\n¿Qué deseas hacer?")
    print(" [1] Eliminar todo y empezar limpio")
    print(" [2] Sobrescribir archivos existentes (riesgo de conflictos)")
    print(" [3] Cancelar")

    while True:
        choice = safe_input("Elige una opción (1/2/3)", "3")
        if choice == "1":
            for f in files:
                try:
                    f.unlink()
                except Exception as e:
                    print(f"[!] Error al borrar {f.name}: {e}")
            print("[-] Carpeta limpiada.")
            break
        elif choice == "2":
            print("[!] Sobrescribiendo archivos existentes...")
            break
        elif choice == "3":
            print("[X] Operación cancelada por el usuario.")
            sys.exit(0)
        else:
            print("[!] Opción no válida. Intenta de nuevo.")

def run_openssl(command, error_msg):
    """Ejecuta comandos OpenSSL con manejo de errores."""
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"\n[X] Error ejecutando OpenSSL: {error_msg}")
        print(f"    Detalles: {e.stderr.decode(errors='ignore').strip()}")
        sys.exit(1)
    except FileNotFoundError:
        print("[X] OpenSSL no está instalado o no se encuentra en el PATH.")
        sys.exit(1)

def generate_certificates():
    """Flujo principal del generador de certificados TLS."""
    try:
        check_existing_files()
        print("\n=== Generador de Certificados TLS ===\n")

        # --------- INPUT PRINCIPAL ---------
        C  = safe_input("Código del país (C) (p.ej. MX, US, ES)", "US")
        ST = safe_input("Estado o provincia (ST)", "California")
        L  = safe_input("Localidad o ciudad (L)", "Santa Clara")
        O  = safe_input("Organización (O)", "Apache Software Foundation")
        OU = safe_input("Unidad organizacional (OU)", "Apache Tomcat")
        CN = safe_input("Nombre común del servidor (CN)", "localhost")

        # --------- subjectAltName (DNS/IP) ---------
        dns_entries = [safe_input("Dominio DNS.1", "localhost")]
        while True:
            more = safe_input("¿Agregar otro dominio DNS? (enter para saltar)", "")
            if not more:
                break
            dns_entries.append(more)

        ip_entries = [safe_input("Dirección IP.1", "127.0.0.1")]
        while True:
            more = safe_input("¿Agregar otra IP? (enter para saltar)", "")
            if not more:
                break
            ip_entries.append(more)

        # --------- VALIDACIÓN DE DÍAS ---------
        valid_days_ca = safe_input("Días de validez del certificado CA", "1024")
        valid_days_server = safe_input("Días de validez del certificado del servidor", "500")

        # Validación de números
        try:
            int(valid_days_ca)
            int(valid_days_server)
        except ValueError:
            print("[X] Los valores de días deben ser números enteros.")
            sys.exit(1)

        # --------- CONFIGURACIÓN DE OpenSSL ---------
        conf_path = CERT_DIR / "conf.cnf"
        alt_dns = "\n".join([f"DNS.{i+1} = {dns}" for i, dns in enumerate(dns_entries)])
        alt_ips = "\n".join([f"IP.{i+1} = {ip}" for i, ip in enumerate(ip_entries)])

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
        conf_path.write_text(conf_content)
        print("[+] Archivo de configuración generado correctamente.")

        # --------- GENERACIÓN DE CERTIFICADOS ---------
        print("\n[/] Generando CA...")
        run_openssl(["openssl", "genrsa", "-out", str(CERT_DIR/"ca.key"), "4096"], "Generación de clave CA")
        run_openssl([
            "openssl", "req", "-x509", "-new", "-nodes",
            "-key", str(CERT_DIR/"ca.key"),
            "-sha256", "-days", valid_days_ca,
            "-out", str(CERT_DIR/"ca.crt"),
            "-subj", f"/C={C}/ST={ST}/L={L}/O={O}/OU={OU}/CN=CA"
        ], "Creación de certificado CA")

        print("[+] Generando clave del servidor...")
        run_openssl(["openssl", "genrsa", "-out", str(CERT_DIR/"BlackBerryC2_Proxy.key"), "2048"], "Clave del servidor")

        print("[+] Generando CSR del servidor...")
        run_openssl([
            "openssl", "req", "-new",
            "-key", str(CERT_DIR/"BlackBerryC2_Proxy.key"),
            "-out", str(CERT_DIR/"BlackBerryC2_Proxy.csr"),
            "-config", str(conf_path)
        ], "Solicitud CSR")

        print("[+] Firmando certificado del servidor con CA...")
        run_openssl([
            "openssl", "x509", "-req",
            "-in", str(CERT_DIR/"BlackBerryC2_Proxy.csr"),
            "-CA", str(CERT_DIR/"ca.crt"),
            "-CAkey", str(CERT_DIR/"ca.key"),
            "-CAcreateserial",
            "-out", str(CERT_DIR/"BlackBerryC2_Proxy.crt"),
            "-days", valid_days_server,
            "-sha256",
            "-extfile", str(conf_path),
            "-extensions", "req_ext"
        ], "Firma del certificado")

        print("\n[*] Certificados creados exitosamente en la carpeta 'cert/'")

    except Exception as e:
        print(f"\n[X] Error inesperado: {e}")
        sys.exit(1)

# ================ EJECUCIÓN DIRECTA =================

if __name__ == "__main__":
    generate_certificates()
