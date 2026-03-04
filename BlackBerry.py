#!/usr/bin/env python3
#BlackBerry Launcher
import subprocess
import sys
import os
import shutil
import importlib.util
import time
import random
import string

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKBERRY_SCRIPT = os.path.join(SCRIPT_DIR, "BlackBerryC2_server.py")
TMUX_SESSION_NAME = "BlackBerryC2-Server"
HISTORY_LIMIT = 1000000  # scrollback gigante

# Colores ANSI
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = '\033[0m'
    YELLOW = "\033[93m"

def show_loading_banner():
    """Animación letra por letra estilo msfconsole."""
    
    target_text = "Starting BlackBerry C2 Framework"
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    
    display = ""
    
    for i, target_char in enumerate(target_text):
        if target_char == " ":
            display += " "
            print(f"\r{Colors.RED}{display}{Colors.RESET}", end='', flush=True)
            time.sleep(0.03)
        else:
            # Hacer glitch en el carácter antes de mostrarlo
            for _ in range(3):
                glitch_char = random.choice(charset)
                print(f"\r{Colors.RED}{display}{glitch_char}{Colors.RESET}", end='', flush=True)
                time.sleep(0.02)
            
            # Mostrar el carácter correcto
            display += target_char
            print(f"\r{Colors.RED}{display}{Colors.RESET}", end='', flush=True)
            time.sleep(0.04)
    
    # Color final verde
    print(f"\r{Colors.GREEN}{target_text}{Colors.RESET}", end='', flush=True)
    time.sleep(0.5)
    print()
    
    # Limpiar pantalla
    time.sleep(0.3)
    print("\033[H\033[J", end='', flush=True)

def silent_run(cmd):
    """Ejecuta comando sin output."""
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

def check_tmux_installed():
    """Verifica si tmux está instalado."""
    return shutil.which("tmux") is not None

def tmux_has_session(session_name=TMUX_SESSION_NAME):
    """Devuelve True si la sesión tmux existe."""
    try:
        r = subprocess.run(
            ["tmux", "has-session", "-t", session_name], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        return r.returncode == 0
    except Exception:
        return False

def get_current_tmux_session():
    """Si estamos dentro de tmux, devuelve el nombre de la sesión actual."""
    if "TMUX" not in os.environ:
        return None
    try:
        r = subprocess.run(
            ["tmux", "display-message", "-p", "#S"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        name = r.stdout.strip()
        return name if name else None
    except Exception:
        return None

def kill_tmux_session():
    """Mata la sesión tmux silenciosamente."""
    silent_run(["tmux", "kill-session", "-t", TMUX_SESSION_NAME])

def get_python_executable():
    """Obtiene el ejecutable de Python correcto, respetando entornos virtuales."""
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        return sys.executable
    return sys.executable

def run_directly(args):
    """Ejecuta el script directamente en el terminal actual."""
    if not os.path.exists(BLACKBERRY_SCRIPT):
        print(f"Error: no se encontró el script: {BLACKBERRY_SCRIPT}")
        sys.exit(1)
    
    # Mostrar animación de carga
    if "-h" not in args and "--help" not in args and "--kill" not in args:
        show_loading_banner()
    
    try:
        original_argv = sys.argv
        sys.argv = [BLACKBERRY_SCRIPT] + args
        
        spec = importlib.util.spec_from_file_location("BlackBerryC2_server", BLACKBERRY_SCRIPT)
        if spec is None or spec.loader is None:
            print(f"Error: No se pudo cargar el módulo desde {BLACKBERRY_SCRIPT}")
            sys.exit(1)
            
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        sys.argv = original_argv
        
    except SystemExit as e:
        sys.exit(e.code if hasattr(e, 'code') else 0)
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario.")
        sys.exit(0)
    except ImportError as e:
        print(f"Error de importación: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error ejecutando el script: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def create_tmux_session(args):
    """Crea una sesión tmux con historial gigante y adjunta al usuario."""
    if not os.path.exists(BLACKBERRY_SCRIPT):
        print(f"Error: no se encontró el script: {BLACKBERRY_SCRIPT}")
        sys.exit(1)

    python_exec = get_python_executable()
    
    # Mostrar animación de carga
    show_loading_banner()
    
    # Construir comando python con argumentos escapados
    cmd_parts = [python_exec, BLACKBERRY_SCRIPT] + args
    python_cmd = " ".join([f"'{a}'" if " " in a or "$" in a else a for a in cmd_parts])

    try:
        # Crear la sesión
        subprocess.run([
            "tmux", "new-session", "-d",
            "-s", TMUX_SESSION_NAME,
            "-x", "200", "-y", "50",
            "bash", "-lc", python_cmd
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Configurar historial gigante
        silent_run(["tmux", "set-option", "-g", "history-limit", str(HISTORY_LIMIT)])
        silent_run(["tmux", "set-option", "-t", TMUX_SESSION_NAME, "history-limit", str(HISTORY_LIMIT)])
        
        # Configuraciones para copiar/pegar
        silent_run(["tmux", "set-option", "-t", TMUX_SESSION_NAME, "mouse", "on"])
        silent_run(["tmux", "set-option", "-t", TMUX_SESSION_NAME, "set-clipboard", "on"])
        silent_run(["tmux", "set-option", "-g", "mouse", "on"])
        silent_run(["tmux", "set-option", "-g", "set-clipboard", "on"])
        
        # Configuraciones vi mode
        silent_run(["tmux", "set-option", "-t", TMUX_SESSION_NAME, "mode-keys", "vi"])
        silent_run(["tmux", "set-option", "-t", TMUX_SESSION_NAME, "status-keys", "vi"])
        
    except subprocess.CalledProcessError:
        print("Error al crear la sesión tmux. Ejecutando directamente...")
        run_directly(args)
        return

    # Esperar a que la sesión aparezca
    for _ in range(20):
        time.sleep(0.1)
        if tmux_has_session():
            break

    # Adjuntarse a la sesión
    if tmux_has_session():
        try:
            os.execvp("tmux", ["tmux", "attach-session", "-t", TMUX_SESSION_NAME])
        except Exception as e:
            print(f"Error adjuntando a la sesión tmux: {e}")
            sys.exit(1)
    else:
        run_directly(args)

def attach_to_existing_session():
    """Adjunta al usuario a la sesión tmux existente."""
    try:
        os.execvp("tmux", ["tmux", "attach-session", "-t", TMUX_SESSION_NAME])
    except Exception as e:
        print(f"Error al intentar adjuntar a la sesión tmux: {e}")
        return False

def main():
    args = sys.argv[1:]

    # --kill solo mata la sesión
    if "--kill" in args or "-kill" in args:
        if check_tmux_installed() and tmux_has_session():
            kill_tmux_session()
            print(f"Sesión tmux '{TMUX_SESSION_NAME}' terminada.")
        else:
            print("No hay sesión tmux activa para matar.")
        sys.exit(0)

    # Si piden ayuda (-h o --help) ejecutar en consola actual
    if "-h" in args or "--help" in args:
        run_directly(args)
        return

    # Si no hay tmux → ejecutar directo con animación
    if not check_tmux_installed():
        run_directly(args)
        return

    # Si existe sesión previa -> intentar recuperar/adjuntar
    if tmux_has_session():
        current = get_current_tmux_session()
        if current == TMUX_SESSION_NAME:
            print(f"Ya estás en la sesión tmux activa: '{TMUX_SESSION_NAME}'.")
            print("No se iniciará otra instancia.")
            sys.exit(0)
        else:
            print(f"Sesión '{TMUX_SESSION_NAME}' detectada. Recuperando...")
            try:
                os.execvp("tmux", ["tmux", "attach-session", "-t", TMUX_SESSION_NAME])
            except Exception as e:
                print(f"Error adjuntando a sesión existente: {e}")
                print("Recreando sesión...")
                kill_tmux_session()
                time.sleep(0.5)
                create_tmux_session(args)
            return

    # No existe sesión: crear nueva y adjuntar
    create_tmux_session(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido por usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"Error inesperado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
