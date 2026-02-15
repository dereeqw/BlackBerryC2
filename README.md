# BlackBerryC2

BlackBerryC2 is an **encrypted remote administration and C2 framework** designed **exclusively for educational use, security research, and controlled laboratory environments**.

The project demonstrates how to build a **custom command-and-control server** with **application-layer cryptography**, session management, and secure client communication **without relying on external TLS stacks**.

The server component is distributed as a **precompiled binary** to ensure consistency, protect core logic, and avoid accidental modification.  
Client payloads are generated and managed by the server.

---

## ⚠️ Important Notice

This project is **NOT malware** and **NOT intended for unauthorized access**.

BlackBerryC2:
- Does **not** self-propagate
- Does **not** exploit vulnerabilities automatically
- Does **not** include persistence mechanisms
- Does **not** attempt to evade antivirus software

Use **only on systems and networks you own or have explicit authorization to test**.

---

## System Requirements

**Architecture Compatibility:**

The binaries aarch64, x86_64 and armv7l are distributed as a ZIP archive.

➡️ Download the appropriate binary from the official release page:
https://github.com/dereeqw/BlackBerryC2/releases/tag/v1.7

Unsupported architectures include: i386, and macOS.

---

## Key Features

- Custom TCP-based encrypted C2 server
- Application-level cryptographic handshake
- RSA-based key exchange
- AES-GCM authenticated encryption per session
- Multiple concurrent client sessions
- Interactive operator console
- Encrypted remote command execution
- Encrypted file transfers
- Client payload generator
- IP blocking and access control
- Persistent logging and audit support
- Optional HTTP(s)/TLS proxy support

---

## Cryptographic Design

BlackBerryC2 establishes secure communication as follows:

1. Client connects to the server via TCP.
2. Server sends an identification banner.
3. Client responds with a predefined handshake token.
4. Server sends its RSA public key.
5. Client generates a random AES session key.
6. AES key is encrypted using RSA-OAEP and sent to the server.
7. Server decrypts the AES key using its private RSA key.
8. All further communication uses **AES-GCM authenticated encryption**.

Each client session maintains:
- Its own AES key
- Independent nonces
- Isolated encryption context

All cryptographic keys are generated **at runtime** and are never reused across restarts.

---

## Server Distribution

The server is provided as a **single standalone executable**:

- No Python installation required
- No external dependencies at runtime
- All components bundled into one file
- Temporary runtime data extracted in memory

This design is intentional and suitable for:
- Cybersecurity labs
- Red team simulations
- Research and training environments

---

## Running the Server

```bash
chmod +x BlackBerryC2Server
./BlackBerryC2Server
```

Default configuration:
- Host: `0.0.0.0`
- Port: `9949`

---

## Operator Console Commands

```
BlackBerry - Herramienta de administración remota RSA-OAEP_AES-GCM v1.5

Comandos del Servidor:
  list                   -> Lista conexiones activas con estadísticas.
  select <ID>            -> Interactúa con una sesión de cliente.
  set host <HOST>        -> Cambia el host de escucha.
  set port <PUERTO>      -> Cambia el puerto de escucha.
  sVbanner "<BANNER>"    -> Cambia el banner del servicio.
  generate-payload       -> Genera un payload de cliente.
  fingerprint            -> Muestra el fingerprint RSA del servidor.
  proxy-tls              -> Inicia el proxy TLS.
  proxy-tls-gui          -> Inicia el proxy TLS en modo gráfico.
  log                    -> Imprime el log del servidor.
  rsa-keys               -> Imprime las claves RSA generadas.
  cert                   -> Info del certificado del proxy.
  new-cert               -> Crea nuevo certificado personalizado.
  block <IP>             -> Bloquea IP permanentemente.
  unblock <IP>           -> Desbloquea una IP.
  blocklist              -> Muestra IPs bloqueadas.
  clean                  -> Limpia archivos de log.
  E <comando>            -> Ejecuta comando con os.system.
  exit                  -> Salir y cerrar el servidor.
```

---

## Client Payloads

Client payloads are generated directly by the server using the `generate-payload` command.

Payloads are intended for:
- Controlled deployment
- Testing encrypted channels
- Demonstrating secure remote administration concepts

Clients are **not persistent** and **do not self-install**.

---

## Logging

Server logs are written to:

```
BlackBerryC2Server.log
```

Logs are intended for:
- Debugging
- Auditing
- Training analysis

---

## Intended Use

This project is intended **only for**:

- Educational demonstrations
- Security research
- Controlled lab environments
- Authorized penetration testing

Unauthorized use against systems without permission is strictly prohibited.

---

## License

See [LICENSE](LICENCE) file for full license details.

---

## Disclaimer

This software is provided **"as is"**, without warranty of any kind.  
The authors assume **no responsibility** for misuse or damage caused by this software.
