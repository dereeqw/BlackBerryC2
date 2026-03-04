# BlackBerryC2

BlackBerryC2 is an **encrypted remote administration and C2 framework** designed **exclusively for educational use, security research, and controlled laboratory environments**.

The project demonstrates how to build a **custom command-and-control server** with **application-layer cryptography**, session management, and secure client communication **without relying on external TLS stacks**.

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

**Architecture Compatibility:** aarch64, x86_64, armv7l

**Python dependencies:**
```
pip install cryptography prompt_toolkit zstandard
```

> `zstandard` is optional but recommended for transfers larger than 1 GB.

---

## Key Features

- Custom TCP-based encrypted C2 server (v2.0)
- ECDHE (secp256r1) key exchange — ephemeral or persistent
- AES-256-GCM authenticated encryption per session
- HMAC-SHA256 per-packet authentication + anti-replay sequence numbers
- Multiple concurrent client sessions
- Interactive operator console with tab-completion (prompt_toolkit)
- Encrypted remote command execution
- Encrypted file transfers with zlib / Zstandard compression
- Recursive directory upload/download (`get -r`, `put -r`)
- Background transfers (`-b` flag) — non-blocking, cancellable
- Transfer resume support (`.partial` + `.resume` files)
- Client payload generator (`generate-payload`)
- IP blocking: persistent blocklist + temporary auto-bans
- Scan/flood detection: connect scan, banner grab, handshake failures, heartbeat flood
- Optional HTTP(S)/TLS proxy support (`BlackBerryHTTPs_TLSProxyDaemon`)
- SPA (Single Packet Authorization) and Port-Knocking pre-auth
- **BerryTransfer mode** — dedicated file-transfer-only server (no shell)
- Encrypted session log (AES-256-GCM + PBKDF2, 600k iterations)
- Encrypted server log with in-shell viewer (`log` command)
- Startup config saved to `logs/last_start.json`

---

## Cryptographic Design

BlackBerryC2 v2.0 establishes secure communication as follows:

1. Client connects via TCP; server sends service banner.
2. Client sends `REQUEST_PUBKEY`.
3. Server sends its ephemeral ECDHE public key (`secp256r1`).
4. Client sends its ECDHE public key + HMAC-SHA256 authentication tag.
5. Server verifies the HMAC against the pre-shared secret (`HMAC_PRE_SHARED_SECRET`).
6. Both sides derive a 256-bit AES session key via **HKDF-SHA256** over the shared secret.
7. All further communication uses **AES-256-GCM** with per-packet **HMAC-SHA256** and anti-replay sequence numbers.

Each session maintains:
- Its own AES-256 key and HMAC key
- Independent nonces (12-byte random per message)
- Isolated anti-replay tracker (sequence window ±100)
- Flood protection rate limiter (configurable commands/second)

All cryptographic keys are generated **at runtime** and never reused across restarts (unless `--persistente` is set).

---

## Running the Server

```bash
python3 BlackBerryC2_server.py
```

Default configuration:
- Host: `0.0.0.0`
- Port: `9949`

---

## Command-Line Arguments

| Flag | Description |
|------|-------------|
| `-p` / `--persistente` | Use persistent ECDHE keys from `ecdhe-cert/` (prompts for passphrase) |
| `-v` | Debug logging |
| `-vv` | Verbose (relaxed) logging |
| `-H <host>` | Listening host (default: `0.0.0.0`) |
| `-P <port>` | Listening port (default: `9949`) |
| `--no-secure` | Accept any ECDHE client without HMAC verification |
| `--hmac <secret>` | Custom HMAC pre-shared secret (hex or string) |
| `--log-passphrase <pass>` | Encrypt server log with AES-256-GCM (PBKDF2 600k iter) |
| `--logs` | Interactive log viewer — no server started |
| `--spa` | Enable SPA/port-knocking pre-authentication |
| `--spa-mode <spa\|knock>` | `spa` = single UDP token, `knock` = port sequence |
| `--spa-port <port>` | UDP port for SPA listener (default: `7331`) |
| `--knock-seq <ports>` | Port sequence for knock mode (default: `7001,7002,7003`) |
| `--knock-timeout <sec>` | Seconds to complete knock sequence (default: `10`) |
| `--spa-ttl <sec>` | Seconds an authorized IP remains valid (default: `60`) |
| `--berrytransfer` | BerryTransfer mode: file-transfer-only, no shell |
| `--transfer-root <dir>` | Root directory for BerryTransfer (default: `./berry_transfers`) |
| `--auto-confirm` | Auto-approve all GET requests in BerryTransfer (no operator prompt) |

**Examples:**
```bash
# Basic startup (prompts for log passphrase)
python3 BlackBerryC2_server.py

# Persistent ECDHE keys + verbose
python3 BlackBerryC2_server.py -p -vv

# Custom port, no HMAC check
python3 BlackBerryC2_server.py -P 8080 --no-secure

# Port-knocking on custom ports
python3 BlackBerryC2_server.py --spa --spa-mode knock --knock-seq 9001,9002,9003

# BerryTransfer mode with auto-confirm
python3 BlackBerryC2_server.py --berrytransfer --auto-confirm

# View/decrypt logs without starting server
python3 BlackBerryC2_server.py --logs
```

---

## Operator Console Commands

### Server Management

| Command | Description |
|---------|-------------|
| `list` | List active sessions with stats and hostname |
| `select <ID>` | Interact with a client session |
| `all <cmd>` | Send a command to all connected clients |
| `report` | Full server status report (uptime, sessions, transfers) |
| `set host <HOST>` | Change listening host (rebinds server) |
| `set port <PORT>` | Change listening port (rebinds server) |
| `sVbanner "<text>"` | Change service banner |
| `generate-payload` | Generate a client payload |
| `fingerprint` | Show ECDHE server key fingerprint (SHA-256) |
| `ecdhe-keys` | Print current ECDHE key pair (PEM) |
| `kill <id\|ip>` | Terminate a session by ID or IP |
| `block <IP>` | Permanently block an IP |
| `unblock <IP>` | Unblock an IP (persistent + temporary) |
| `blocklist` | Show blocked IPs (persistent and temporary) |
| `log` | Interactive log viewer (supports encrypted logs) |
| `report` | Status summary: uptime, sessions, transfers |
| `banner` | Redisplay startup banner |
| `clean` | Delete server log files |
| `v` | Toggle DEBUG logging |
| `vv` | Toggle VERBOSE logging |
| `cd <dir>` | Change server local working directory |
| `E <cmd>` | Execute command via `os.system` locally |
| `<any command>` | Execute locally on the server |
| `exit` | Stop server and exit |

### Proxy

| Command | Description |
|---------|-------------|
| `proxy` | Start TLS/HTTP proxy daemon (auto mode) |
| `proxy --mode <mode>` | Modes: `auto`, `tls`, `http`, `https`, `both`, `all` |
| `proxy --stats` | Show proxy statistics |
| `proxy gui` | Launch proxy GUI (separate process) |
| `stop-proxy` | Stop proxy daemon |
| `stop-proxy-gui` | Stop proxy GUI |
| `proxy-help` | Full proxy help |

---

## Session Commands (inside `select <ID>`)

### General

| Command | Description |
|---------|-------------|
| `help` | Show session help |
| `exit` | Return to main shell |
| `!<cmd>` | Execute command **locally on the server** |
| `<cmd>` | Execute command on the remote client |
| `cmd1 && cmd2` | Chain: run `cmd2` only if `cmd1` succeeded |
| `cmd1 \|\| cmd2` | Chain: run `cmd2` only if `cmd1` failed |
| `cmd1 ; cmd2` | Chain: always run `cmd2` |

### File Transfer

| Command | Description |
|---------|-------------|
| `get <file>` | Download file from client |
| `get <dir> -r` | Recursive directory download |
| `get <file> -b` | Background download (non-blocking) |
| `get <dir> -r -b` | Background recursive download |
| `put <file>` | Upload file to client |
| `put <file> -exc` | Upload and execute in memory (scripts) |
| `put <dir> -r` | Recursive directory upload |
| `put <file> -b` | Background upload |
| `transfers` | List all active and completed transfers |
| `stop <ID>` | Cancel a background transfer (e.g. `stop T1`) |
| `resume <local_file>` | Resume an interrupted download |
| `screenshot` | Capture client screen |

---

## BerryTransfer Mode

BerryTransfer is a dedicated **file-transfer-only** server mode inspired by `scp`. When active, the server rejects all shell access and only accepts `BT:*` protocol commands.

**Start:**
```bash
python3 BlackBerryC2_server.py --berrytransfer
python3 BlackBerryC2_server.py --berrytransfer --auto-confirm  # no operator prompt for GETs
```

**BerryTransfer shell commands:**

| Command | Description |
|---------|-------------|
| `confirm <ID>` | Approve a pending GET request |
| `deny <ID>` | Reject a pending GET request |
| `pending` | List GET requests awaiting approval |
| `auto [on\|off]` | Toggle/set auto-confirm |
| `clients` | Show active BerryTransfer sessions |
| `ls [dir]` | List files in transfer root |
| `tree [dir]` | File tree of transfer root |
| `find <name>` | Search file in transfer root |
| `rm <file>` | Delete file from transfer root (with confirmation) |
| `log [N]` | Show last N transfer log entries (default 30) |
| `cd <dir>` | Change local working directory |
| `pwd` | Show current local directory |
| `!<cmd>` | Execute local system command |
| `exit` | Stop BerryTransfer server |

Transfer log is written to `logs/bt_transfer.jsonl` (optionally AES-256-GCM encrypted).

---

## SPA / Port-Knocking

When `--spa` is active, clients must authenticate via UDP before the TCP connection is accepted.

**SPA mode** (default): Client sends a 32-byte HMAC-SHA256 token to `SPA_UDP_PORT`.
```
token = HMAC-SHA256(HMAC_SECRET, "{ip}:{time_window_30s}")
```

**Knock mode**: Client knocks a sequence of UDP ports in order within a timeout window.
```bash
python3 BlackBerryC2_server.py --spa --spa-mode knock --knock-seq 7001,7002,7003 --knock-timeout 10
```

Authorized IPs are valid for `--spa-ttl` seconds (default 60).

---

## Security Features

| Feature | Details |
|---------|---------|
| Key exchange | ECDHE secp256r1 ephemeral or persistent |
| Session encryption | AES-256-GCM, random 12-byte nonce per message |
| Client authentication | HMAC-SHA256 over shared secret during handshake |
| Message integrity | HMAC-SHA256 per-packet (covers seq + nonce + ciphertext) |
| Anti-replay | Sequence number window tracker per session |
| Downgrade protection | Minimum AES key size enforced (256-bit) |
| Heartbeat rate limiting | Min 3s between heartbeats; violations tracked |
| Command flood protection | Rate limiter; auto-disconnect after threshold |
| Scan detection | Connect scan, banner grab, handshake failure counters |
| IP management | Persistent blocklist + temporary bans (auto + manual) |
| Log encryption | AES-256-GCM + PBKDF2-HMAC-SHA256 (600k iterations) |
| Response jitter | 10–50ms random jitter to resist timing attacks |
| Pre-auth | SPA token or port-knocking before TCP is accepted |

---

## Logging

| Log file | Contents |
|----------|----------|
| `logs/BlackBerryC2_Server.log` | Plaintext rotating server log (INFO+) |
| `logs/BlackBerryC2_enc.log` | Encrypted server log (if `--log-passphrase` set) |
| `logs/sessions.jsonl` | Session events: connect, disconnect, bytes |
| `logs/bt_transfer.jsonl` | BerryTransfer file transfer log |
| `logs/last_start.json` | Startup config snapshot (host, port, token, pid) |

View logs with the built-in viewer:
```
BlackBerry> log
```
Or standalone (no server):
```bash
python3 BlackBerryC2_server.py --logs
```

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

See [LICENSE](LICENSE) file for full license details.

---

## Disclaimer

This software is provided **"as is"**, without warranty of any kind.  
The authors assume **no responsibility** for misuse or damage caused by this software.
