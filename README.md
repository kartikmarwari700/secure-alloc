# SecureAlloc
### A Secure Client–Server Resource Allocation System with Deadlock Detection

Computer Networks Lab (24B11CS313) · Semester 5 · Jaypee Institute of Information Technology
Ishita Arora · Priyani Rajvanshi · Kartik Marwari

Clients connect to a central server and request shared resources. The channel is protected with **Diffie-Hellman key exchange, RSA authentication and AES-256-GCM encryption** (with sequence numbers against replay). The server keeps a **wait-for graph**, finds **deadlocks** with DFS, and recovers automatically. A **UDP** channel carries heartbeats and status. Traffic is analysed in **Wireshark** and the topology is modelled in **NS2**.

## Quick start (Linux; also works in MSYS2/Cygwin)
```bash
sudo apt install build-essential libssl-dev     # once
make keys            # RSA key pairs for the server and clients C1..C20  (keys/)
make                 # builds server, client, bench, wire_demo and the test programs
make check           # unit tests (54 checks, no server needed)
make itest           # integration tests TC1-TC9 + attacks + load test (starts its own servers)
```
Run it (from the project folder):
```bash
./server --debug                 # terminal 1      (type help / status / clients / stats / quit)
./client 127.0.0.1 C1            # terminal 2
./client 127.0.0.1 C2            # terminal 3
```
Client commands: `req R1 1` · `rel R1 1` · `status` · `tamper` · `replay` · `mute` · `menu` · `quit`
Resources (editable in `secure_alloc.conf`): R1 = 1 unit, R2 = 1 unit, R3 = 3 units.

## Easiest way to show it
**Windows:** double-click `START_DEMO.bat`. **Linux:** `bash scripts/demo.sh`. It runs the whole demo by itself (secure connection, deadlock, attacks, heartbeat, plain vs encrypted, performance) and explains each step; press Enter for the next step.

## Project layout
```
src/
  server.c          M1  multi-client TCP server (1 pthread/client), UDP heartbeat + status, timeouts, admin console
  client.c          M1/M2  menu-driven client, heartbeat sender
  protocol.c        M2  message types, send_all / recv_all, length-prefixed framing
  auth.c            M3  Diffie-Hellman + RSA signed handshake, session key = SHA-256(secret)
  crypto.c          M3/M4  OpenSSL wrappers: DH, RSA, SHA-256, AES-256-GCM, HMAC
  secure_channel.c  M4  packet format, random IV, integrity tag, sequence numbers, tamper/replay detection
  resource.c        M5  resource table, wait queue, wait-for graph, DFS cycle detection, recovery
  logger.c config.c     event log (screen + logs/server.log), settings file
tests/   test_deadlock.c  test_crypto.c  test_protocol.c  run_tests.sh (TC1-TC9, X1-X9, NFR)
tools/   bench.c (load + timing)  wire_demo.c (plain vs encrypted bytes)  sniffer.py (mini Wireshark)
ns2/     secure_alloc.tcl  analyze.awk  run_ns2.sh  (M6: NS2 model and trace analysis)
scripts/ capture.sh (tcpdump)  netcheck.sh (ip, ping, ss, traceroute, nslookup)
docs/    REPORT.md  DEMO.md  WIRESHARK.md  VIVA_QA.md  TEST_REPORT.md
```

| Module | Owner | Files |
|---|---|---|
| M1 Socket communication layer | Ishita | `server.c`, `client.c`, `logger.c`, `config.c` |
| M2 Application protocol and client | Ishita | `protocol.c`, `client.c` |
| M3 Key exchange and authentication | Priyani | `auth.c`, `crypto.c` |
| M4 Encryption and integrity layer | Priyani | `secure_channel.c`, `crypto.c` |
| M5 Resource manager and deadlock detection | Kartik | `resource.c` |
| M6 Traffic analysis and performance evaluation | Kartik | `ns2/`, `tools/`, `scripts/` |

## How it works (short)
1. **Handshake:** server sends `g^a mod p` signed with RSA; client verifies, replies `g^b mod p` + ID signed with its RSA key; both compute `g^ab mod p`; session key = SHA-256 of it.
2. **Every packet:** `Type(1) | Seq(4) | Len(2) | IV(12) | encrypted payload | Tag(16)`. Tag covers the header and payload; sequence number must increase.
3. **Resource manager:** `REQ` → `GRANT` or `WAIT`. Each new wait runs DFS on the wait-for graph. A cycle (e.g. `C1 -> C2 -> C1`) is a deadlock: the lowest-priority client is the victim — its request is aborted, its resources are released, everybody is notified.
4. **UDP:** heartbeat every 2 s (HMAC-protected); silent for 6 s → connection dropped, resources freed. Status broadcast every 5 s.

## Results (loopback, 20 clients at the same time, 50 rounds each)
| Requirement | Measured |
|---|---|
| NFR2 handshake < 1 s | avg 52 ms, max 69 ms |
| NFR2 request–response < 50 ms | avg 1.3 ms, max 4.5 ms |
| NFR4 ≥ 20 clients without errors | 20 clients, 0 errors, resource table consistent |
| Security | tampered, replayed, forged-signature, fake-server and duplicate-ID cases all rejected (see `docs/TEST_REPORT.md`) |

## Documents
`docs/REPORT.md` full project report · `docs/DEMO.md` step-by-step demo for the presentation · `docs/WIRESHARK.md` capture guide · `docs/VIVA_QA.md` expected questions with answers · `docs/TEST_REPORT.md` test cases and results.

## Limits
Lab-scale system, not a replacement for TLS. Multi-unit resources: a cycle is treated as a deadlock (exact for single-unit resources). Private keys are not password-protected. UDP status text is not encrypted.
