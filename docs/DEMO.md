# Demo script (about 10 minutes)

Open four terminals in the project folder. Build once: `make keys && make`.

## Part 0 – setup (1 min)
```bash
bash scripts/netcheck.sh          # ip, ping, ss, traceroute, nslookup as listed in the synopsis
./server --debug                  # terminal 1: server log appears here
```
Say: "The server listens on TCP 5000 and UDP 5001. Resources: R1 (1 unit), R2 (1 unit), R3 (3 units)."
In terminal 1 you can type `help`, `status`, `clients`, `stats`.

## Part 1 – secure connection (2 min)
```bash
./client 127.0.0.1 C1 --debug     # terminal 2
```
Show: "Connected as C1 – ENCRYPTED (AES-256-GCM)". The client prints `session-key fingerprint = ...` and the server prints **the same value** (TC3). Only a hash of the key is shown, never the key.
Type `req R3 2`, `status`, `rel R3 2`. Server log shows `[REQ]`, `[GRANT]`.

## Part 2 – deadlock (3 min)  *(Kartik – module M5)*
Terminal 2 = C1, terminal 3 = `./client 127.0.0.1 C2`.
1. C1: `req R1 1` → GRANT
2. C2: `req R2 1` → GRANT
3. C1: `req R2 1` → **WAIT** (C1 waits for C2)
4. C2: `req R1 1` → this closes the circle C1 → C2 → C1

Expected output:
```
server : [WARN] DEADLOCK cycle: C1 -> C2 -> C1 | victim: C2 (lowest priority)
C1     : << [STATUS] DEADLOCK detected (C1 -> C2 -> C1). Victim C2 was aborted; your request will be served.
C1     : << [GRANT] R2 x1 granted (you were waiting)
C2     : << [DENY] DEADLOCK detected (C1 -> C2 -> C1). Your request was aborted and your resources were released.
```
Explain: wait-for graph → DFS finds the cycle → lowest priority (C2) is aborted → its resources are released → C1 continues.
Type `status` on the server console to show who holds what.

## Part 3 – attacks (2 min)  *(Priyani – modules M3/M4)*
In a client: `req R3 1`, then
* `tamper` → server: `REJECTED packet from C1: integrity tag mismatch (packet modified)`; client: `<< [ERR] packet rejected by server`
* `replay` → server: `REJECTED packet ...: old sequence number 1 (replay)`
* `status` → session still works.

Optional (man-in-the-middle / spoofing, see `tests/run_tests.sh` X1, X2): a fake server with another RSA key → client prints `SERVER AUTHENTICATION FAILED`; a client with a wrong private key → server prints `RSA signature of 'C1' INVALID`.

## Part 4 – heartbeat (1 min)  *(Ishita – module M1)*
Client C3: `req R1 1`, then `mute` (stops heartbeats). After ~6 s the server prints `heartbeat timeout for C3`, then `client C3 disconnected - releasing its resources`. R1 can be requested again by another client.
`./client 127.0.0.1 C4 --udp-log` shows the UDP status line every 5 s.

## Part 5 – Wireshark / NS2 (2 min)  *(Kartik – module M6)*
`./wire_demo` (instant, no Wireshark needed) or the `.pcap` steps in `docs/WIRESHARK.md`.
`bash ns2/run_ns2.sh` → delay, throughput and loss for 2, 5, 10, 20 clients; `xgraph delay.xg`.

## Part 6 – numbers (1 min)
```bash
./bench 127.0.0.1 20 50
```
`handshake avg 52 ms (limit 1000)`, `round trip avg 1.3 ms (limit 50)`, 20 clients, 0 errors.

## Everything automatically
```bash
make check        # 54 unit-test checks, no server needed
make itest        # starts servers by itself, runs TC1-TC9 + attacks + load test
```
