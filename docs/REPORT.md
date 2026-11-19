# SecureAlloc: A Secure Client–Server Resource Allocation System with Deadlock Detection

**Computer Networks Lab (24B11CS313), Semester 5, Jaypee Institute of Information Technology**
Team: Ishita Arora (2401030253), Priyani Rajvanshi (2401030256), Kartik Marwari (2401030279)
Submitted to: Mrs. Kirti Aggarwal, Mrs. Meenal Jain

---

## 1. Problem statement

Many distributed systems keep a central server that hands out limited shared resources (files, printers, licences, bandwidth slots) to remote clients. Two problems appear:

1. **Security.** Messages between client and server can be read (eavesdropping), changed (tampering), copied and sent again (replay), or forged by someone pretending to be a client or the server (spoofing, man-in-the-middle).
2. **Deadlock.** Clients that hold one resource while waiting for another can block each other forever.

SecureAlloc solves both in one C program written with Berkeley sockets and OpenSSL.

## 2. What was built

| | |
|---|---|
| Language / platform | C11, GCC, GNU Make, Linux (also runs under MSYS2/Cygwin) |
| Transport | **TCP** port 5000 for requests, **UDP** port 5001 for heartbeat and status |
| Concurrency | one `pthread` per client, one UDP/timeout thread, one admin-console thread |
| Key exchange | Diffie-Hellman, 2048-bit MODP group (RFC 3526), generator 2 |
| Authentication | RSA-2048 signatures (SHA-256) in both directions |
| Encryption + integrity | AES-256-GCM, random 96-bit IV per packet, 128-bit tag |
| Replay protection | strictly increasing 32-bit sequence number per direction |
| Deadlock handling | wait-for graph, DFS cycle detection, victim selection, roll-back, notification |
| Analysis | Wireshark/tcpdump captures, built-in sniffer and wire demo, NS2 simulation with awk post-processing |
| Size | about 1 600 lines of C in `src/`, about 2 400 lines including tests, tools and NS2 scripts; 3 unit-test programs (54 checks), 1 integration script (about 40 checks), 1 load tester |

## 3. Architecture

```
 Client application (menu, REQ / REL / STATUS, heartbeat sender)                      client.c
        |
 Security layer, client side: DH + RSA sign/verify (auth.c) -> AES-256-GCM (secure_channel.c)
        |
 ===== TCP 5000 (requests, encrypted)  |  UDP 5001 (heartbeat + status) =====   <- captured in Wireshark
        |                                                      <- modelled in NS2
 Server socket layer: listener, 1 thread / client, UDP thread, timeout monitor   server.c, protocol.c
        |
 Security layer, server side: RSA key pair, DH session keys, tag + replay check
        |
 Resource manager and deadlock detector: table, wait queue, wait-for graph, DFS   resource.c
```

### 3.1 Module ownership (as in the synopsis)

| Module | Content | Files | Owner |
|---|---|---|---|
| M1 Socket communication | multi-client TCP server with pthreads, TCP client, UDP heartbeat/status, timeouts, logging, configuration | `server.c`, `client.c`, `logger.c`, `config.c` | Ishita |
| M2 Application protocol and client | message types, length-prefixed framing, serialisation, menu client | `protocol.c`, `client.c` | Ishita |
| M3 Key exchange and authentication | DH, RSA key pairs, signing/verification of handshake, SHA-256 session key | `auth.c`, `crypto.c` | Priyani |
| M4 Encryption and integrity | AES-256-GCM per packet, random IV, tag, sequence numbers | `secure_channel.c`, `crypto.c` | Priyani |
| M5 Resource manager and deadlock detection | resource table, wait queue, wait-for graph, DFS, recovery | `resource.c` | Kartik |
| M6 Traffic analysis and performance | Wireshark captures, plain vs encrypted, NS2 model, awk, benchmark | `ns2/`, `tools/`, `scripts/` | Kartik |

### 3.2 Threads and locking

The server has one global mutex `g_lock`. It protects the client table and the resource table. Every request is handled completely inside the lock, including sending the reply. This has two advantages: the resource manager needs no locking of its own (so it can be tested alone), and the reply to a request can never overtake a notification caused by the same request. Each session also has its own `send_lock` so that the UDP thread, a client thread, and the resource manager can all write to one socket without mixing bytes.

## 4. Protocol design

### 4.1 Messages
`REQ` (request units of a resource), `GRANT`, `WAIT` (queued), `DENY`, `REL` (release), `STATUS` (query / information), `HB` (UDP heartbeat), `ERR`, and `HELLO` (plain mode only).

### 4.2 Packet format (TCP, after the handshake)

| Field | Size | Purpose |
|---|---|---|
| Type | 1 byte | message type |
| Sequence number | 4 bytes | increases for every packet; detects replay |
| Length | 2 bytes | length of the encrypted payload (framing on the TCP byte stream) |
| IV / nonce | 12 bytes | random per packet, so equal messages give different ciphertext |
| Payload | Length bytes | encrypted text such as `R1 1` |
| Tag | 16 bytes | GCM authentication tag |

The first 7 bytes (Type, Sequence number, Length) are sent in clear but are **additional authenticated data**: the tag covers them, so changing them makes the packet fail verification.

TCP delivers a byte stream, so `recv_all()` keeps reading until the 19-byte header and then exactly `Length + 16` bytes have arrived. The length field is checked against `MAX_PAYLOAD` before it is used (a hostile length cannot cause a large allocation or a buffer overflow).

### 4.3 Secure handshake

```
Client                                                    Server
  | -------- TCP connect (SYN, SYN-ACK, ACK) -----------> |
  | <-- g^a mod p , RSA_server(g^a) ---------------------- |  client verifies: "this is the real server"
  | --- g^b mod p , client ID , RSA_client(g^a|g^b|ID) --> |  server verifies: "this is the real client"
  |  shared secret = g^ab mod p (never sent)               |
  |  session key   = SHA-256(shared secret)                |
  | <-------- first AES-GCM packet: STATUS "WELCOME" ----- |  proves both keys are equal
```

*Why signatures:* plain Diffie-Hellman gives a shared secret but no identity. A man-in-the-middle could run one DH exchange with the client and another with the server. Because `g^a` is signed with the server's private key, and `g^a | g^b | ID` with the client's, he cannot substitute his own values without the signatures failing. The client's signature also contains `g^a`, so it cannot be reused in another session.

*Details:* the peer's DH value must lie strictly between 1 and p−1 (this rejects the small-subgroup values 0, 1, p−1). Each client has its own RSA key pair (`keys/C<n>_priv.pem`); the server accepts only IDs for which it has a public key. The client ID may only contain letters and digits (it becomes part of a file name, so `../` tricks are impossible). A handshake that does not finish within 10 seconds is dropped.

### 4.4 UDP: heartbeat and status
Each client sends `HB <id> <seq> <HMAC-SHA256(session key, "HB id seq")>` every 2 s. The server accepts it only if the MAC is right and the sequence number is new, so an outsider cannot keep a dead client alive or kill a live one. If no valid heartbeat arrives for 6 s, the server shuts the connection down; the client's thread then releases everything it held. Every 5 s the server sends each client a UDP status line with the resource table.

## 5. Resource manager and deadlock detection (M5)

**Data:** a table of resources (name, total, available, units held per client) and a FIFO wait queue (client, resource, units, arrival order). Each client has at most one waiting request.

**Request:** if enough units are free → `GRANT`. Otherwise the request is queued → `WAIT`, then deadlock detection runs.

**Wait-for graph:** one node per client; an edge `Ci → Cj` means *Ci waits for a resource that Cj holds*. It is rebuilt from the table whenever needed.

**Detection:** depth-first search with three colours (white = unvisited, grey = on the current path, black = finished). Meeting a grey node means a cycle; the path from that node is the deadlock cycle, for example `C1 → C2 → C1`.

**Recovery:** the victim is the client in the cycle with the *lowest priority* (priority = the number in the ID; C1 is the highest). The victim's waiting request is aborted and its held resources are released (roll back). The victim gets `DENY`, the other members get a `STATUS` notice, and the wait queue is served again. Detection repeats until no cycle remains, so several deadlocks are resolved in one go. The same procedure runs when a client disconnects or times out.

**Complexity:** building the graph is O(W · C) and DFS is O(C²) for W waiting requests and C clients (at most 32) — negligible.

**Limitation:** for resources with several units a cycle is only a *possible* deadlock (a unit might still be freed by a client outside the cycle). The system treats every cycle as a deadlock. With single-unit resources, as in the demo, a cycle is exactly a deadlock.

## 6. Threat model

| Threat | Attack example | Countermeasure | Verified by |
|---|---|---|---|
| Eavesdropping | read requests with a sniffer | AES-256-GCM on all payloads | TC4 (sniffer: text not visible), `wire_demo` |
| Man-in-the-middle | replace DH values | RSA signatures on both handshake messages | X1 (fake server detected), unit test "modified data fails verification" |
| Spoofing | claim another client's ID | RSA client authentication, per-client keys, duplicate-ID refusal | X2, X3, X4 |
| Tampering | flip bits in transit | GCM tag covers header and payload | TC5, protocol unit tests |
| Replay | resend an old valid packet | strictly increasing sequence numbers, per-session keys | TC6, protocol unit tests |
| Denial of service | client holds resources then vanishes; handshake never finished; connection flood | heartbeat timeout, 10 s handshake timeout, client limit | TC8, `max_clients` |

**Not covered (out of scope):** the server's private key is stored in a PEM file without a password; there is no key renewal during a long session; UDP status messages are not encrypted (they contain only public resource counts); there is no revocation of client keys; traffic analysis (message sizes and timing) is visible. SecureAlloc is a lab-scale system and does **not** replace TLS.

## 7. Testing and results

All tests are automated (`make check`, `make itest`). Full table: `docs/TEST_REPORT.md`.

| Group | Result |
|---|---|
| Unit tests (deadlock, crypto, protocol) | 54 / 54 passed |
| Integration tests TC1–TC8 and extra X1–X9 | all passed |
| NFR2 handshake time (20 clients at once, loopback) | average 52 ms, maximum 69 ms (limit 1 000 ms) |
| NFR2 request–response time | average 1.3 ms, maximum 4.5 ms (limit 50 ms) |
| NFR4 scalability | 20 simultaneous clients × 50 rounds, 0 errors, resource table consistent afterwards |

### 7.1 Plain versus encrypted traffic (TC4)
`tools/sniffer.py` (a small TCP proxy) and `tools/wire_demo` show what an eavesdropper sees. The request `REQ "R1 1"` in plain mode contains the bytes `52 31 20 31` — readable in the ASCII column. In secure mode the same message becomes `78 68 a9 4b` with a fresh random IV, and sending it again produces different bytes. With Wireshark the same can be seen on the loopback interface (`docs/WIRESHARK.md`), together with the TCP three-way handshake and our own handshake blobs.

An attack in plain mode: the `tamper` command changes `R3 1` to `S3 1`; the plain server accepts the modified request without noticing. In secure mode the same attack is rejected.

### 7.2 NS2 simulation (TC9)
`ns2/secure_alloc.tcl` models N clients (10 Mb/s, 2 ms links) → router → server over a 2 Mb/s, 10 ms bottleneck, one TCP/FTP flow per client. `ns2/analyze.awk` reads the trace and prints average delay, throughput and loss; `ns2/run_ns2.sh` runs N = 2, 5, 10, 20 and prepares `xgraph` files. Expected behaviour: throughput saturates at the 2 Mb/s bottleneck while delay and packet loss grow with N. The awk script was checked on a hand-made trace (`ns2/sample.tr`: delay 70 ms, loss 33.3 %, throughput 4.2 kb/s, equal to the hand calculation). Run `bash ns2/run_ns2.sh` on the lab machine with `ns-2.35` and paste the results table below.

| Clients | Delay (ms) | Throughput (kb/s) | Loss (%) |
|---|---|---|---|
| 2 | *(run NS2)* | | |
| 5 | | | |
| 10 | | | |
| 20 | | | |

## 8. Design decisions and why

| Decision | Reason |
|---|---|
| AES-**GCM** instead of AES-CBC + HMAC | encryption and the 16-byte integrity tag in one step; the synopsis' "integrity tag" field is the GCM tag; no padding-oracle risk |
| Header as additional authenticated data | an attacker cannot change the type or sequence number without breaking the tag |
| One mutex for all shared state | simple to reason about and to explain; performance is far above the requirement |
| Resource manager has no sockets or locks | it can be unit-tested alone and explained alone |
| Per-client RSA keys | spoofing of one client does not help against another; the server knows who is allowed |
| Plain mode (`--plain`) | needed for the Wireshark comparison required by the synopsis; clearly labelled insecure |
| Sequence numbers must only *increase* (gaps allowed) | a rejected (tampered) packet must not break the session; replays are still impossible |

## 9. Possible extensions
TLS-style certificates instead of raw RSA keys; forward secrecy with fresh ephemeral keys on rekeying; encrypting the UDP status; priorities set by the administrator instead of the ID; banker's-algorithm *avoidance* instead of detection; a graphical client; running over two real machines on a LAN with `tc netem` to compare with the NS2 curves.

## 10. References
1. J. F. Kurose, K. W. Ross, *Computer Networking: A Top-Down Approach*, 8th ed., Pearson, 2021.
2. A. S. Tanenbaum, N. Feamster, D. Wetherall, *Computer Networks*, 6th ed., Pearson, 2021.
3. W. R. Stevens, B. Fenner, A. M. Rudoff, *UNIX Network Programming, Vol. 1*, 3rd ed., Addison-Wesley, 2003.
4. W. Stallings, *Cryptography and Network Security*, 8th ed., Pearson, 2020.
5. W. Diffie, M. Hellman, "New Directions in Cryptography," *IEEE Trans. Information Theory*, 22(6), 1976.
6. R. Rivest, A. Shamir, L. Adleman, "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems," *CACM*, 21(2), 1978.
7. NIST FIPS 197, *Advanced Encryption Standard*, 2001; NIST SP 800-38D, *Galois/Counter Mode*, 2007.
8. T. Kivinen, M. Kojo, RFC 3526, *More MODP Diffie-Hellman groups for IKE*, 2003.
9. OpenSSL documentation, https://www.openssl.org/docs/ · Wireshark User's Guide, https://www.wireshark.org/docs/ · The Network Simulator ns-2, https://www.isi.edu/nsnam/ns/
