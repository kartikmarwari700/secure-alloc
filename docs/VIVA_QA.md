# Viva questions and answers

## General
**Q. What does your project do, in two lines?**
Clients connect to a central server over TCP and ask for shared resources (R1, R2, R3). Everything between them is encrypted and authenticated (Diffie-Hellman + RSA + AES-256), and the server detects and fixes deadlocks between clients.

**Q. Why TCP for requests and UDP for heartbeat?**
Requests must arrive completely and in order (TCP gives that). A heartbeat is tiny and sent again every 2 s, so losing one is harmless, and UDP has no connection set-up cost. UDP also lets the server hear that a client is alive without keeping the TCP stream busy.

**Q. Why one thread per client?**
Simple to understand: each thread blocks in `recv()` for its own client. For a lab-scale system (≤ 32 clients) it is perfectly fine; for thousands of clients we would use `epoll`.

**Q. How do you handle two threads using the resource table at the same time?**
One mutex `g_lock` protects the client table and the resource table. Every request is processed fully inside the lock.

**Q. What is TCP framing and why do you need it?**
TCP is a byte stream — one `send()` of 40 bytes can arrive as two `recv()`s of 20 bytes, or two messages can arrive glued together. So every packet has a length field and `recv_all()` loops until exactly that many bytes are read.

## Cryptography (Priyani)
**Q. Explain Diffie-Hellman.**
Both sides agree on public numbers *p* (a big prime) and *g* = 2. The server picks secret *a* and sends *g^a mod p*; the client picks secret *b* and sends *g^b mod p*. Each side raises the other's value to its own secret: both get *g^(ab) mod p*. An eavesdropper sees *g^a* and *g^b* but cannot compute *g^(ab)* (discrete-logarithm problem). Our prime is the 2048-bit group from RFC 3526.

**Q. DH alone is not enough — why do you add RSA?**
DH does not tell you *who* you are talking to. A man-in-the-middle can do DH with the client and another DH with the server and relay everything. We sign *g^a* with the server's RSA private key (the client checks it with the server's public key) and sign *g^a | g^b | ID* with the client's key. The attacker cannot forge those signatures.

**Q. Why do you hash the shared secret with SHA-256?**
The DH result is a 2048-bit number with mathematical structure. SHA-256 turns it into a uniformly looking 256-bit key — exactly the size AES-256 needs.

**Q. Which AES mode and why GCM?**
GCM: it encrypts and also produces a 16-byte authentication tag, so one operation gives confidentiality and integrity. With plain CBC we would need a separate HMAC and padding. We also put the header (type, sequence number, length) into the tag as *additional authenticated data*.

**Q. What is the IV and why random?**
A 12-byte nonce used once per packet. With GCM the same key + same IV must never be used twice; we draw a fresh random IV for every packet, so the same message gives different ciphertext each time (shown in `./wire_demo`).

**Q. How do you stop a replay attack?**
Each packet carries a sequence number that must be larger than the last accepted one. A replayed packet has an old number and is rejected (`./client` command `replay`). The tag cannot be recomputed by an attacker, so he cannot just change the number.

**Q. What happens when a packet is tampered?**
The tag check fails, the packet is dropped, the event is logged as SECURITY and counted in the statistics. The session continues (command `tamper`).

**Q. Is keeping the sequence check *after* the tag check important?**
Yes. Otherwise an attacker could use fake packets with big sequence numbers to push the counter forward and lock out the real client. We only update the counter after the tag was verified.

**Q. What if the server's private key is stolen?**
Then an attacker can impersonate the server. This is a limitation of the lab design (key in a file, no revocation). Real systems use certificates, hardware security modules and short-lived keys.

**Q. Do you have forward secrecy?**
Yes for the session key: the DH secrets *a* and *b* are random per session and deleted afterwards, so stealing the RSA keys later does not reveal old sessions. RSA is only used for signing, not for encrypting the key.

**Q. Why not just use TLS?**
TLS is the right choice in production. The lab asks us to *build* the mechanisms (key exchange, authentication, encryption, integrity) to understand them; SecureAlloc is a small TLS-like protocol.

## Deadlock (Kartik)
**Q. Define deadlock. What are the four necessary conditions?**
A set of processes waiting for each other forever. Conditions: mutual exclusion, hold and wait, no pre-emption, circular wait. We break "no pre-emption" when recovering (the victim's resources are taken back).

**Q. What is a wait-for graph?**
Nodes are clients; an edge C1 → C2 means "C1 waits for a resource that C2 holds". A cycle means deadlock.

**Q. How do you find the cycle?**
Depth-first search with three colours. White = not visited, grey = on the current DFS path, black = finished. If DFS reaches a grey node, we found a cycle; the path from that node is printed (e.g. `C1 -> C2 -> C1`). See `dfs()` in `resource.c`.

**Q. Who is the victim and why?**
The client with the lowest priority in the cycle (highest number in the ID, so C2 loses against C1). Its waiting request is aborted and its resources are released, then the waiting queue is served again.

**Q. Detection vs prevention vs avoidance?**
Prevention removes one of the four conditions, avoidance (banker's algorithm) needs to know maximum demands in advance. Detection + recovery lets everything run and fixes the problem when it appears — simplest for clients who ask for resources one by one.

**Q. Is a cycle always a deadlock?**
For single-unit resources, yes. For multi-unit resources a cycle is only a possible deadlock; we conservatively treat it as one. (This is stated as a limitation.)

**Q. What if a client dies while holding a resource?**
Two ways: the TCP connection closes (immediately detected), or the client freezes — then its UDP heartbeats stop and after 6 s the server drops it. In both cases `rm_remove_client()` releases its units and wakes up waiters (test TC8).

## Network analysis
**Q. What do you see in Wireshark?**
The TCP three-way handshake; our handshake messages (public DH values and signatures, no secrets); then encrypted data packets — only the 7-byte header is readable. In plain mode the text `R1 1` is readable. UDP heartbeats with an HMAC every 2 s.

**Q. What do you measure in NS2 and what do you expect?**
Throughput, end-to-end delay and packet loss for 2, 5, 10, 20 clients sharing a 2 Mb/s link. Throughput stays near the link capacity; delay and loss increase with more clients (queue at the router fills up).

**Q. Did you measure the real performance?**
Yes, `./bench 127.0.0.1 20 50`: handshake about 50 ms, request-response about 1.3 ms with 20 clients at the same time (requirements: < 1 s and < 50 ms).

**Q. What is the cost of encryption?**
AES-GCM is hardware-accelerated (AES-NI); encrypting 40-byte packets takes microseconds. The bigger cost is the handshake (2048-bit modular exponentiation and RSA), done once per session.

## Tricky ones
**Q. Why does an RSA signature of 2048 bits not become a problem for the 2-byte blob length?**
The length field allows 65 535 bytes; our biggest handshake item is 256 bytes. The receiver also checks the length against its buffer size before reading.

**Q. What stops someone from using `../../etc/passwd` as client ID?**
`valid_client_id()` allows only 1–8 letters or digits, because the ID becomes part of the file name `keys/<id>_pub.pem`.

**Q. What happens if the same client ID connects twice?**
The second connection is refused and logged as a possible spoofing attempt (test X3).

**Q. Which part is *not* secure?**
UDP status messages are not encrypted (only public counts); the heartbeat is authenticated but not secret; private keys have no password; message sizes and timing are visible.
