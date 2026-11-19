# Wireshark guide (module M6, test case TC4)

Goal: show that in **plain mode** an eavesdropper can read every request, and in **secure mode** he sees only ciphertext. Also show the TCP three-way handshake.

## 0. No Wireshark at hand? Two built-in alternatives
```bash
./wire_demo                     # prints the same request as plain packet and as encrypted packet (hex + ASCII)
python3 tools/sniffer.py --listen 5200 --server 127.0.0.1:5000 --grep "R3 1" --seconds 20
./client 127.0.0.1 C1 --tcp-port 5200     # (in another terminal) client talks THROUGH the sniffer
```
The sniffer prints every packet like Wireshark's "bytes" pane and finally says whether your text was visible.

## 1. Capture with tcpdump / Wireshark
Everything runs on one machine, so capture on the loopback interface `lo`.

**A. Secure mode**
```bash
sudo bash scripts/capture.sh secure        # terminal 1 (Ctrl+C when done) -> captures/secure.pcap
./server                                   # terminal 2
./client 127.0.0.1 C1                      # terminal 3:  req R1 1 , status , rel R1 1 , quit
```
**B. Plain mode**
```bash
sudo bash scripts/capture.sh plain         # -> captures/plain.pcap
./server --plain
./client 127.0.0.1 C1 --plain
```
(Or start Wireshark directly: choose interface **Loopback: lo**, capture filter `tcp port 5000 or udp port 5001`.)

## 2. What to show (open the `.pcap` in Wireshark)

| Step | Wireshark action | What you see | What it proves |
|---|---|---|---|
| 1 | filter `tcp.port == 5000` | first three packets `[SYN]`, `[SYN, ACK]`, `[ACK]` | TCP three-way handshake |
| 2 | secure.pcap: packets 4–7 | two blobs from the server (256-byte `g^a`, 256-byte RSA signature) and three from the client (`g^b`, ID `C1`, signature) | Diffie-Hellman + RSA handshake; **no key is ever sent**, only public values |
| 3 | secure.pcap: right click a data packet → *Follow → TCP Stream* | unreadable bytes | AES-256-GCM encryption (NFR1) |
| 4 | plain.pcap: *Follow → TCP Stream* | you can read `R1 1`, `R1 x1 granted`, `WELCOME` | plain mode is insecure |
| 5 | secure.pcap: compare two packets for the same request | different IV (bytes 8–19) and different ciphertext | random IV per packet |
| 6 | filter `udp.port == 5001` | `HB C1 <seq> <64 hex characters>` every 2 s, and `STATUS ...` every 5 s | UDP heartbeat is authenticated with an HMAC |
| 7 | secure.pcap: bytes 0–6 of a data packet | Type, Sequence number, Length in clear | header fields are visible, but protected by the tag |

### Packet layout to point at in the hex pane (data packets)
```
01 | 00 00 00 02 | 00 04 | 18 e8 ea cc 21 e8 cf 13 ac 6a 12 e9 | 78 68 a9 4b | 77 98 02 dc ... (16 B)
type   seq no.      length        IV (12 bytes, random)           ciphertext      tag
```

## 3. Optional: show tampering live
Plain mode: in the client type `tamper` — the server accepts `S3 1` instead of `R3 1` (data silently changed).
Secure mode: the same command gives `REJECTED packet ... integrity tag mismatch` in the server log.

## 4. Useful display filters
`tcp.port == 5000` · `tcp.flags.syn == 1` · `udp.port == 5001` · `frame contains "R1"` (finds readable text: matches in plain.pcap, not in secure.pcap) · `tcp.len > 0`
