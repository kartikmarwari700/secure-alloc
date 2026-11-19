# Test report

Environment: Windows 11 with MSYS2 (GCC 16.2, OpenSSL 3.x), loopback `127.0.0.1`. Same code builds with GCC + OpenSSL on Ubuntu 22.04.
Run: `make check` (unit tests) and `bash tests/run_tests.sh` (integration). Raw output of the last run: `tests/last_run.txt`, details per test in `tests/out/`.

**Result: 41 automated checks passed, 0 failed, 1 skipped (TC9 needs NS2, not installed on the test machine).** Plus 54 unit-test checks.

## Test cases from the synopsis

| TC | Test case | Expected output | Result | How it is tested |
|---|---|---|---|---|
| TC1 | Start server, connect 5 clients at once over TCP | all connect; server shows 5 active threads | **PASS** | `run_tests.sh` (5 clients in parallel; server log shows 5 × "client C? connected"; on Linux `ss -tn 'sport = :5000'` shows the sockets) |
| TC2 | Client sends REQ for 2 units of a free resource | server replies GRANT, table updated | **PASS** | `GRANT] R3 x2 granted`; also `test_deadlock` |
| TC3 | DH handshake client ↔ server | both compute the same session key (hash printed in debug mode) | **PASS** | client and server print the same fingerprint (compared automatically) |
| TC4 | Capture in Wireshark, plain and secure mode | plain: readable REQ; secure: only ciphertext | **PASS** | `tools/sniffer.py` proxy: text visible in plain, not visible in secure; `wire_demo`; for real Wireshark see `docs/WIRESHARK.md` |
| TC5 | Modify one byte of an encrypted packet | integrity check fails, packet rejected and logged | **PASS** | client command `tamper`; log: `integrity tag mismatch (packet modified)` |
| TC6 | Resend a captured valid packet (replay) | old sequence number detected, rejected | **PASS** | client command `replay`; log: `old sequence number 1 (replay)` |
| TC7 | C1 holds R1 wants R2, C2 holds R2 wants R1 | deadlock detected (C1 → C2 → C1), lower-priority aborted, both notified | **PASS** | log: `DEADLOCK cycle: C1 -> C2 -> C1 \| victim: C2`; C2 gets DENY, C1 gets STATUS then GRANT |
| TC8 | Kill a client without releasing | heartbeat timeout fires, resources freed to waiting clients | **PASS** | client `mute`; after 6 s `heartbeat timeout for C3`, resources released, R1 granted to another client |
| TC9 | NS2 with 2, 5, 10, 20 clients on one link | throughput, delay, loss graphs; delay grows with load | **SKIPPED here** | `bash ns2/run_ns2.sh` on a machine with ns-2.35. `analyze.awk` verified with a hand-made trace (`ns2/sample.tr`, expected 70 ms / 33.33 % / 4.2 kb/s, got exactly that) |

## Non-functional requirements

| NFR | Requirement | Measured (`./bench 127.0.0.1 20 50`) | Result |
|---|---|---|---|
| NFR1 | no message content or key material visible in captured packets; keys never sent in plain text | sniffer capture of a secure session does not contain the request text; only public DH values and signatures are sent in the handshake | **PASS** |
| NFR2 | request–response < 50 ms on a LAN; handshake < 1 s | round trip avg 1.3 ms, max 4.5 ms; handshake avg 52 ms, max 69 ms (20 clients at the same moment) | **PASS** |
| NFR3 | abrupt client disconnection must not crash the server; resources released | TC8 and the disconnect after every test client; server stays up | **PASS** |
| NFR4 | at least 20 simultaneous clients without loss of correctness | 20 clients × 50 request/release cycles, 0 errors, table back to `R3 3/3 free` | **PASS** |
| NFR5 | pure C, Makefile, menu-driven client | `make` builds with `-Wall -Wextra`, no warnings | **PASS** |

## Additional tests (beyond the synopsis)

| ID | Scenario | Expected | Result |
|---|---|---|---|
| X1 | **Man-in-the-middle**: fake server with a different RSA key | client prints `SERVER AUTHENTICATION FAILED` and aborts | PASS |
| X2 | **Spoofing**: attacker uses the ID `C1` with a different private key | server: `RSA signature of 'C1' INVALID`, connection refused | PASS |
| X3 | Second connection with an ID that is already online | refused and logged | PASS |
| X4 | Client ID without a registered key (`C99`) | client cannot sign, no session | PASS |
| X5 | Server admin console: `help`, `clients`, `status`, `stats`, `quit` | outputs shown; `quit` shuts down cleanly | PASS |
| X7 | SIGTERM / Ctrl+C | statistics printed, clean exit | PASS |
| X8 | Events written to `logs/server.log` | file exists and is not empty | PASS |
| X9 | Broken configuration file | server refuses to start and names the line | PASS |
| TC4+ | Plain mode: `tamper` changes `R3 1` into `S3 1` | server accepts the changed data (demonstrates why encryption is needed) | PASS |

## Unit tests (`make check`)

| Program | Checks | Covers |
|---|---|---|
| `test_deadlock` | 13 | grant/wait/deny, 2-client and 3-client cycles, victim selection, notification, recovery, release on disconnect |
| `test_crypto` | 23 | DH agreement, DH rejects 0 and 1, SHA-256 known answer, RSA sign/verify (modified data, wrong key, missing key), AES-GCM round trip, flipped bit / header / tag / key detected, random IV, HMAC |
| `test_protocol` | 18 | framing, empty payload, both directions, sequence numbers, tamper → reject → session continues, replay, wrong key, oversized length, closed connection, plain mode, blob framing |

## Bugs found by testing (and fixed)
* `client.c`: a `'\n'` character literal was broken, so the client did not compile.
* `config.c`: `key=value` without spaces was rejected; now spaces are optional.
* Test script: waiting for all background jobs hung forever because a server was still running; now waits for specific PIDs.
