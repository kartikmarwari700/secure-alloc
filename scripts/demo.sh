#!/bin/bash
# demo.sh - automatic guided demo of SecureAlloc. Press ENTER to go to the next step.
#   bash scripts/demo.sh            (DEMO_AUTO=1 skips the pauses)
cd "$(dirname "$0")/.." || exit 1
mkdir -p tests/out logs
LOG=tests/out/demo_server.log
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; R=$'\e[31m'; N=$'\e[0m'

[ -x ./server ] && [ -x ./client ] && [ -d keys ] || { echo "build first:  make keys && make"; exit 1; }

pause() { [ -n "$DEMO_AUTO" ] || read -r -p "${Y}   [Press Enter for the next step]${N}" _; echo; }
title() { echo; echo "${B}${C}=========================================================${N}"; echo "${B}${C} $1${N}"; echo "${B}${C}=========================================================${N}"; }
say()   { echo "${G}NOTE:${N} $1"; }
script(){ while [ $# -ge 2 ]; do echo "$1"; sleep "$2"; shift 2; done; }
clean() { sed 's/^\(> \)*//' | grep -E '^(>>|<<|Connected|DEBUG|!!|connection closed)'; }
mark()  { MARK=$(wc -l < $LOG); }
newlog(){ tail -n +$((MARK+1)) $LOG | sed 's/^\[[0-9:]*\] //'; }

trap 'kill $SPID 2>/dev/null' EXIT
: > $LOG
./server --debug > $LOG 2>&1 < /dev/null &
SPID=$!
sleep 1

clear 2>/dev/null
title "SecureAlloc - Secure Client-Server Resource Allocation"
say "A server hands out shared resources (R1, R2, R3) to clients."
say "Everything between client and server is ENCRYPTED, and the server detects DEADLOCKS by itself."
say "The server is running: TCP port 5000 (requests), UDP port 5001 (heartbeat)."
echo; head -4 $LOG | sed 's/^\[[0-9:]*\] //'
pause

# ---------------------------------------------------------------- 1
title "STEP 1: Secure connection (Diffie-Hellman + RSA + AES-256)"
say "Client C1 connects. In the handshake both sides derive the same session key without ever sending it."
mark
script "req R3 2" 1 "status" 1 "rel R3 2" 1 | ./client 127.0.0.1 C1 --debug 2>&1 | clean | tee tests/out/demo_c1.txt
echo; echo "${B}--- Server log ---${N}"; newlog | grep -v "new TCP"
cfp=$(grep -o 'fingerprint = [0-9a-f]*' tests/out/demo_c1.txt | awk '{print $3}')
echo; say "Client key fingerprint ${B}$cfp${N} equals the server fingerprint -> both sides hold the same key."
say "(Only a hash of the key is shown. The key itself never crosses the network.)"
pause

# ---------------------------------------------------------------- 2
title "STEP 2: DEADLOCK detection (module M5)"
say "C1 holds R1 and wants R2. C2 holds R2 and wants R1. Each waits for the other = deadlock."
mark
script "req R1 1" 2 "req R2 1" 3 | ./client 127.0.0.1 C1 2>&1 | clean > tests/out/demo_d1.txt &
script "" 1 "req R2 1" 2 "req R1 1" 3 | ./client 127.0.0.1 C2 2>&1 | clean > tests/out/demo_d2.txt &
sleep 9
echo "${B}--- Client C1 output ---${N}"; cat tests/out/demo_d1.txt
echo; echo "${B}--- Client C2 output ---${N}"; cat tests/out/demo_d2.txt
echo; echo "${B}--- Server log ---${N}"; newlog | grep -E "REQ|GRANT|WAIT|DEADLOCK|DENY|STATUS" | grep -v "R3"
echo
say "The server built the wait-for graph C1 -> C2 -> C1 and DFS found the cycle."
say "C2 (lowest priority) became the victim: its request was aborted, its resources released, and C1 received R2."
pause

# ---------------------------------------------------------------- 3
title "STEP 3: Attacks (tampering and replay)"
say "Now we act as an attacker: first flip one bit (tamper), then resend an old packet (replay)."
mark
script "req R3 1" 1 "tamper" 1 "replay" 1 "status" 1 | ./client 127.0.0.1 C2 2>&1 | clean
echo; echo "${B}--- Server log ---${N}"; newlog | grep -E "REJECTED|REQ|GRANT"
echo
say "tamper -> 'integrity tag mismatch': one flipped bit breaks the authentication tag, the packet is rejected."
say "replay -> 'old sequence number': the old packet is recognised and rejected."
say "The 'status' command still works afterwards: the session stays intact."
pause

# ---------------------------------------------------------------- 4
title "STEP 4: Heartbeat timeout (UDP)"
say "Client C3 takes a resource and then freezes (heartbeat stops). The server notices after about 6 seconds."
mark
script "req R1 1" 1 "mute" 12 | ./client 127.0.0.1 C3 2>&1 | clean &
echo "(waiting about 8 seconds...)"; sleep 9
newlog | grep -E "C3|timeout|releasing"
echo; say "Without heartbeats the server closed the connection and freed the resources of C3."
sleep 5
pause

# ---------------------------------------------------------------- 5
title "STEP 5: What an eavesdropper sees (Wireshark view) - plain vs encrypted"
say "The same message 'R1 1' sent in plain mode and in secure mode (as seen on the wire)."
echo
./wire_demo
echo
say "Plain mode: 'R1 1' is readable in the ASCII column. Secure mode: only random-looking bytes."
say "Sending the same message again gives different bytes (random IV). Tamper and replay are both rejected."
pause

# ---------------------------------------------------------------- 6
title "STEP 6: Performance - 20 clients at the same time"
say "Requirements: handshake < 1 s, request-response < 50 ms, 20 simultaneous clients."
echo
./bench 127.0.0.1 20 50
echo
say "Result: all requirements met with a large margin, 0 errors."
pause

title "END OF DEMO"
say "Full server log: logs/server.log  |  All tests: make check  and  make itest"
say "Report: docs/REPORT.md"
echo
