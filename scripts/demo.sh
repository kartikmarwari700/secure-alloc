#!/bin/bash
# demo.sh - automatic guided demo of SecureAlloc. Press ENTER to go to the next step.
#   bash scripts/demo.sh            (DEMO_AUTO=1 skips the pauses)
cd "$(dirname "$0")/.." || exit 1
mkdir -p tests/out logs
LOG=tests/out/demo_server.log
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; R=$'\e[31m'; N=$'\e[0m'

[ -x ./server ] && [ -x ./client ] && [ -d keys ] || { echo "pehle chalao:  make keys && make"; exit 1; }

pause() { [ -n "$DEMO_AUTO" ] || read -r -p "${Y}   [Enter dabao -> agla step]${N}" _; echo; }
title() { echo; echo "${B}${C}=========================================================${N}"; echo "${B}${C} $1${N}"; echo "${B}${C}=========================================================${N}"; }
say()   { echo "${G}BOLO:${N} $1"; }
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
say "Ye ek server hai jo clients ko shared resources (R1, R2, R3) deta hai."
say "Client aur server ke beech sab kuch ENCRYPTED hai, aur server DEADLOCK khud pakadta hai."
say "Server abhi chal raha hai: TCP port 5000 (requests), UDP port 5001 (heartbeat)."
echo; head -4 $LOG | sed 's/^\[[0-9:]*\] //'
pause

# ---------------------------------------------------------------- 1
title "STEP 1: Secure connection (Diffie-Hellman + RSA + AES-256)"
say "Client C1 connect ho raha hai. Handshake mein dono ne bina key bheje same session key bana li."
mark
script "req R3 2" 1 "status" 1 "rel R3 2" 1 | ./client 127.0.0.1 C1 --debug 2>&1 | clean | tee tests/out/demo_c1.txt
echo; echo "${B}--- Server ne ye dekha ---${N}"; newlog | grep -v "new TCP"
cfp=$(grep -o 'fingerprint = [0-9a-f]*' tests/out/demo_c1.txt | awk '{print $3}')
echo; say "Client ka key-fingerprint ${B}$cfp${N} aur server ka fingerprint SAME hai -> dono ke paas ek hi key hai."
say "(Sirf key ka hash dikha rahe hain, key khud kabhi network par nahi jaati.)"
pause

# ---------------------------------------------------------------- 2
title "STEP 2: DEADLOCK detection (mera module M5)"
say "C1 ke paas R1 hai aur wo R2 chahta hai. C2 ke paas R2 hai aur wo R1 chahta hai. Dono ek-dusre ka wait karenge = deadlock."
mark
script "req R1 1" 2 "req R2 1" 3 | ./client 127.0.0.1 C1 2>&1 | clean > tests/out/demo_d1.txt &
script "" 1 "req R2 1" 2 "req R1 1" 3 | ./client 127.0.0.1 C2 2>&1 | clean > tests/out/demo_d2.txt &
sleep 9
echo "${B}--- Client C1 ne ye dekha ---${N}"; cat tests/out/demo_d1.txt
echo; echo "${B}--- Client C2 ne ye dekha ---${N}"; cat tests/out/demo_d2.txt
echo; echo "${B}--- Server ka log ---${N}"; newlog | grep -E "REQ|GRANT|WAIT|DEADLOCK|DENY|STATUS" | grep -v "R3"
echo
say "Server ne wait-for graph banaya: C1 -> C2 -> C1. DFS ne ye cycle pakad li."
say "Sabse kam priority wala C2 victim bana: uski request abort hui, resource wapas liya gaya, C1 ko R2 mil gaya."
pause

# ---------------------------------------------------------------- 3
title "STEP 3: Attacks (tampering aur replay)"
say "Ab hacker ban ke dekhte hain. Pehle ek bit badlenge (tamper), phir purana packet dobara bhejenge (replay)."
mark
script "req R3 1" 1 "tamper" 1 "replay" 1 "status" 1 | ./client 127.0.0.1 C2 2>&1 | clean
echo; echo "${B}--- Server ka log ---${N}"; newlog | grep -E "REJECTED|REQ|GRANT"
echo
say "tamper -> 'integrity tag mismatch': ek bit badla to tag check fail, packet reject."
say "replay -> 'old sequence number': purana packet pehchan liya gaya."
say "Aur uske baad bhi 'status' sahi chala: session safe raha."
pause

# ---------------------------------------------------------------- 4
title "STEP 4: Heartbeat timeout (UDP)"
say "Client C3 resource lega aur phir 'freeze' ho jayega (heartbeat band). Server ~6 second baad pakad lega."
mark
script "req R1 1" 1 "mute" 12 | ./client 127.0.0.1 C3 2>&1 | clean &
echo "(8 second ruko...)"; sleep 9
newlog | grep -E "C3|timeout|releasing"
echo; say "Heartbeat band hone par server ne connection toda aur C3 ke resources free kar diye."
sleep 5
pause

# ---------------------------------------------------------------- 5
title "STEP 5: Wireshark jaisa view - plain vs encrypted"
say "Ek hi message 'R1 1' ko plain mode aur secure mode mein dekhte hain (jo Wireshark mein dikhta)."
echo
./wire_demo
echo
say "Plain mein dahine ASCII column mein 'R1 1' padh sakte ho. Secure mein sirf random bytes."
say "Same message dobara bhejo to bytes alag aate hain (random IV). Tamper aur replay dono reject."
pause

# ---------------------------------------------------------------- 6
title "STEP 6: Performance - 20 clients ek saath"
say "Requirement: handshake < 1 second, request-response < 50 ms, 20 clients."
echo
./bench 127.0.0.1 20 50
echo
say "Result: requirements se bahut behtar, 0 errors."
pause

title "DEMO KHATAM"
say "Server ka pura log: logs/server.log  |  Saare tests ek saath: make check   aur   make itest"
say "Report: docs/REPORT.md   |  Viva ke sawal: docs/VIVA_QA.md"
echo
