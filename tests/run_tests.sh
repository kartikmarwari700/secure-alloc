#!/bin/bash
# Integration tests TC1 - TC9 from the synopsis + extra security / robustness tests (X1 - X9).
# Run from anywhere after:  make keys && make        ->        bash tests/run_tests.sh
# It starts its own servers (ports 5000/5001, 5100/5101, 5300/5301), drives clients with piped commands and checks the logs.
cd "$(dirname "$0")/.." || exit 1
mkdir -p logs tests/out
OUT=tests/out
pass=0; fail=0; skip=0
PY=$(command -v python3 || command -v python || echo "")

ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; fail=$((fail+1)); }
check(){ if grep -q -- "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1   (expected '$3' in $2)"; fi; }
nocheck(){ if grep -q -- "$3" "$2" 2>/dev/null; then bad "$1   (found '$3' in $2)"; else ok "$1"; fi; }
script(){ while [ $# -ge 2 ]; do echo "$1"; sleep "$2"; shift 2; done; }       # cmd delay cmd delay ...

SERVER_PIDS=""
start_server() {   # start_server <outfile> <args...>
    local f=$1; shift
    : > "$f"
    ./server "$@" > "$f" 2>&1 < /dev/null &
    SERVER_PIDS="$SERVER_PIDS $!"
    sleep 1
}
stop_servers() { for p in $SERVER_PIDS; do kill $p 2>/dev/null; done; wait 2>/dev/null; SERVER_PIDS=""; }
trap stop_servers EXIT

printf 'tcp_port=5100\nudp_port=5101\nlog_file=logs/plain.log\n' > $OUT/plain.conf
printf 'tcp_port=5300\nudp_port=5301\nlog_file=logs/console.log\nresource R1 1\nresource R2 2\n' > $OUT/console.conf
printf 'tcp_port = abc\nbogus_setting = 1\n' > $OUT/bad.conf

echo "================ unit tests ================"
for t in test_deadlock test_crypto test_protocol; do
    if ./$t > $OUT/$t.txt 2>&1; then ok "unit tests: $t ($(grep -c '^PASS' $OUT/$t.txt) checks)"; else bad "unit tests: $t"; fi
done

echo "================ integration tests (secure server) ================"
: > logs/server.log
start_server $OUT/server.out --debug

echo "TC1: 5 clients connect at the same time"
for i in 1 2 3 4 5; do ( sleep 4; echo quit ) | ./client 127.0.0.1 C$i > $OUT/tc1_$i.txt 2>&1 & done
sleep 2.5
n=$(grep -c "client C. connected" $OUT/server.out)
[ "$n" -ge 5 ] && ok "TC1 five clients connected concurrently (server shows $n active threads)" || bad "TC1 only $n clients connected"
sleep 3

echo "TC2 + TC3: REQ -> GRANT, and both sides derive the same session key"
script "req R3 2" 1 "rel R3 2" 1 | ./client 127.0.0.1 C1 --debug > $OUT/tc2.txt 2>&1
check "TC2 server replies GRANT, resource table updated" $OUT/server.out "GRANT\] R3 x2 granted"
cfp=$(grep -o 'fingerprint = [0-9a-f]*' $OUT/tc2.txt | awk '{print $3}')
sfp=$(grep 'fingerprint for C1' $OUT/server.out | tail -1 | grep -o '[0-9a-f]\{16\}$')
[ -n "$cfp" ] && [ "$cfp" = "$sfp" ] && ok "TC3 session-key fingerprint identical on client and server ($cfp)" || bad "TC3 fingerprints differ (client=$cfp server=$sfp)"

echo "TC5 + TC6: tampered packet and replayed packet"
script "req R3 1" 1 "tamper" 1 "replay" 1 "status" 1 | ./client 127.0.0.1 C2 > $OUT/tc5.txt 2>&1
check "TC5 modified byte -> integrity check fails, packet rejected and logged" $OUT/server.out "integrity tag mismatch"
check "TC6 replayed packet -> old sequence number detected and logged" $OUT/server.out "(replay)"
check "TC5/6 client is told the packet was rejected" $OUT/tc5.txt "packet rejected by server"
check "TC5/6 session keeps working after the attacks (STATUS answered)" $OUT/tc5.txt "you hold: R3 x1"

echo "TC7: deadlock  C1 holds R1 wants R2,  C2 holds R2 wants R1"
script "req R1 1" 2 "req R2 1" 4 | ./client 127.0.0.1 C1 > $OUT/tc7_c1.txt 2>&1 &
script "" 1 "req R2 1" 2 "req R1 1" 3 | ./client 127.0.0.1 C2 > $OUT/tc7_c2.txt 2>&1 &
sleep 9
check "TC7 deadlock detected (cycle C1 -> C2 -> C1)" $OUT/server.out "DEADLOCK cycle: C1 -> C2 -> C1"
check "TC7 lowest-priority request (C2) aborted" $OUT/server.out "victim: C2"
check "TC7 victim C2 notified with DENY" $OUT/tc7_c2.txt "\[DENY\] DEADLOCK"
check "TC7 other client C1 notified" $OUT/tc7_c1.txt "\[STATUS\] DEADLOCK"
check "TC7 recovery: C1 finally gets the resource it was waiting for" $OUT/tc7_c1.txt "R2 x1 granted (you were waiting)"

echo "TC8: client freezes (no heartbeat) while holding R1"
script "req R1 1" 1 "mute" 14 | ./client 127.0.0.1 C3 > $OUT/tc8.txt 2>&1 &
sleep 11
check "TC8 heartbeat timeout fires" $OUT/server.out "heartbeat timeout for C3"
check "TC8 its resources are released" $OUT/server.out "client C3 disconnected - releasing"
script "req R1 1" 1 | ./client 127.0.0.1 C4 > $OUT/tc8b.txt 2>&1
check "TC8 R1 can be granted to another client afterwards" $OUT/tc8b.txt "R1 x1 granted"
sleep 3

echo "X3: second connection with an id that is already online"
( sleep 5 ) | ./client 127.0.0.1 C5 > $OUT/x3a.txt 2>&1 &
sleep 1.5
( sleep 1 ) | ./client 127.0.0.1 C5 > $OUT/x3b.txt 2>&1
check "X3 second C5 refused" $OUT/server.out "already connected"
check "X3 client sees the refusal" $OUT/x3b.txt "server refused"
sleep 4

echo "X4: client id without a registered key (C99) is refused"
( sleep 1 ) | ./client 127.0.0.1 C99 > $OUT/x4.txt 2>&1
check "X4 unknown client cannot sign" $OUT/x4.txt "cannot sign"

echo "X2: spoofing - attacker knows id C1 but has a different private key"
mkdir -p $OUT/evil/keys
openssl genrsa -out $OUT/evil/keys/C1_priv.pem 2048 > /dev/null 2>&1
cp keys/server_pub.pem $OUT/evil/keys/
( cd $OUT/evil && ../../../client 127.0.0.1 C1 < /dev/null > ../x2.txt 2>&1 )
check "X2 server rejects the forged client signature" $OUT/server.out "RSA signature of 'C1' INVALID"

echo "X1: man-in-the-middle - fake server with a different RSA key"
mkdir -p $OUT/fake/keys
openssl genrsa -out $OUT/fake/keys/server_priv.pem 2048 > /dev/null 2>&1
for i in 1 2 3; do cp keys/C${i}_pub.pem $OUT/fake/keys/; done
printf 'tcp_port=5400\nudp_port=5401\nlog_file=logs/fake.log\n' > $OUT/fake/fake.conf
( cd $OUT/fake && exec ../../../server --config fake.conf > ../fake.out 2>&1 < /dev/null ) &
FAKEPID=$!
sleep 1
./client 127.0.0.1 C1 --tcp-port 5400 < /dev/null > $OUT/x1.txt 2>&1
check "X1 client detects the fake server and aborts" $OUT/x1.txt "SERVER AUTHENTICATION FAILED"
kill $FAKEPID 2>/dev/null

echo "X9: broken config file is reported"
./server --config $OUT/bad.conf > $OUT/x9.txt 2>&1 < /dev/null
check "X9 server refuses a bad config" $OUT/x9.txt "unknown setting"

echo "================ TC4: Wireshark-style capture, plain vs secure ================"
if [ -n "$PY" ]; then
    $PY tools/sniffer.py --listen 5200 --server 127.0.0.1:5000 --grep "R3 1" --seconds 9 --out $OUT/capture_secure.txt &
    SP=$!
    sleep 1
    script "req R3 1" 1 "status" 1 "rel R3 1" 1 | ./client 127.0.0.1 C1 --tcp-port 5200 > $OUT/tc4_secure.txt 2>&1
    wait $SP 2>/dev/null; sleep 1
    check "TC4 secure mode: request text NOT visible on the wire" $OUT/capture_secure.txt "is NOT visible"
    check "TC4 secure mode: capture shows handshake + ciphertext bytes" $OUT/capture_secure.txt "SUMMARY: [0-9]* packets"

    start_server $OUT/plain_server.out --plain --config $OUT/plain.conf
    $PY tools/sniffer.py --listen 5201 --server 127.0.0.1:5100 --grep "R3 1" --seconds 9 --out $OUT/capture_plain.txt &
    SP=$!
    sleep 1
    script "req R3 1" 1 "status" 1 "rel R3 1" 1 | ./client 127.0.0.1 C1 --plain --tcp-port 5201 --udp-port 5101 > $OUT/tc4_plain.txt 2>&1
    wait $SP 2>/dev/null; sleep 1
    check "TC4 plain mode: request text IS readable on the wire" $OUT/capture_plain.txt "IS VISIBLE"
    script "req R3 1" 1 "tamper" 1 "status" 1 | ./client 127.0.0.1 C2 --plain --tcp-port 5100 --udp-port 5101 > $OUT/x_plain_tamper.txt 2>&1
    check "TC4 plain mode: tampering goes UNDETECTED (server accepts changed data)" $OUT/plain_server.out "S3 1"
else
    echo "SKIP  TC4 sniffer (python not found) - use Wireshark, see docs/WIRESHARK.md"; skip=$((skip+1))
fi
./wire_demo > $OUT/wire_demo.txt 2>&1
check "TC4 wire_demo: plain packet readable" $OUT/wire_demo.txt "R1 1"
check "TC4 wire_demo: tampered + replayed packets rejected" $OUT/wire_demo.txt "(replay)"

echo "================ X5: server admin console ================"
{ sleep 4; echo help; echo clients; echo status; echo stats; sleep 1; echo quit; } | ./server --config $OUT/console.conf > $OUT/x5.txt 2>&1 &
X5PID=$!
sleep 1.5
script "req R2 2" 5 | ./client 127.0.0.1 C1 --tcp-port 5300 --udp-port 5301 > $OUT/x5c.txt 2>&1 &
sleep 6
check "X5 console: help" $OUT/x5.txt "console commands"
check "X5 console: resource table with holder" $OUT/x5.txt "R2  free"
check "X5 console: statistics printed" $OUT/x5.txt "statistics (uptime"
check "X5 console: quit shuts the server down cleanly" $OUT/x5.txt "server shutting down"
wait $X5PID 2>/dev/null

echo "================ performance + load (NFR2, NFR4) ================"
./bench 127.0.0.1 20 50 > $OUT/bench.txt 2>&1
cat $OUT/bench.txt
check "NFR2 handshake under 1 second" $OUT/bench.txt "NFR2 (< 1000 ms): PASS"
check "NFR2 request-response under 50 ms" $OUT/bench.txt "NFR2 (< 50 ms):   PASS"
check "NFR4 20 simultaneous clients, no errors" $OUT/bench.txt "NFR4 (20 simultaneous clients, no errors): PASS"
check "NFR4 consistency: resources free again after the load" $OUT/bench.txt "consistency check (R3 back to 3/3): PASS"

echo "================ log file and statistics ================"
[ -s logs/server.log ] && ok "X8 events are written to logs/server.log" || bad "X8 log file empty"
nocheck "X8 no crash / abnormal exit" $OUT/server.out "Segmentation"
stop_servers
check "X7 Ctrl+C / SIGTERM prints statistics" $OUT/server.out "statistics"

echo "================ TC9: NS2 simulation ================"
if command -v ns > /dev/null 2>&1; then
    if bash ns2/run_ns2.sh > $OUT/ns2.txt 2>&1; then ok "TC9 NS2 produced throughput / delay / loss for 2,5,10,20 clients"; else bad "TC9 NS2 run failed (see $OUT/ns2.txt)"; fi
else
    echo "SKIP  TC9 'ns' (NS2) is not installed here - run  bash ns2/run_ns2.sh  on the NS2 machine"; skip=$((skip+1))
fi

echo
echo "RESULT: $pass passed, $fail failed, $skip skipped        (details in $OUT/)"
[ $fail -eq 0 ]
