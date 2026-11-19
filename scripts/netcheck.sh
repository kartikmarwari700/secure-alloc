#!/bin/bash
# netcheck.sh - the network commands listed in the synopsis (ip/ifconfig, ping, ss/netstat, traceroute, nslookup)
# Use it before the demo to show the setup, and during the demo to show the server threads / connections.
# usage:  bash scripts/netcheck.sh [server-ip]       (default 127.0.0.1)
IP=${1:-127.0.0.1}
run() { echo; echo "\$ $*"; "$@" 2>&1 | head -${LINES_MAX:-12}; }

echo "=============== 1. configuration: ip / ifconfig ==============="
if command -v ip >/dev/null; then run ip addr show; else run ifconfig; fi

echo; echo "=============== 2. connectivity: ping ==============="
run ping -c 3 "$IP"

echo; echo "=============== 3. sockets: ss / netstat  (is the server listening? who is connected?) ==============="
if command -v ss >/dev/null; then
    run ss -tlnp 'sport = :5000'                    # TCP listener of SecureAlloc
    run ss -ulnp 'sport = :5001'                    # UDP heartbeat socket
    run ss -tn 'sport = :5000'                      # one line per connected client (one thread each)
else
    run netstat -an | grep -E ':500[01]'
fi

echo; echo "=============== 4. path: traceroute ==============="
if command -v traceroute >/dev/null; then run traceroute -m 5 "$IP"; else echo "(traceroute not installed:  sudo apt install traceroute)"; fi

echo; echo "=============== 5. name resolution: nslookup ==============="
if command -v nslookup >/dev/null; then run nslookup localhost; else echo "(nslookup not installed:  sudo apt install dnsutils)"; fi
