#!/bin/bash
# capture.sh - record SecureAlloc traffic with tcpdump so it can be opened in Wireshark (test case TC4)
#
#   sudo bash scripts/capture.sh secure     # then use  ./server  and  ./client 127.0.0.1 C1
#   sudo bash scripts/capture.sh plain      # then use  ./server --plain  and  ./client 127.0.0.1 C1 --plain
#
# Stop with Ctrl+C. Result: captures/<mode>.pcap  ->  wireshark captures/<mode>.pcap
# Everything runs on one machine, so the interface is the loopback "lo". For two machines use e.g. eth0 / wlan0.
MODE=${1:-secure}
IFACE=${2:-lo}
mkdir -p captures
echo "capturing TCP 5000 + UDP 5001 on $IFACE  ->  captures/$MODE.pcap   (Ctrl+C to stop)"
tcpdump -i "$IFACE" -w "captures/$MODE.pcap" -s 0 'tcp port 5000 or udp port 5001'
