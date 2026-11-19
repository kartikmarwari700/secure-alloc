#!/bin/bash
# Runs the NS2 model for 2, 5, 10 and 20 clients and collects results.dat (test case TC9)
cd "$(dirname "$0")" || exit 1
: > results.dat
for n in 2 5 10 20; do
    echo "running NS2 with $n clients ..."
    ns secure_alloc.tcl $n || exit 1
    awk -v N=$n -f analyze.awk out_$n.tr >> results.dat
done
echo "clients  delay(ms)  throughput(kbps)  loss(%)"
cat results.dat
awk '{print $1, $2}' results.dat > delay.xg
awk '{print $1, $3}' results.dat > throughput.xg
awk '{print $1, $4}' results.dat > loss.xg
echo "graphs:     xgraph delay.xg    xgraph throughput.xg    xgraph loss.xg"
echo "animation:  nam out_5.nam"
