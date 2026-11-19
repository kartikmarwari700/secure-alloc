# analyze.awk - reads an NS2 trace and prints:  clients  avg_delay_ms  throughput_kbps  loss_percent
# usage: awk -v N=10 -f analyze.awk out_10.tr
# trace line: event time from to type size flags fid src dst seq pktid
BEGIN { sent = 0; recv = 0; drop = 0; bytes = 0; dsum = 0; first = -1; last = 0 }
{
    ev = $1; t = $2; from = $3; to = $4; type = $5; size = $6; pid = $12
    if (type != "tcp") next
    if (ev == "+" && from >= 2) {                 # packet leaves a client node
        if (!(pid in st)) { st[pid] = t; sent++ }
        if (first < 0) first = t
    }
    if (ev == "r" && to == 0 && (pid in st)) {    # packet arrives at the server
        recv++; bytes += size; dsum += (t - st[pid]); last = t
    }
    if (ev == "d") drop++
}
END {
    span = last - first; if (span <= 0) span = 1
    printf "%d %.3f %.1f %.2f\n", N, (recv ? dsum / recv * 1000 : 0), bytes * 8 / span / 1000, (sent ? drop * 100 / sent : 0)
}
