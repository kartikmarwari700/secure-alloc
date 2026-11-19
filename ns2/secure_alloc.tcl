# secure_alloc.tcl - NS2 model of SecureAlloc (Module M6)
# N clients  --(10 Mb, 2 ms)-->  router  --(2 Mb, 10 ms bottleneck)-->  server
# usage:  ns secure_alloc.tcl 10        (10 clients)
set N [lindex $argv 0]
if {$N == ""} { set N 5 }

set ns [new Simulator]
set tf [open out_$N.tr w]
$ns trace-all $tf
set nf [open out_$N.nam w]
$ns namtrace-all $nf

proc finish {} {
    global ns tf nf
    $ns flush-trace
    close $tf
    close $nf
    exit 0
}

set server [$ns node]          ;# node 0
set router [$ns node]          ;# node 1
$ns duplex-link $router $server 2Mb 10ms DropTail
$ns queue-limit $router $server 20

for {set i 0} {$i < $N} {incr i} {
    set c($i) [$ns node]       ;# nodes 2 .. N+1
    $ns duplex-link $c($i) $router 10Mb 2ms DropTail

    set tcp($i)  [new Agent/TCP]
    set sink($i) [new Agent/TCPSink]
    $tcp($i) set packetSize_ 512
    $ns attach-agent $c($i) $tcp($i)
    $ns attach-agent $server $sink($i)
    $ns connect $tcp($i) $sink($i)

    set ftp($i) [new Application/FTP]      ;# clients send a continuous stream of requests
    $ftp($i) attach-agent $tcp($i)
    $ns at [expr 0.5 + 0.1 * $i] "$ftp($i) start"
    $ns at 10.0 "$ftp($i) stop"
}

$ns at 10.5 "finish"
$ns run
