#!/usr/bin/env python3
"""sniffer.py - a tiny "Wireshark" for the demo: a TCP proxy that sits between client and server,
prints every packet it sees in hex + ASCII and tells you whether the text you are looking for is visible.

    python3 tools/sniffer.py --listen 5200 --server 127.0.0.1:5000 --grep "R1 1" --seconds 10 --out sniff.txt

Then start the client with   ./client 127.0.0.1 C1 --tcp-port 5200
In secure mode you only see ciphertext; with ./server --plain and ./client ... --plain you can read the requests.
(Owner: Kartik, module M6 - traffic analysis. For real captures use Wireshark/tcpdump, see docs/WIRESHARK.md)
"""
import argparse, socket, threading, time, sys

def hexdump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("    %04x  %-47s  %s" % (i, hx, asc))
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--server", default="127.0.0.1:5000")
    ap.add_argument("--grep", default="")
    ap.add_argument("--seconds", type=float, default=15)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    shost, sport = a.server.split(":")
    out = open(a.out, "w") if a.out else sys.stdout
    lock = threading.Lock()
    found = {"hit": False, "bytes": 0, "packets": 0}
    needle = a.grep.encode()
    t_end = time.time() + a.seconds

    def pump(src, dst, label):
        while True:
            try:
                data = src.recv(4096)
            except OSError:
                break
            if not data:
                break
            with lock:
                found["packets"] += 1
                found["bytes"] += len(data)
                if needle and needle in data:
                    found["hit"] = True
                print("%s  %d bytes" % (label, len(data)), file=out)
                print(hexdump(data), file=out)
                out.flush()
            try:
                dst.sendall(data)
            except OSError:
                break
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def handle(c):
        s = socket.create_connection((shost, int(sport)))
        threading.Thread(target=pump, args=(c, s, "client -> server"), daemon=True).start()
        threading.Thread(target=pump, args=(s, c, "server -> client"), daemon=True).start()

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.listen))
    ls.listen(8)
    ls.settimeout(0.5)
    while time.time() < t_end:
        try:
            c, _ = ls.accept()
            handle(c)
        except socket.timeout:
            pass
    with lock:
        print("\nSUMMARY: %d packets, %d bytes captured" % (found["packets"], found["bytes"]), file=out)
        if needle:
            print("SUMMARY: text %r %s in the captured traffic" %
                  (a.grep, "IS VISIBLE (readable by an eavesdropper)" if found["hit"] else "is NOT visible (only ciphertext)"), file=out)
        out.flush()

if __name__ == "__main__":
    main()
