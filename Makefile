# SecureAlloc - build with:  make        (needs gcc, make, libssl-dev:  sudo apt install build-essential libssl-dev)
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -pthread
LIBS    = -lcrypto -lpthread

# source files grouped by module (see README):
M1 = src/logger.c src/config.c                       # M1  socket layer helpers (server.c / client.c are the mains)
M2 = src/protocol.c                                  # M2  application protocol + framing
M3 = src/auth.c src/crypto.c                         # M3  DH + RSA        (crypto.c is shared with M4)
M4 = src/secure_channel.c                            # M4  AES-256-GCM packets, seq numbers
M5 = src/resource.c                                  # M5  resource manager + deadlock detection
HDR = $(wildcard src/*.h)

all: server client bench wire_demo test_deadlock test_crypto test_protocol

server: src/server.c $(M1) $(M2) $(M3) $(M4) $(M5) $(HDR)
	$(CC) $(CFLAGS) -o $@ src/server.c $(M1) $(M2) $(M3) $(M4) $(M5) $(LIBS)

client: src/client.c src/logger.c $(M2) $(M3) $(M4) $(HDR)
	$(CC) $(CFLAGS) -o $@ src/client.c src/logger.c $(M2) $(M3) $(M4) $(LIBS)

# load / performance test (NFR2, NFR4)
bench: tools/bench.c src/logger.c $(M2) $(M3) $(M4) $(HDR)
	$(CC) $(CFLAGS) -Isrc -o $@ tools/bench.c src/logger.c $(M2) $(M3) $(M4) $(LIBS)

# shows plain vs encrypted packet bytes (what Wireshark would show)
wire_demo: tools/wire_demo.c $(M2) $(M3) $(M4) src/logger.c $(HDR)
	$(CC) $(CFLAGS) -Isrc -o $@ tools/wire_demo.c src/logger.c $(M2) $(M3) $(M4) $(LIBS)

# deadlock module alone, no network and no OpenSSL needed
test_deadlock: tests/test_deadlock.c src/resource.c src/resource.h
	$(CC) $(CFLAGS) -o $@ tests/test_deadlock.c src/resource.c

test_crypto: tests/test_crypto.c src/crypto.c $(M2) $(M4) $(HDR)
	$(CC) $(CFLAGS) -o $@ tests/test_crypto.c src/crypto.c $(M2) $(M4) $(LIBS)

test_protocol: tests/test_protocol.c src/crypto.c $(M2) $(M4) $(HDR)
	$(CC) $(CFLAGS) -o $@ tests/test_protocol.c src/crypto.c $(M2) $(M4) $(LIBS)

# RSA key pairs: one for the server, one for each client id C1..C20
keys:
	mkdir -p keys
	openssl genrsa -out keys/server_priv.pem 2048
	openssl rsa -in keys/server_priv.pem -pubout -out keys/server_pub.pem
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
	  openssl genrsa -out keys/C$${i}_priv.pem 2048 && \
	  openssl rsa -in keys/C$${i}_priv.pem -pubout -out keys/C$${i}_pub.pem ; \
	done

# unit tests (no server needed)
check: test_deadlock test_crypto test_protocol
	./test_deadlock
	./test_crypto
	./test_protocol

# full integration tests TC1-TC8 + performance (starts a server by itself)
itest: all
	bash tests/run_tests.sh

test: check

clean:
	rm -f server client bench wire_demo test_deadlock test_crypto test_protocol *.o *.exe

.PHONY: all keys check itest test clean
