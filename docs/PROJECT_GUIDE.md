# SecureAlloc: poora project samjho (study guide)

Ye file padh ke tum project ko shuru se aakhir tak samjha sakte ho, aur agar ma'am code ke baare mein puchen to uska jawab bhi de sakte ho.
Order: pehle badi tasveer, phir zaroori concepts, phir har module ka code, phir ek request ka poora safar, phir ma'am ke sawal.

---

# Part 1: Badi tasveer

## 1.1 Project kya hai (30 second)
Ek **server** hai jiske paas kuch shared cheezein (resources) hain: `R1` (1 unit), `R2` (1 unit), `R3` (3 units). Kai **clients** network par server se ye resources maangte hain (`req R1 1`) aur kaam ke baad wapas karte hain (`rel R1 1`).

Do problems solve ki hain:
1. **Security:** beech ka raasta encrypted aur authenticated hai.
2. **Deadlock:** server deadlock khud pakadta aur theek karta hai.

## 1.2 Poora system ek tasveer mein
```
   CLIENT (C1, C2, ...)                                   SERVER
  +--------------------+                          +-------------------------+
  | menu: req/rel/...  |                          | accept() loop           |
  | client.c           |                          | 1 thread per client     |
  +---------+----------+                          | server.c                |
            |                                     +------------+------------+
  +---------v----------+   TCP 5000 (encrypted)   +------------v------------+
  | Security layer     | <======================> | Security layer          |
  | auth.c  (DH + RSA) |                          | auth.c, secure_channel.c|
  | secure_channel.c   |                          +------------+------------+
  | (AES-256-GCM)      |                                       |
  +---------+----------+                          +------------v------------+
            |            UDP 5001 (heartbeat)     | Resource Manager        |
            +-----------------------------------> | resource.c              |
                                                  | table + wait queue +    |
                                                  | wait-for graph + DFS    |
                                                  +-------------------------+
```

## 1.3 Files aur kaun si file kya karti hai

| File | Module | Kaam ek line mein |
|---|---|---|
| `src/server.c` | M1 | Server ka main: connections accept karna, har client ke liye thread, UDP heartbeat, console |
| `src/client.c` | M1/M2 | Client: menu, server se baat, heartbeat bhejna |
| `src/protocol.c` | M2 | TCP ke bytes ko poora bhejna/lena, message ke naam |
| `src/auth.c` | M3 | Handshake: Diffie-Hellman + RSA signature, session key banana |
| `src/crypto.c` | M3/M4 | OpenSSL ke functions ko simple naam dena (DH, RSA, AES, SHA-256, HMAC) |
| `src/secure_channel.c` | M4 | Packet banana (encrypt + tag + sequence number) aur kholna (verify) |
| `src/resource.c` | M5 | Resources dena, wait queue, deadlock dhoondhna aur theek karna |
| `src/logger.c`, `config.c` | M1 | Log likhna, settings file padhna |
| `tests/`, `tools/`, `ns2/`, `scripts/` | M6 | Tests, benchmark, packet viewer, NS2 simulation, demo |

---

# Part 2: Zaroori concepts (inhe samajh lo, baaki sab asaan hai)

## 2.1 Client-Server model
Server ek jagah baitha rehta hai aur **listen** karta hai. Client usse **connect** karta hai. Server har client ko alag se sambhalta hai.

## 2.2 Socket kya hai
Socket = network par baat karne ka "darwaza". Program ek number (file descriptor) paata hai, aur `send()` / `recv()` se bytes bhejta/leta hai, bilkul file padhne jaisa.

Server ke steps: `socket()` -> `bind(port)` -> `listen()` -> `accept()` (naya client aaya, naya socket mila).
Client ke steps: `socket()` -> `connect(server ip, port)`.

## 2.3 TCP vs UDP (zaroor yaad rakho)

| | TCP | UDP |
|---|---|---|
| Connection | pehle 3-way handshake (SYN, SYN-ACK, ACK) | koi connection nahi |
| Bharosa | data poora aur sahi order mein aata hai | packet kho sakta hai |
| Speed | thoda dheema | tez, halka |
| Humne kahan use kiya | requests/grants (port 5000) | heartbeat/status (port 5001) |

**Kyu dono?** Requests galat ya adhoori nahi honi chahiye (TCP). Heartbeat har 2 second mein dobara jaata hai, ek kho jaye to koi baat nahi (UDP).

## 2.4 TCP "byte stream" hai: framing kyu zaroori
TCP message nahi, **bytes ki dhaara** bhejta hai. Tum 40 bytes bhejo to samne wale ko 20 + 20 bhi mil sakte hain, ya do messages chipak ke aa sakte hain. Isliye har packet mein **length** likhte hain, aur `recv_all()` tab tak padhta hai jab tak poore bytes na aa jayein.

## 2.5 Thread aur mutex
- **Thread** = ek program ke andar chhota alag kaam. Humne **har client ke liye ek thread** banaya, taaki ek client ka wait baaki ko na roke.
- Dikkat: sab threads ek hi resource table badalte hain. Do threads ek saath badlenge to table kharab.
- **Mutex** = taala. Jisne taala liya wahi andar ja sakta hai. Humne ek taala `g_lock` rakha, jo client table aur resource table dono ko bachata hai.

## 2.6 Cryptography ke 5 hisse

**(a) Diffie-Hellman (DH) - bina bheje same key banana**
Do log khuli jagah par baat kar rahe hain, phir bhi ek secret key bana lete hain.
Rang wala example: dono ke paas ek common rang (peela) hai. Server apna secret rang (laal) milake bhejta hai, client apna secret rang (neela) milake bhejta hai. Ab dono apna secret rang **doosre ke mixture mein** milate hain. Dono ko same final rang milta hai. Beech wale ko mixture dikhte hain, par wo secret rang alag nahi kar sakta.
Maths mein: public numbers `p` (bada prime) aur `g=2`. Server secret `a`, bhejta hai `g^a mod p`. Client secret `b`, bhejta hai `g^b mod p`. Dono nikalte hain `g^(ab) mod p`. Hacker `g^a` aur `g^b` dekhta hai par `g^(ab)` nahi nikaal sakta (ye "discrete logarithm" problem hai, bahut mushkil).
Humne 2048-bit ka `p` use kiya (RFC 3526 ka standard group).

**(b) RSA signature - "ye asli hai" ka saboot**
DH ye nahi batata ki samne **kaun** hai. Beech ka hacker dono se alag-alag DH kar sakta hai (man-in-the-middle). Isliye **signature**:
- Server apni **private key** se `g^a` par sign karta hai.
- Client server ki **public key** se check karta hai. Sahi nikla = asli server.
- Waise hi client apni private key se sign karta hai, server uski public key se check karta hai.
Private key sirf owner ke paas, public key sabke paas. Sign sirf private key wala kar sakta hai.

**(c) SHA-256 - hash**
Kisi bhi data ka 256-bit ka "fingerprint". Chhota sa badlav bhi poora alag hash deta hai. Humne DH ke bade number ko SHA-256 se 32 byte ki **session key** banaya (AES-256 ko exactly yahi chahiye).

**(d) AES-256-GCM - encryption + integrity ek saath**
- **AES-256:** message ko scramble karta hai, sirf key wala khol sakta hai.
- **GCM mode:** scramble ke saath ek **16-byte tag** bhi banata hai. Agar koi ek bit bhi badle, tag match nahi karega.
- **IV (nonce):** 12 random bytes, har packet ke liye naya. Isliye ek hi message har baar alag dikhta hai.
- **AAD:** packet ka header (type, sequence, length) encrypt nahi hota par tag usko bhi cover karta hai, isliye header badlo to bhi pakda jata hai.

**(e) HMAC - UDP heartbeat ke liye**
Heartbeat par key ke saath ek mohar (`HMAC-SHA256`). Bahar wala nakli heartbeat nahi bana sakta.

## 2.7 Deadlock
**4 conditions (sab ek saath hon tab deadlock):**
1. Mutual exclusion: resource ek time par ek hi ke paas.
2. Hold and wait: ek rakhke doosra maangna.
3. No pre-emption: resource zabardasti chhina nahi ja sakta.
4. Circular wait: gol chakkar mein wait.

**Wait-for graph:** har client ek node. Agar `C1` us resource ka wait kar raha hai jo `C2` ke paas hai, to arrow `C1 -> C2`. **Cycle = deadlock.**

**Detection vs prevention vs avoidance:** prevention = ek condition todo, avoidance = pehle se hisaab (banker's algorithm), **detection = hone do, pakdo aur theek karo.** Humne detection use kiya.

---

# Part 3: Har module ka code samjho

Neeche code ke chhote tukde hain. Ma'am pooche "ye line kya karti hai", to yahan se jawab do.

---

## 3.1 `protocol.c` (M2): bytes ka sahi transfer

**`send_all()`** ek loop hai jo tab tak `send()` karta hai jab tak saare bytes na chale jayein (kabhi `send()` aadha bhejta hai).
```c
while (n > 0) {
    ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
    p += w; n -= w;
}
```
**`recv_all()`** waise hi: tab tak padho jab tak poore `n` bytes na aa jayein. `0` aaye to samne wale ne connection band kar diya.

**`send_blob / recv_blob`**: handshake mein bade numbers bhejne ke liye: pehle 2 byte ki length, phir data. Padhne wala length ko apne buffer se check karta hai (`if (len > cap) return -1`), taaki koi jhoothi bahut badi length bhejke program na tod sake.

**`msg_name()`**: message type ke number (1, 2, ...) ko naam (REQ, GRANT, ...) deta hai.

**Message types:** `REQ`=maang, `GRANT`=mil gaya, `WAIT`=queue mein, `DENY`=mana, `REL`=wapas, `STATUS`=jaankari, `ERR`=galti, `HELLO`=sirf plain mode ka pehla message.

---

## 3.2 `crypto.c` (M3/M4): OpenSSL ke wrappers

Ye file khud crypto ka algorithm nahi likhti. Wo OpenSSL library karti hai. Ye file bas use simple functions mein lapet deti hai.

| Function | Kaam |
|---|---|
| `dh_generate()` | secret `a` banata hai (random 256 bit), `g^a mod p` nikalta hai |
| `dh_shared()` | samne wale ka public value lekar `g^(ab) mod p` nikalta hai. Pehle check karta hai ki value `0`, `1`, `p-1` na ho (ye kamzor values hain) |
| `sha256()` | 256-bit hash |
| `rsa_sign()` / `rsa_verify()` | PEM file se key padhke signature banana/check karna |
| `aes_gcm_encrypt()` / `aes_gcm_decrypt()` | encrypt + tag, decrypt + tag check |
| `random_bytes()` | OpenSSL ka secure random (IV ke liye) |
| `hmac_sha256()` | heartbeat ki mohar |

DH ka core:
```c
BN_mod_exp(A, g, a, p, bc);   // A = g^a mod p
```
`BN_` = Big Number (kyunki 2048-bit number normal `int` mein nahi aata).

AES-GCM mein header ko authenticate karne ka tarika:
```c
EVP_EncryptUpdate(c, NULL, &len, aad, aadlen);   // header: sirf tag mein shamil
EVP_EncryptUpdate(c, ct, &len, pt, n);           // message: encrypt
EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag);   // tag nikalo
```
Decrypt mein `EVP_DecryptFinal_ex()` **fail** ho jata hai agar tag match na kare. Yahi tamper detection hai.

---

## 3.3 `auth.c` (M3): handshake

Poori kahani:
```
Client                                         Server
  |--------- TCP connect -------------------------->|
  |<-- g^a  +  RSA_sign_server(g^a) ----------------|   client: "asli server hai?"
  |--- g^b + ID + RSA_sign_client(g^a|g^b|ID) ----->|   server: "asli client hai?"
  | dono: secret = g^(ab) mod p
  | dono: session key = SHA-256(secret)
  |<------ pehla encrypted message: WELCOME --------|   saboot ki key same hai
```
**Server wala (`auth_server_handshake`) ke steps:**
1. `dh_generate()` se `g^a` banao.
2. `rsa_sign("keys/server_priv.pem", g^a)`, `g^a` aur signature bhejo.
3. Client ka `g^b`, ID, signature lo.
4. ID check karo (`valid_client_id`: sirf 1-8 letter/digit).
5. `keys/<ID>_pub.pem` se signature verify karo. Fail = connection refuse.
6. `dh_shared()` se secret, `sha256()` se session key.

**Client wala (`auth_client_handshake`):** pehle server ka signature `keys/server_pub.pem` se verify karta hai. Galat = `SERVER AUTHENTICATION FAILED`.

**Dhyan dene wali baatein (ma'am pooch sakti hain):**
- Client apne signature mein `g^a` bhi daalta hai, taaki wo signature kisi aur session mein dobara use na ho.
- `valid_client_id()` kyu? ID se file ka naam bante hai (`keys/C1_pub.pem`). Agar koi `../../x` jaisa ID bheje to galat file khul sakti thi. Isliye sirf letters/digits allowed.
- Har client ki apni alag RSA key hai.
- `client_priority("C3")` = 3. **Chhota number = zyada priority.**
- `key_fingerprint()` = session key ke hash ke pehle 8 byte. Debug mein print karte hain taaki client aur server ka match dikha sakein (key khud kabhi print nahi hoti).

---

## 3.4 `secure_channel.c` (M4): packet ka design

Har packet aisa dikhta hai:
```
+------+---------+--------+-----------+----------------------+---------+
| Type | Seq No. | Length |  IV       |  Payload (encrypted) |   Tag   |
| 1 B  |  4 B    |  2 B   |  12 B     |      Length bytes    |  16 B   |
+------+---------+--------+-----------+----------------------+---------+
```
**Packet banana (`build_frame`):**
```c
uint32_t seq = ++s->send_seq;            // har packet ka number badhta hai
f[0] = type;  f[1..4] = seq;  f[5..6] = length;
random_bytes(f + 7, IV_LEN);             // naya random IV
aes_gcm_encrypt(key, iv, f /*header = AAD*/, 7, payload, n, ciphertext, tag);
```
**Packet kholna (`recv_msg`)** do jaanch karta hai, **is order mein**:
```c
if (aes_gcm_decrypt(...) < 0)  -> "integrity tag mismatch"   (tamper)
if (seq <= s->recv_seq)        -> "old sequence number"      (replay)
s->recv_seq = seq;
```
**Order kyu important hai?** Pehle tag, phir sequence. Agar pehle sequence badha dete to hacker nakli packet bhejke counter aage kar sakta aur asli client ka rasta band ho jata. Counter tabhi badhta hai jab tag sahi ho.

**Sequence "badhna chahiye" (barabar nahi)** kyu? Agar kisi tamper wale packet ko reject kiya, to client ka agla asli packet ka number aage hoga. Gap allowed hai, purane number nahi.

**Attack demo ke functions:**
- `send_tampered()`: encrypt karke ek bit ulta karke bhejta hai (hacker ka role).
- `send_replay()`: pichla packet bilkul wahi dobara bhejta hai.

Return values `recv_msg`: `1` theek, `0` connection band, `-1` galat protocol, `-2` packet reject (tamper/replay).

**Plain mode (`--plain`)**: encryption band. Sirf Wireshark mein "pehle vs baad" dikhane ke liye.

---

## 3.5 `resource.c` (M5): deadlock (ye tumhara module hai, isse acche se yaad karo)

### Data structures
```c
resource_t { name, total, avail, held[client] }   // har resource: kitna total, kitna free, kiske paas kitna
waiter_t   { client, res, units, order }          // wait queue: kaun kya maang raha hai, kab se (order)
```

### Request ka flow: `rm_request()`
1. Resource naam sahi hai? units 1..total ke beech? Client pehle se wait mein to nahi? Nahi to `DENY`.
2. Agar `avail >= units` -> turant `GRANT`.
3. Nahi to **wait queue mein daalo** -> phir deadlock check chalao.
4. Deadlock ke baad bhi agar queue mein hai to `WAIT`.

### Wait-for graph: `build_graph()`
```c
// client i, resource r ka wait kar raha hai, aur j us resource ko hold karta hai  =>  edge i -> j
adj[W[w].client][j] = 1;
```

### Cycle dhoondhna: `dfs()` (sabse important)
DFS (Depth First Search) graph mein ek rasta pakad ke ghusta chala jata hai. 3 rang:
- **0 (safed)** = abhi dekha nahi
- **1 (bhoora)** = abhi isi raste par hai
- **2 (kaala)** = pura dekh liya
```c
color[u] = 1;                         // andar gaye
for (v ...) if (adj[u][v]) {
    if (color[v] == 0)  dfs(v);       // naya node: aur andar jao
    else if (color[v] == 1)  -> CYCLE // wapas apne hi raste ke node par aaye = gol chakkar!
}
color[u] = 2;                         // nikal aaye
```
Example: C1 se shuru. `C1 -> C2` (C1 bhoora, C2 bhoora). `C2 -> C1`: C1 to bhoora hai, matlab raste mein hi hai = **cycle: C1 -> C2 -> C1**.

### Deadlock theek karna: `resolve_deadlocks()`
```
jab tak cycle milti hai:
    1. cycle mein sabse kam priority wala client (victim) chuno
    2. victim ki waiting request cancel karo        (drop_waiter)
    3. victim ke saare resources wapas lo            (release_all)   <- pre-emption
    4. victim ko DENY bhejo, baaki cycle walon ko STATUS bhejo
    5. wait queue dobara chalao: jisko ab mil sakta hai use GRANT
```
**Victim kaun?** `cprio[]` sabse bada number = sabse kam priority (C2, C1 se kam important).
**Kyu resources bhi wapas?** Deadlock ka ek reason "no pre-emption" tha. Hum victim ke resources zabardasti lekar us condition ko tod dete hain.

### Queue serve karna: `serve_queues()`
Jab bhi resource free hota hai, sabse purani request (`order` sabse chhota) dekho jisko ab mil sakta hai, use do. **FIFO = pehle aao pehle pao.**

### Ye kab chalta hai
- Naya wait queue mein aane par.
- `rel` (release) par.
- Client disconnect ya heartbeat timeout par (`rm_remove_client`).

### Do chhoti cheezein
- `quiet_client` trick: jab `rm_request` chal raha ho aur recovery se khud us client ko bhi message bhejna ho (jaise usko hi victim banaya), to wo message alag se na bhej kar **reply mein hi** lauta dete hain. Isse "pehle WAIT phir DENY" jaise ulte-seedhe messages nahi aate.
- Is file mein **koi socket ya lock nahi**. Isse isse akele test kar sakte hain (`test_deadlock`) aur samjhana bhi asaan.

### Limitation (jhoot nahi bolna)
Agar resource mein **kai units** hon, to cycle ka matlab "shayad deadlock", pakka nahi (koi bahar wala client unit free kar sakta hai). Humne har cycle ko deadlock maan liya. Demo ke resources (R1, R2 = 1 unit) mein cycle = pakka deadlock.

---

## 3.6 `server.c` (M1): server ka dil

### Threads
| Thread | Kaam |
|---|---|
| main | `accept()` loop: naya client aaya to slot do, thread banao |
| `client_thread` (har client ka) | handshake, phir request loop |
| `udp_thread` | heartbeat sunna, 6s se zyada chup client ko hatana, har 5s status bhejna |
| `console_thread` | server ke terminal par commands: `help status clients stats quit` |

### `client_thread` ka flow
```
1. handshake (auth_server_handshake)             <- fail to band
2. check: kya ye ID pehle se connected hai?      <- haan to refuse (spoofing)
3. rm_register(...)
4. WELCOME bhejo
5. loop:
     recv_msg()
        rc == -2  -> "REJECTED" log, ERR bhejo, continue   (tamper/replay)
        rc == 0   -> client gaya, loop khatam
     lock lo -> REQ/REL/STATUS handle karo -> reply bhejo -> lock chhodo
6. cleanup: lock lo -> rm_remove_client (resources wapas) -> socket band
```
**Reply lock ke andar kyu bhejte hain?** Taaki reply aur "late GRANT" notification ulte order mein na pahunche.

### Heartbeat ka kaam
- Client har 2s UDP par `HB C1 <seq> <HMAC>` bhejta hai.
- Server HMAC check karta hai (nakli nahi chalegi) aur sequence naya hona chahiye.
- `now - last_hb > 6` -> `shutdown(socket)` -> us client ka thread jaag ke cleanup karta hai (resources free).

### Aur cheezein
- **Slot table `clients[32]`:** har client ka ek khana. Zyada clients aaye to `too many clients` bolke mana.
- **10 second handshake timeout:** koi connect karke handshake na kare to wo atka na rahe (DoS se bachav).
- **Ctrl+C:** `g_stop` flag set hota hai, server saaf band hota hai aur statistics print karta hai.
- **Statistics:** kitne connections, handshakes, rejected packets (tampered/replayed), heartbeats, grants, waits, deadlocks.

---

## 3.7 `client.c` (M1/M2)

- Command parse karta hai (`req R1 1` ya `1 R1 1`) aur `send_msg()` karta hai.
- **`select()`** se dono ko ek saath sunta hai: keyboard (stdin) aur server ka socket. Isse tum type kar rahe ho tab bhi server ka message (jaise late GRANT) turant dikh jata hai.
- **Heartbeat thread:** har 2 second `HB` UDP bhejta hai. `mute` command isko band kar deta hai (demo ke liye).
- **`tamper`, `replay`:** hacker ka role karne ke liye.

---

## 3.8 `logger.c`, `config.c`
- `logger.c`: har event ek line mein, time aur level ke saath (`INFO`, `WARN`, `SECURITY`, `ERROR`), screen aur `logs/server.log` dono mein. Thread-safe (apna mutex).
- `config.c`: `secure_alloc.conf` padhta hai (ports, timeout, resources). `key = value` format, `#` se comment.

---

# Part 4: Ek request ka poora safar (end to end)

Maan lo C1 type karta hai: `req R1 1`.

```
1. client.c      -> send_msg(MSG_REQ, "R1 1")
2. secure_channel-> seq=2, random IV, AES-GCM se "R1 1" encrypt, tag lagao
3. TCP           -> bytes server ko (hacker ko sirf random bytes dikhte hain)
4. secure_channel-> server: header+tag verify, sequence check, decrypt -> "R1 1"
5. server.c      -> g_lock lo, sscanf("R1 1") -> res="R1", units=1
6. resource.c    -> rm_request(): R1 free? haan -> avail-- , held[C1]++ -> GRANT
7. server.c      -> send_msg(GRANT, "R1 x1 granted"), g_lock chhodo
8. client.c      -> recv_msg -> screen par: << [GRANT] R1 x1 granted
```
Agar R1 free nahi hota: step 6 mein queue mein jata, deadlock check chalta, `WAIT` jata. Baad mein kisi ke `rel R1 1` karne par `serve_queues()` use apne aap `GRANT` bhej deta.

---

# Part 5: Attacks aur bachav

| Attack | Hacker kya karta hai | Hum kaise rokte hain | Demo |
|---|---|---|---|
| Eavesdropping | traffic padhta hai | AES-256 encryption | `wire_demo`, sniffer |
| Man-in-the-middle | beech mein nakli server bankar DH values badalta hai | RSA signature: client check karta hai | fake server test (X1) |
| Spoofing | doosre client ka ID use karta hai | har client ki alag RSA key, signature check, duplicate ID refuse | X2, X3, X4 |
| Tampering | packet ka byte badalta hai | GCM tag | `tamper` |
| Replay | purana asli packet dobara bhejta hai | sequence number | `replay` |
| DoS | resource pakadke gayab ho jata, ya handshake adhura chhodta | heartbeat timeout, 10s handshake timeout, client limit | `mute`, TC8 |

**Plain mode ka sabak:** `--plain` mein `tamper` karne par `R3 1` badal ke `S3 1` ho jata hai aur server bina pakde maan leta hai. Isse dikhta hai ki encryption kyu zaroori hai.

---

# Part 6: Results (asli numbers)

| Cheez | Requirement | Mila |
|---|---|---|
| Handshake time | 1 second se kam | average 52 ms |
| Request-response time | 50 ms se kam | average 1.3 ms |
| Clients ek saath | kam se kam 20 | 20 clients x 50 rounds, 0 errors |
| Tests | | 54 unit checks + 41 integration checks pass |

NS2 ke numbers abhi nahi chale (NS2 install nahi tha). Wo lab machine par `bash ns2/run_ns2.sh` se aayenge.

---

# Part 7: Wireshark aur NS2 (M6)

**Wireshark mein kya dikhta hai:**
- Pehle 3 packet: `SYN`, `SYN-ACK`, `ACK` (TCP handshake).
- Phir handshake ke blobs: 256-byte `g^a`, signature, `g^b`, ID, signature. **Koi secret key nahi**, sirf public values.
- Phir data packets: sirf pehle 7 byte (Type, Seq, Length) padhne layak hain, baaki random.
- Plain mode mein `R1 1`, `granted`, `WELCOME` padh sakte ho.
- UDP: `HB C1 <seq> <64 hex>` har 2s, `STATUS ...` har 5s.

**NS2 kya hai:** Network Simulator. Hum ek nakli network banate hain: N clients -> router -> server (beech ki link 2 Mb/s, bottleneck). Chalate hain 2, 5, 10, 20 clients ke saath. Pehle se andaza: clients badhne par **throughput link ki limit ke paas rukta hai, delay aur packet loss badhte hain** (queue bharti hai).
- `secure_alloc.tcl`: simulation ki script.
- `analyze.awk`: trace file se average delay, throughput, loss nikalta hai.
- `run_ns2.sh`: 2/5/10/20 clients chalata hai aur graphs ki files banata hai.

---

# Part 8: Ma'am ke possible sawal (code wale)

**Q. `recv_all` kyu? `recv` seedha kyu nahi?**
TCP byte stream hai. Ek `recv` poora message de, ye pakka nahi. `recv_all` loop mein tab tak padhta hai jab tak poore bytes na aa jayein.

**Q. Mutex kahan use kiya aur kyu?**
`server.c` mein `g_lock`. Client table aur resource table dono usse bachte hain. Har request pura lock ke andar handle hota hai. Isse do threads ek saath table nahi badalte.

**Q. DFS mein `color[v]==1` ka matlab?**
Wo node abhi mere hi current rasta mein hai. Usse wapas milna = gol chakkar = cycle.

**Q. Victim kaise chunte ho?**
Cycle ke clients mein jiska ID number sabse bada (C2, C1 se kam priority). `cprio[]` mein compare karte hain.

**Q. IV random kyu?**
GCM mein ek hi key ke saath ek hi IV dobara nahi use hona chahiye. Random 12 byte se har packet alag hota hai (aur same message ka ciphertext bhi alag).

**Q. Tag aur sequence ka order?**
Pehle tag, phir sequence. Warna hacker bina asli key ke sequence counter aage kar sakta tha.

**Q. DH ke baad hash kyu?**
DH ka output bada structured number hai. SHA-256 usse 256-bit ki uniform key bana deta hai jo AES-256 ko chahiye.

**Q. RSA kyu agar DH hai?**
DH sirf key banata hai, identity nahi batata. Man-in-the-middle ke liye RSA signature chahiye.

**Q. Forward secrecy hai?**
Haan session key ke liye. DH ke secrets `a`, `b` har session mein naye hain aur baad mein mita diye jate hain, to baad mein RSA key chori ho jaye tab bhi purane sessions nahi khulte. RSA sirf signature ke liye use hota hai.

**Q. `valid_client_id` kyu?**
Kyunki ID se `keys/<ID>_pub.pem` file ka naam banta hai. Bina check ke `../` jaisa ID kisi aur file tak pahuncha sakta tha.

**Q. Heartbeat ko HMAC kyu?**
Taaki bahar wala nakli heartbeat bhejke mare hue client ko zinda na dikha sake, ya zinda ko mara hua.

**Q. Server crash kyu nahi hota jab client achanak band ho?**
`recv` 0 ya -1 deta hai, thread loop se nikal ke cleanup karta hai (resources free). `SIGPIPE` ignore hai aur `send` mein `MSG_NOSIGNAL`.

**Q. Kitne clients sambhalta hai?**
Config se (default 32). 20 clients ka load test chala hai, 0 errors.

**Q. Isme kya kamzori hai?** (ye bolna acchi baat hai)
Private keys par password nahi. UDP status encrypted nahi (sirf public counts). Multi-unit resources mein cycle ko deadlock maan lete hain. Ye lab-level project hai, asli kaam ke liye TLS use hota hai.

---

# Part 9: Kaun sa hissa kisne banaya (synopsis ke hisaab se)

| Module | Kaam | Owner |
|---|---|---|
| M1 | socket layer, threads, UDP heartbeat, timeout | Ishita |
| M2 | protocol, framing, client menu | Ishita |
| M3 | Diffie-Hellman, RSA, session key | Priyani |
| M4 | AES-256-GCM, integrity tag, sequence number | Priyani |
| M5 | resource manager, deadlock detection | Kartik |
| M6 | Wireshark, NS2, performance | Kartik |

---

# Part 10: Explain karne ka sahi order (ma'am ke saamne)

1. **Problem batao** (2 line): secure chahiye + deadlock rokna hai.
2. **Architecture** (Part 1.2 ki tasveer).
3. **Demo chalao** (`START_DEMO.bat` ya `bash scripts/demo.sh`). Har step par "BOLO" wali line padho.
4. Jo hissa ma'am puchein, us module ka section yahan se padh ke samjhao.
5. Ant mein **numbers** (Part 6) aur **limitations** (Part 8 ka aakhri sawal).

**Yaad rakhne wali 5 line:**
1. TCP = bharosemand requests, UDP = halka heartbeat.
2. DH se key bani, RSA se pehchaan hui, AES-GCM se data secure hua.
3. Tag = tamper pakadta hai, sequence number = replay pakadta hai.
4. Wait-for graph mein cycle = deadlock, DFS se dhoondhte hain.
5. Sabse kam priority wala victim, uske resources wapas, baaki chal padte hain.
