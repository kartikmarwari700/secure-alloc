# Presentation script (ma'am ke saamne bolne ke liye)

**Time:** kareeb 12 minute. **Kaise use karo:** `[SCREEN]` = screen par kya karna hai. `[BOLO]` = jo bolna hai (apne shabdon mein bhi bol sakte ho, bas meaning yahi rakho). `[RUKO]` = ek second ruk ke ma'am ko dekho.
**Demo chalane ka tareeka:** `START_DEMO.bat` double-click (Linux par `bash scripts/demo.sh`). Har step ke baad Enter dabana hai.
**Pehle se kar lo:** demo ek baar khud chala ke dekh lo, aur ye file khol ke rakho.

---

## PART 1: Shuruaat (1 min)  *[screen: kuch nahi chalana, README ya report ka title]*

**[BOLO]**
"Good morning ma'am. Hamara project hai **SecureAlloc**: ek secure client-server resource allocation system with deadlock detection. Ye Computer Networks Lab ke liye hai. Is project ko main, Ishita aur Priyani ne milke banaya hai. Main aapko ye 4 cheezein dikhaunga: ye kya hai, kaise secure hai, deadlock kaise pakadta hai, aur performance kaisi hai."

---

## PART 2: Problem kya hai (1.5 min)

**[BOLO]**
"Socho ek college lab hai jisme 2 printers hain aur bahut saare students. Ek server hai jo printers baantta hai. Isme **do problems** aati hain."

"**Pehli problem: security.** Students ki requests network par jaati hain. Koi hacker beech mein request **padh** sakta hai, usse **badal** sakta hai, jaise 1 page ko 100 page, ya purani request **dobara bhej** sakta hai, ya kisi aur student ban ke request bhej sakta hai."

"**Doosri problem: deadlock.** Student A ke paas printer 1 hai aur wo printer 2 maang raha hai. Student B ke paas printer 2 hai aur wo printer 1 maang raha hai. Dono ek-dusre ka wait karte rahenge, hamesha ke liye."

"Hamara project in **dono problems ko solve** karta hai."

---

## PART 3: Architecture (1.5 min)  *[screen: PROJECT_GUIDE.md ka Part 1.2 wala diagram, ya report ka architecture]*

**[BOLO]**
"Ye hamara architecture hai. Left mein **client** hai, jisme ek menu hai: request, release, status. Right mein **server** hai, jo har client ke liye ek alag **thread** chalata hai."

"Beech mein **do raaste** hain. **TCP port 5000**: isse requests jaati hain, aur ye pura **encrypted** hai. **UDP port 5001**: isse chhote 'main zinda hoon' wale heartbeat jaate hain."

"TCP isliye ki request poori aur sahi order mein pahunchni chahiye. UDP isliye ki heartbeat chhota hai aur har 2 second mein dobara jaata hai, to ek kho jaye to koi baat nahi."

"Server ke andar ek **Resource Manager** hai jo resources deta hai aur deadlock pakadta hai."

"Code C mein hai, Linux par chalta hai, aur OpenSSL library use ki hai."

---

## PART 4: LIVE DEMO (6 min)

**[SCREEN]** `START_DEMO.bat` chalao. Pehli screen aayegi.

### Intro screen
**[BOLO]** "Ye server abhi chal raha hai. Isme teen resources hain: R1, R2 (ek-ek unit) aur R3 (teen units). Ab main step by step dikhata hoon." **[Enter]**

### STEP 1: Secure connection (1.5 min)
**[SCREEN]** Client connect hota hai, `req R3 2`, status, release dikhega. Neeche fingerprint dikhega.

**[BOLO]**
"Ye pehla step hai: **secure connection**. Jab client connect hota hai to pehle ek **handshake** hota hai. Isme do cheezein hoti hain."

"**Pehli: Diffie-Hellman.** Isse client aur server **bina key bheje** ek hi secret key bana lete hain. Hacker network par jo bhi dekhe, wo key nahi nikaal sakta."

"**Doosri: RSA signature.** Isse pata chalta hai ki samne wala **asli** server ya client hai. Isse man-in-the-middle attack rukta hai."

**[SCREEN]** `session-key fingerprint` wali line par ungli rakho.
**[BOLO]**
"Dekhiye, client aur server dono ka **fingerprint same** hai. Fingerprint key ka hash hai. Isse pata chalta hai ki dono ke paas **ek hi key** hai. Key khud kabhi network par nahi gayi, na hi screen par dikhayi."

"Uske baad client ne `req R3 2` bheja, server ne `GRANT` diya. Ye saara data **AES-256** se encrypted tha." **[Enter]**

### STEP 2: Deadlock (2 min)  <- ye sabse important hai, yahi mera module hai
**[BOLO]**
"Ab **deadlock**. Ye mera module hai. Dekhiye kya hota hai."

**[SCREEN]** Client C1 aur C2 ka output dikhega.
**[BOLO]**
"Pehle C1 ne R1 liya aur C2 ne R2 liya. Phir C1 ne R2 maanga, to use **WAIT** mila, kyunki R2 C2 ke paas hai. Phir C2 ne R1 maanga, jo C1 ke paas hai. Ab dono ek-dusre ka wait kar rahe hain, ye **deadlock** hai."

**[SCREEN]** `DEADLOCK cycle: C1 -> C2 -> C1 | victim: C2` wali line.
**[BOLO]**
"Server ne turant pakad liya. Server ek **wait-for graph** banata hai: agar C1, C2 ke resource ka wait kar raha hai to C1 se C2 ka arrow. Fir wo graph mein **DFS** chalata hai cycle dhoondhne ke liye. Yahan cycle mili: **C1 se C2 se wapas C1.**"

"Fir server ne **sabse kam priority wale client** C2 ko victim banaya. Uski request cancel hui, uske resources wapas liye gaye, aur C1 ko R2 mil gaya. C2 ko DENY ka message gaya aur C1 ko deadlock ka notification."

**[RUKO]**
"To deadlock **bina insaan ke** khud theek ho gaya." **[Enter]**

### STEP 3: Attacks (1 min)
**[BOLO]**
"Ab hacker ban ke dekhte hain. Do attacks hain."

**[SCREEN]** `tamper` aur `replay` ke result.
"**Tamper:** hacker ne packet ka **ek bit badla**. Humne AES-GCM use kiya hai jo ek **tag** banata hai. Bit badla to tag match nahi hua, aur server ne `integrity tag mismatch` bolke packet **reject** kar diya."

"**Replay:** hacker ne ek purana asli packet **dobara bheja**. Har packet ke saath ek **sequence number** hota hai jo sirf badhta hai. Purana number aaya to server ne `replay` bolke reject kar diya."

"Aur dekhiye, uske baad bhi `status` command sahi chala. Session safe raha." **[Enter]**

### STEP 4: Heartbeat (30 sec)
**[BOLO]**
"Ye heartbeat ka step hai. Client har 2 second mein UDP se 'main zinda hoon' bhejta hai. Yahan ek client freeze ho gaya, to **6 second ke baad** server ne use hata diya aur uske resources free kar diye. Isse koi client resource pakad ke gayab nahi ho sakta." **[Enter]**

### STEP 5: Plain vs encrypted (1 min)  <- Wireshark wala
**[BOLO]**
"Ye wahi hai jo **Wireshark** mein dikhta hai. Ek hi message `R1 1` dono tareeke se bheja."

**[SCREEN]** `PLAIN mode` wala hex dump, dahine side ASCII column.
"**Plain mode** mein dahine column mein `R1 1` saaf padh sakte hain. Hacker ko sab dikh raha hai."

**[SCREEN]** `SECURE mode` wala.
"**Secure mode** mein sirf random bytes hain. Aur dekhiye, **same message** dobara bheja to bytes **alag** aaye, kyunki har packet ka IV random hota hai. Neeche tamper aur replay dono reject dikh rahe hain." **[Enter]**

### STEP 6: Performance (30 sec)
**[BOLO]**
"Ye 20 clients ek saath chalane ka test hai. Requirement thi handshake **1 second** se kam, aur request-response **50 millisecond** se kam. Hamara result: handshake kareeb **50 millisecond**, request-response kareeb **1 millisecond**, aur **0 errors**. Sab requirements se kaafi behtar."

---

## PART 5: Conclusion (1 min)

**[BOLO]**
"To summary mein: humne ek client-server system banaya jisme **Diffie-Hellman** se key banti hai, **RSA** se pehchaan hoti hai, **AES-256-GCM** se data secure hota hai, **sequence number** se replay rukta hai, aur **wait-for graph aur DFS** se deadlock khud theek hota hai. UDP heartbeat se mare hue clients ke resources free hote hain."

"Humne **54 unit tests aur 41 integration tests** likhe hain, sab pass hue. Wireshark se traffic ka analysis kiya aur NS2 simulation ki script bhi taiyar hai."

"**Limitation** ye hai ki ye lab-level project hai. Asli duniya mein TLS use hota hai, jo isi idea par bana hai. Hamare yahan private keys par password nahi hai, aur multi-unit resources mein hum har cycle ko deadlock maan lete hain. Thank you ma'am. Koi sawal ho to bataiye."

---

## Agar ma'am beech mein kuch pooche: chhote jawab

| Sawal | Jawab (1-2 line) |
|---|---|
| Diffie-Hellman kya hai? | "Dono apne secret number se public value banate hain, ek-dusre ko bhejte hain, aur dono same shared secret nikaal lete hain. Hacker public values dekh ke secret nahi nikaal sakta." |
| RSA kyu, DH kaafi nahi? | "DH ye nahi batata ki samne **kaun** hai. Beech ka hacker dono se alag DH kar sakta hai. RSA signature se asli ya nakli pata chalta hai." |
| AES-GCM kyu? | "Encryption aur integrity tag ek saath. Alag HMAC ki zarurat nahi." |
| IV kya hai? | "12 random bytes, har packet ke liye naya. Isse same message ka ciphertext har baar alag aata hai." |
| Replay kaise rokte ho? | "Sequence number sirf badhta hai. Purana number aaye to reject." |
| TCP aur UDP dono kyu? | "Requests ko pakki delivery chahiye, isliye TCP. Heartbeat halka aur baar-baar jaata hai, isliye UDP." |
| Thread kyu? | "Har client ke liye alag thread, taaki ek ka wait doosre ko na roke. Shared table ko ek mutex lock bachata hai." |
| Deadlock kaise pakadte ho? | "Wait-for graph banate hain, DFS se cycle dhoondhte hain. Cycle mili to deadlock." |
| Victim kaun hota hai? | "Cycle mein sabse kam priority wala client, jiska ID number sabse bada ho." |
| Client crash ho jaye to? | "TCP band hone par ya 6 second heartbeat na aane par server uske resources free kar deta hai." |
| NS2 ka result? | "Script aur analysis taiyar hai. Clients badhne par throughput link limit par rukta hai aur delay aur loss badhte hain. Lab machine par run karke numbers report mein daalunga." |

**Agar kuch pata na ho:** ghabrao mat. Bolo, "Ma'am, ye hissa Ishita/Priyani ne kiya hai, main code dekh ke bata sakta hoon." Aur `docs/PROJECT_GUIDE.md` ya `docs/VIVA_QA.md` mein dhoondh lo.

---

## Teen cheezein jo ma'am ko impress karengi
1. **"Humne khud attack karke dikhaya"** (tamper, replay, fake server, nakli client). Sirf bola nahi, chala ke dikhaya.
2. **"54 + 41 tests pass hue."** Matlab project sirf demo ke liye nahi, test bhi hua hai.
3. **"Hamari limitations ye hain."** Apni kamiyan khud batana acchi baat hoti hai.

## Ek zaroori baat
NS2 ke numbers abhi nahi aaye hain. Agar ma'am NS2 ke graphs maangein to jhoot mat bolna. Bolo, "Simulation ki script taiyar hai, lab machine par run karke results report mein daalenge." Ho sake to demo se pehle lab mein `bash ns2/run_ns2.sh` chala lo.
