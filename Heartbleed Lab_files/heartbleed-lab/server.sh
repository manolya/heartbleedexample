#!/bin/bash
# keep the "secret" resident in heap near the SSL buffers
export SECRET="$(cat /srv/secret.txt)"

OPENSSL=/usr/local/openssl-vuln/bin/openssl
echo "[*] vulnerable openssl: $($OPENSSL version)"
echo "[*] TLS server up on :4433 — heap is primed, waiting for heartbeats"

# -www serves a trivial page so a browser/curl generates heap activity
exec $OPENSSL s_server -key /srv/key.pem -cert /srv/cert.pem \
     -accept 4433 -www
