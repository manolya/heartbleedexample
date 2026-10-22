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

# plant a fake "secret" in server memory so the leak is visible
RUN echo "TOPSECRET-FLAG=the_cake_is_a_lie_42" > /srv/secret.txt

COPY server.sh /srv/server.sh
RUN chmod +x /srv/server.sh

ENV LD_LIBRARY_PATH=/usr/local/openssl-vuln/lib
EXPOSE 4433
CMD ["/srv/server.sh"]
