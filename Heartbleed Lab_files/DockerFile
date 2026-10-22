FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    openssl \
    curl \
    wget \
    net-tools \
    iputils-ping \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab

CMD ["/bin/bash"]
