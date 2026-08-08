FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    build-essential \
    wget \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget https://www.sudo.ws/dist/sudo-1.8.31.tar.gz && \
    tar xzf sudo-1.8.31.tar.gz && \
    cd sudo-1.8.31 && \
    ./configure && \
    make && \
    make install

RUN useradd -m tester && echo "tester:password" | chpasswd

USER tester
WORKDIR /home/tester
CMD ["/bin/bash"]
