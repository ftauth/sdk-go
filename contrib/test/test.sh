#!/bin/sh

apt update && \
    apt install -y \
    ca-certificates \
    git \
    make \
    curl \
    wget

# Install Go
cd /
wget https://golang.org/dl/go1.16.linux-amd64.tar.gz
tar xvf go1.16.linux-amd64.tar.gz
export PATH=$PATH:/go/bin

# Run tests
cd sdk-go
export FTAUTH_SERVER_HOST=ftauth
export FTAUTH_SERVER_PORT=8080
make test