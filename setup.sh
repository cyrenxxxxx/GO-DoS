#!/bin/bash

echo "=== C DOS TOOL SETUP (HTTP/2 + HTTP/1.1) ==="

# Download main.c from GitHub
echo "Downloading main.c..."
wget -q https://raw.githubusercontent.com/cyrenxxxxx/GO-DoS/refs/heads/main/main.c

# Check if download successful
if [ ! -f "main.c" ]; then
    echo "Error: Failed to download main.c"
    exit 1
fi

# Try to update package lists (ignore errors)
echo "Trying to update package lists..."
apt update 2>/dev/null || pkg update 2>/dev/null || echo "Skipping update"

# Try to install gcc
echo "Trying to install gcc..."
apt install -y gcc 2>/dev/null || pkg install -y gcc 2>/dev/null || echo "gcc may already be installed"

# Try to install libcurl dev
echo "Trying to install libcurl dev..."
apt install -y libcurl4-openssl-dev 2>/dev/null || pkg install -y libcurl 2>/dev/null

# Try to install OpenSSL dev
echo "Trying to install OpenSSL dev..."
apt install -y libssl-dev 2>/dev/null || pkg install -y openssl 2>/dev/null

# Try to install nghttp2 dev
echo "Trying to install nghttp2 dev..."
apt install -y libnghttp2-dev 2>/dev/null || pkg install -y nghttp2 2>/dev/null

echo "pthread should be built-in"

# Compile - try Termux path first, then normal
echo "Compiling with -D_GNU_SOURCE for CPU affinity and libcurl..."

if [ -d "/data/data/com.termux" ]; then
    gcc -o main main.c -lssl -lcrypto -lnghttp2 -pthread -lm -lcurl -O3 -D_GNU_SOURCE -I$PREFIX/include -L$PREFIX/lib
else
    gcc -o main main.c -lssl -lcrypto -lnghttp2 -pthread -lm -lcurl -O3 -D_GNU_SOURCE
fi

# Check if compilation successful
if [ -f "main" ]; then
    chmod +x main
    echo "Compilation successful!"
    
    # Cleanup source file
    echo "Cleaning up..."
    rm -f main.c
    
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
    exit 0
else
    echo "Compilation failed!"
    exit 1
fi