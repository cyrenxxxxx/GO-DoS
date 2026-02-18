#!/bin/bash

echo "=== GO DOS TOOL SETUP ==="

# Check OS
if [ -d "/data/data/com.termux" ]; then
    echo "Termux detected"
    PKG_MGR="pkg"
elif command -v apt &> /dev/null; then
    echo "Debian/Ubuntu detected"
    PKG_MGR="apt"
elif command -v pacman &> /dev/null; then
    echo "Arch Linux detected"
    PKG_MGR="pacman -S"
elif command -v yum &> /dev/null; then
    echo "CentOS/RHEL detected"
    PKG_MGR="yum"
elif command -v dnf &> /dev/null; then
    echo "Fedora detected"
    PKG_MGR="dnf"
elif command -v brew &> /dev/null; then
    echo "macOS detected"
    PKG_MGR="brew"
else
    echo "Unknown OS, assuming Linux with apt"
    PKG_MGR="apt"
fi

# Check and install Go
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    if [ "$PKG_MGR" = "apt" ]; then
        $PKG_MGR update
        $PKG_MGR install -y golang
    elif [ "$PKG_MGR" = "pacman -S" ]; then
        $PKG_MGR go
    elif [ "$PKG_MGR" = "yum" ] || [ "$PKG_MGR" = "dnf" ]; then
        $PKG_MGR install -y golang
    elif [ "$PKG_MGR" = "brew" ]; then
        $PKG_MGR install go
    elif [ "$PKG_MGR" = "pkg" ]; then
        $PKG_MGR update
        $PKG_MGR install -y golang
    fi
else
    echo "Go already installed"
fi

# Check main.go exists
if [ ! -f "main.go" ]; then
    echo "Error: main.go not found"
    exit 1
fi

# Setup Go modules and dependencies
echo "Initializing Go module..."
go mod init attack 2>/dev/null

echo "Downloading dependencies..."
go get github.com/quic-go/quic-go@latest
go get golang.org/x/net/http2@latest
go mod tidy

# Compile
echo "Compiling..."
go build -o main main.go
chmod +x main

# Cleanup
echo "Cleaning up..."
rm -f go.mod go.sum

echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"