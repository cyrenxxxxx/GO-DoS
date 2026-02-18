#!/bin/bash

echo "=== GO DOS TOOL SETUP ==="

# Download main.go from GitHub
echo "Downloading main.go..."
wget -q https://raw.githubusercontent.com/cyrenxxxxx/GO-DoS/main/main.go

# Check if download successful
if [ ! -f "main.go" ]; then
    echo "Error: Failed to download main.go"
    exit 1
fi

# Check OS and package manager
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

# Setup Go modules and dependencies
echo "Initializing Go module..."
go mod init attack 2>/dev/null

echo "Downloading dependencies..."
go get github.com/quic-go/quic-go@latest
go get golang.org/x/net/http2@latest
go mod tidy

# ===== FALLBACK FOR MODULE ERRORS =====
echo "Checking for module errors..."
if [ $? -ne 0 ] || [ -f "go.sum" ] && grep -q "should not have @version" go.mod 2>/dev/null; then
    echo "Module error detected! Running fallback..."
    
    # Clear module cache
    echo "Cleaning module cache..."
    go clean -modcache
    
    # Re-download dependencies
    echo "Re-downloading dependencies..."
    go mod download
    
    # Retry tidy
    echo "Retrying go mod tidy..."
    go mod tidy
fi

# Compile
echo "Compiling..."
go build -o main main.go

# Check if compilation succeeded
if [ $? -ne 0 ]; then
    echo "Compilation failed! Trying alternative method..."
    
    # Alternative: download dependencies manually
    go get -u all
    go mod vendor
    go build -o main main.go
    
    if [ $? -ne 0 ]; then
        echo "Still failing. Last resort: resetting Go module..."
        rm -rf go.mod go.sum
        go mod init attack
        go get github.com/quic-go/quic-go@latest
        go get golang.org/x/net/http2@latest
        go build -o main main.go
    fi
fi

chmod +x main

# Cleanup
echo "Cleaning up..."
rm -f main.go go.mod go.sum

echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"