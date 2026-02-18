#!/bin/bash

echo "=== GO DOS TOOL SETUP (LATEST VERSIONS) ==="

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
    case "$PKG_MGR" in
        "apt"|"pkg")
            $PKG_MGR update
            $PKG_MGR install -y golang
            ;;
        "pacman -S")
            pacman -S --noconfirm go
            ;;
        "yum"|"dnf")
            $PKG_MGR install -y golang
            ;;
        "brew")
            brew install go
            ;;
    esac
else
    echo "Go already installed"
fi

# Clean old module files
rm -rf go.mod go.sum

echo "Initializing Go module..."
go mod init main  

# Download latest dependencies
echo "Downloading latest dependencies..."
go get github.com/quic-go/quic-go@latest
go get golang.org/x/net@latest
go get golang.org/x/crypto@latest
go get golang.org/x/sys@latest
go get github.com/quic-go/qpack@latest

# Tidy up
echo "Running go mod tidy..."
go mod tidy

# Compile with retry mechanism
echo "Compiling..."
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    go build -o main main.go
    
    if [ -f "main" ]; then
        chmod +x main
        echo "✅ Compilation successful on attempt $((RETRY_COUNT+1))!"
        
        # Cleanup
        echo "Cleaning up..."
        rm -f main.go go.mod go.sum
        
        echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
        exit 0
    fi
    
    RETRY_COUNT=$((RETRY_COUNT+1))
    
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        echo "⚠️ Compilation failed, retrying... (Attempt $((RETRY_COUNT+1))/$MAX_RETRIES)"
        
        # Fix common issues on each retry
        case $RETRY_COUNT in
            1)
                echo "Running go mod download..."
                go mod download
                ;;
            2)
                echo "Cleaning module cache and reinstalling..."
                go clean -modcache
                go get -u ./...
                go mod tidy -go=1.21
                ;;
        esac
    fi
done

# If all retries failed, try last resort with -mod=mod
echo "⚠️ Last resort: Using -mod=mod flag..."
go build -mod=mod -o main main.go

if [ -f "main" ]; then
    chmod +x main
    echo "✅ Compilation successful with -mod=mod!"
    rm -f main.go go.mod go.sum
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
    exit 0
fi

# If everything failed
echo "❌ All compilation attempts failed!"
echo "Try running these commands manually:"
echo "  go mod init godostool"
echo "  go get github.com/quic-go/quic-go@latest"
echo "  go get golang.org/x/net@latest"
echo "  go mod tidy"
echo "  go build -o main main.go"

rm -f main.go
exit 1