#!/bin/bash

echo "=== GO DOS TOOL SETUP (HTTP/2 + HTTP/1.1 ONLY) ==="

# Download main.go from GitHub
echo "Downloading main.go..."
wget -q https://raw.githubusercontent.com/cyrenxxxxx/GO-DoS/refs/heads/main/main.go
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

# Get Go version
GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1)
echo "Detected Go version: $GO_VERSION"

# Clean old module files
rm -rf go.mod go.sum

echo "Initializing Go module..."
go mod init main

# ===== SMART DEPENDENCY MANAGEMENT =====
# Choose compatible versions based on Go version
if (( $(echo "$GO_VERSION >= 1.24" | bc -l) )); then
    echo "Go $GO_VERSION detected - using latest dependencies"
    NET_VERSION="latest"
    CRYPTO_VERSION="latest"
    SYS_VERSION="latest"
elif (( $(echo "$GO_VERSION >= 1.21" | bc -l) )); then
    echo "Go $GO_VERSION detected - using compatible v0.23.0"
    NET_VERSION="v0.23.0"
    CRYPTO_VERSION="v0.23.0"
    SYS_VERSION="v0.18.0"
elif (( $(echo "$GO_VERSION >= 1.19" | bc -l) )); then
    echo "Go $GO_VERSION detected - using older v0.17.0"
    NET_VERSION="v0.17.0"
    CRYPTO_VERSION="v0.17.0"
    SYS_VERSION="v0.15.0"
else
    echo "Go $GO_VERSION detected - using legacy v0.4.0"
    NET_VERSION="v0.4.0"
    CRYPTO_VERSION="v0.4.0"
    SYS_VERSION="v0.4.0"
fi

echo "Downloading dependencies..."
go get golang.org/x/net@$NET_VERSION
go get golang.org/x/crypto@$CRYPTO_VERSION
go get golang.org/x/sys@$SYS_VERSION

# Tidy up with version-specific flags
echo "Running go mod tidy..."
if (( $(echo "$GO_VERSION >= 1.21" | bc -l) )); then
    go mod tidy -go=1.21
else
    go mod tidy
fi

# ===== FALLBACK MECHANISM =====
compile_with_version() {
    local version=$1
    echo "Trying fallback with golang.org/x/net@$version..."
    
    go get golang.org/x/net@$version
    go get golang.org/x/crypto@$version
    go get golang.org/x/sys@$version
    
    if (( $(echo "$GO_VERSION >= 1.21" | bc -l) )); then
        go mod tidy -go=1.21
    else
        go mod tidy
    fi
    
    go build -o main main.go
    return $?
}

# Compile with retry mechanism
echo "Compiling..."
MAX_RETRIES=5
RETRY_COUNT=0
FALLBACK_VERSIONS=("v0.23.0" "v0.21.0" "v0.19.0" "v0.17.0" "v0.15.0" "v0.13.0" "v0.11.0" "v0.9.0" "v0.7.0" "v0.5.0" "v0.4.0")

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    go build -o main main.go 2>/tmp/go_error.log
    
    if [ -f "main" ]; then
        chmod +x main
        echo "✅ Compilation successful on attempt $((RETRY_COUNT+1))!"
        
        # Cleanup
        echo "Cleaning up..."
        rm -f main.go go.mod go.sum
        
        echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW|TLS-*> [proxy]"
        exit 0
    fi
    
    # Check if error is version mismatch
    if grep -q "requires go" /tmp/go_error.log; then
        echo "⚠️ Version mismatch detected!"
        
        # Try fallback versions
        for ver in "${FALLBACK_VERSIONS[@]}"; do
            echo "Trying fallback with golang.org/x/net@$ver..."
            go get golang.org/x/net@$ver
            go get golang.org/x/crypto@$ver
            go get golang.org/x/sys@$ver
            
            if (( $(echo "$GO_VERSION >= 1.21" | bc -l) )); then
                go mod tidy -go=1.21
            else
                go mod tidy
            fi
            
            go build -o main main.go 2>/dev/null
            if [ -f "main" ]; then
                chmod +x main
                echo "✅ Compilation successful with fallback $ver!"
                rm -f main.go go.mod go.sum
                echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW|TLS-*> [proxy]"
                exit 0
            fi
        done
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
            3)
                echo "Trying with -mod=mod flag..."
                go build -mod=mod -o main main.go
                if [ -f "main" ]; then
                    chmod +x main
                    echo "✅ Compilation successful with -mod=mod!"
                    rm -f main.go go.mod go.sum
                    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW|TLS-*> [proxy]"
                    exit 0
                fi
                ;;
            4)
                echo "LAST RESORT: Creating new module from scratch..."
                rm -rf go.mod go.sum
                go mod init main
                go get golang.org/x/net@v0.17.0
                go get golang.org/x/crypto@v0.17.0
                go get golang.org/x/sys@v0.15.0
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
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW|TLS-*> [proxy]"
    exit 0
fi

# If everything failed
echo "❌ All compilation attempts failed!"
echo "Try running these commands manually based on your Go version ($GO_VERSION):"

if (( $(echo "$GO_VERSION >= 1.24" | bc -l) )); then
    echo "  go mod init main"
    echo "  go get golang.org/x/net@latest"
    echo "  go get golang.org/x/crypto@latest"
    echo "  go get golang.org/x/sys@latest"
elif (( $(echo "$GO_VERSION >= 1.21" | bc -l) )); then
    echo "  go mod init main"
    echo "  go get golang.org/x/net@v0.23.0"
    echo "  go get golang.org/x/crypto@v0.23.0"
    echo "  go get golang.org/x/sys@v0.18.0"
else
    echo "  go mod init main"
    echo "  go get golang.org/x/net@v0.17.0"
    echo "  go get golang.org/x/crypto@v0.17.0"
    echo "  go get golang.org/x/sys@v0.15.0"
fi
echo "  go mod tidy -go=1.21"
echo "  go build -o main main.go"

rm -f main.go
exit 1