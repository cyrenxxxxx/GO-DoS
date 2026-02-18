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

# Initialize with proper module name (FIXED: hindi na "attack")
echo "Initializing Go module..."
go mod init godostool

# Download dependencies with specific compatible versions (FIXED)
echo "Downloading dependencies..."
go get github.com/quic-go/quic-go@v0.48.2
go get golang.org/x/net@v0.24.0
go get golang.org/x/crypto@v0.22.0
go get golang.org/x/sys@v0.19.0
go get github.com/quic-go/qpack@v0.4.0

# Tidy up
echo "Running go mod tidy..."
go mod tidy

# Compile
echo "Compiling..."
go build -o main main.go

# Check compilation status
COMPILE_STATUS=$?
if [ $COMPILE_STATUS -eq 0 ] && [ -f "main" ]; then
    chmod +x main
    echo "✅ Compilation successful!"
    
    # Cleanup
    echo "Cleaning up..."
    rm -f main.go go.mod go.sum
    
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
    exit 0
fi

# ===== FALLBACK METHODS =====
echo "⚠️ Compilation failed with standard versions. Trying fallback methods..."

# Fallback 1: Try older but stable versions
echo "Fallback 1: Using older stable versions..."
rm -rf go.mod go.sum
go mod init godostool
go get github.com/quic-go/quic-go@v0.42.0
go get golang.org/x/net@v0.19.0
go get golang.org/x/crypto@v0.21.0
go mod tidy
go build -o main main.go

if [ -f "main" ]; then
    chmod +x main
    echo "✅ Fallback 1 successful!"
    rm -f main.go go.mod go.sum
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
    exit 0
fi

# Fallback 2: Use go get without versions
echo "Fallback 2: Using go get without versions..."
rm -rf go.mod go.sum
go mod init godostool
go get github.com/quic-go/quic-go
go get golang.org/x/net
go mod tidy
go build -o main main.go

if [ -f "main" ]; then
    chmod +x main
    echo "✅ Fallback 2 successful!"
    rm -f main.go go.mod go.sum
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
    exit 0
fi

# Fallback 3: Last resort with -mod=mod flag
echo "Fallback 3: Last resort with -mod=mod..."
rm -rf go.mod go.sum
go mod init godostool
go get github.com/quic-go/quic-go@latest
go get golang.org/x/net@latest
go build -mod=mod -o main main.go

if [ -f "main" ]; then
    chmod +x main
    echo "✅ Fallback 3 successful!"
    rm -f main.go go.mod go.sum
    echo "Done! Run: ./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]"
    exit 0
fi

# If all fallbacks failed
echo "❌ All compilation attempts failed!"
echo "Please check your Go installation and internet connection."
rm -f main.go
exit 1