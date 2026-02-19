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

# Check OS and package manager
if [ -d "/data/data/com.termux" ]; then
    echo "Termux detected"
    PKG_MGR="termux"
elif command -v apt &> /dev/null; then
    echo "Debian/Ubuntu detected"
    PKG_MGR="apt"
elif command -v pacman &> /dev/null; then
    echo "Arch Linux detected"
    PKG_MGR="pacman"
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
    echo "Unknown OS, assuming Debian/Ubuntu"
    PKG_MGR="apt"
fi

# Update package lists
echo "Updating package lists..."
case "$PKG_MGR" in
    "termux")
        pkg update
        ;;
    "apt")
        apt update
        ;;
    "pacman")
        pacman -Sy
        ;;
    "yum"|"dnf")
        $PKG_MGR check-update
        ;;
    "brew")
        brew update
        ;;
esac

# Check and install gcc
if ! command -v gcc &> /dev/null; then
    echo "Installing gcc..."
    case "$PKG_MGR" in
        "termux")
            pkg install -y gcc
            ;;
        "apt")
            apt install -y gcc
            ;;
        "pacman")
            pacman -S --noconfirm gcc
            ;;
        "yum"|"dnf")
            $PKG_MGR install -y gcc
            ;;
        "brew")
            brew install gcc
            ;;
    esac
else
    echo "gcc already installed"
fi

# Check and install libcurl dev
echo "Checking libcurl..."
case "$PKG_MGR" in
    "termux")
        if ! command -v curl-config &> /dev/null; then
            echo "Installing libcurl for Termux..."
            pkg install -y libcurl
        else
            echo "libcurl already installed"
        fi
        ;;
    "apt")
        if ! dpkg -l | grep -q libcurl4-openssl-dev; then
            echo "Installing libcurl4-openssl-dev..."
            apt install -y libcurl4-openssl-dev
        else
            echo "libcurl4-openssl-dev already installed"
        fi
        ;;
    "pacman")
        if ! pacman -Q libcurl &> /dev/null; then
            echo "Installing libcurl..."
            pacman -S --noconfirm libcurl
        else
            echo "libcurl already installed"
        fi
        ;;
    "yum"|"dnf")
        if ! rpm -q libcurl-devel &> /dev/null; then
            echo "Installing libcurl-devel..."
            $PKG_MGR install -y libcurl-devel
        else
            echo "libcurl-devel already installed"
        fi
        ;;
    "brew")
        if ! brew list curl &> /dev/null; then
            echo "Installing curl..."
            brew install curl
        else
            echo "curl already installed"
        fi
        ;;
esac

# Check and install OpenSSL dev
echo "Checking OpenSSL..."
case "$PKG_MGR" in
    "termux")
        if ! command -v openssl &> /dev/null; then
            echo "Installing openssl for Termux..."
            pkg install -y openssl
        else
            echo "openssl already installed"
        fi
        ;;
    "apt")
        if ! dpkg -l | grep -q libssl-dev; then
            echo "Installing libssl-dev..."
            apt install -y libssl-dev
        else
            echo "libssl-dev already installed"
        fi
        ;;
    "pacman")
        if ! pacman -Q openssl &> /dev/null; then
            echo "Installing openssl..."
            pacman -S --noconfirm openssl
        else
            echo "openssl already installed"
        fi
        ;;
    "yum"|"dnf")
        if ! rpm -q openssl-devel &> /dev/null; then
            echo "Installing openssl-devel..."
            $PKG_MGR install -y openssl-devel
        else
            echo "openssl-devel already installed"
        fi
        ;;
    "brew")
        if ! brew list openssl &> /dev/null; then
            echo "Installing openssl..."
            brew install openssl
        else
            echo "openssl already installed"
        fi
        ;;
esac

# Check and install nghttp2
echo "Checking nghttp2..."
case "$PKG_MGR" in
    "termux")
        if ! command -v nghttp2 &> /dev/null; then
            echo "Installing nghttp2 for Termux..."
            pkg install -y nghttp2
        else
            echo "nghttp2 already installed"
        fi
        ;;
    "apt")
        if ! dpkg -l | grep -q libnghttp2-dev; then
            echo "Installing libnghttp2-dev..."
            apt install -y libnghttp2-dev
        else
            echo "libnghttp2-dev already installed"
        fi
        ;;
    "pacman")
        if ! pacman -Q libnghttp2 &> /dev/null; then
            echo "Installing libnghttp2..."
            pacman -S --noconfirm libnghttp2
        else
            echo "libnghttp2 already installed"
        fi
        ;;
    "yum"|"dnf")
        if ! rpm -q libnghttp2-devel &> /dev/null; then
            echo "Installing libnghttp2-devel..."
            $PKG_MGR install -y libnghttp2-devel
        else
            echo "libnghttp2-devel already installed"
        fi
        ;;
    "brew")
        if ! brew list nghttp2 &> /dev/null; then
            echo "Installing nghttp2..."
            brew install nghttp2
        else
            echo "nghttp2 already installed"
        fi
        ;;
esac

echo "pthread should be built-in"

# Compile with optimization
echo "Compiling with -D_GNU_SOURCE for CPU affinity and libcurl..."

# Special handling for Termux
if [ "$PKG_MGR" = "termux" ]; then
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