#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SEP="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MAIN_URL="https://raw.githubusercontent.com/cyrenxxxxx/GO-DoS/refs/heads/main/main.go"

clear
echo -e "${CYAN}${SEP}${NC}"
echo -e "${WHITE}  DENIAL SERVICE OF GO (utls build)${NC}"
echo -e "${CYAN}${SEP}${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}Downloading main.go...${NC}"
if command -v curl &> /dev/null; then
    curl -fsSL "$MAIN_URL" -o main.go
elif command -v wget &> /dev/null; then
    wget -q "$MAIN_URL" -O main.go
else
    echo -e " ${RED}✗ Need curl or wget${NC}"
    exit 1
fi

if [ ! -s "main.go" ]; then
    echo -e " ${RED}✗ Failed to download main.go${NC}"
    exit 1
fi
echo -e " ${GREEN}✓ Download complete${NC}"

if ! grep -q 'refraction-networking/utls' main.go; then
    echo -e " ${RED}✗ Downloaded main.go is NOT the utls version${NC}"
    echo -e " ${YELLOW}➤${NC} Push the new utls main.go to your repo first."
    rm -f main.go
    exit 1
fi
echo -e " ${GREEN}✓ utls import confirmed${NC}"
echo

if [ -d "/data/data/com.termux" ]; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} Termux"
    PKG_MGR="pkg"; PKG_UPDATE="pkg update"; PKG_INSTALL="pkg install -y"
elif command -v dnf &> /dev/null && grep -qi "rhel\|fedora\|centos" /etc/os-release 2>/dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} RHEL/Fedora/CentOS"
    PKG_MGR="dnf"; PKG_UPDATE="dnf check-update"; PKG_INSTALL="dnf install -y"
elif command -v pacman &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} Arch Linux"
    PKG_MGR="pacman"; PKG_UPDATE="pacman -Sy"; PKG_INSTALL="pacman -S --noconfirm"
elif command -v apt &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} Debian/Ubuntu"
    PKG_MGR="apt"; PKG_UPDATE="apt update"; PKG_INSTALL="apt install -y"
elif command -v zypper &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} openSUSE"
    PKG_MGR="zypper"; PKG_UPDATE="zypper refresh"; PKG_INSTALL="zypper install -y"
elif command -v apk &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} Alpine Linux"
    PKG_MGR="apk"; PKG_UPDATE="apk update"; PKG_INSTALL="apk add"
elif command -v yum &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} Old RHEL/CentOS"
    PKG_MGR="yum"; PKG_UPDATE="yum check-update"; PKG_INSTALL="yum install -y"
elif command -v brew &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System:${NC} macOS"
    PKG_MGR="brew"; PKG_UPDATE="brew update"; PKG_INSTALL="brew install"
else
    echo -e " ${YELLOW}➤${NC} ${YELLOW}Unknown OS, assuming apt${NC}"
    PKG_MGR="apt"; PKG_UPDATE="apt update"; PKG_INSTALL="apt install -y"
fi
echo

if ! command -v go &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}Installing Go...${NC}"
    if [[ "$PKG_MGR" == "pacman" ]]; then
        $PKG_INSTALL go > /dev/null 2>&1
    elif [[ "$PKG_MGR" == "brew" ]]; then
        $PKG_INSTALL go > /dev/null 2>&1
    else
        if [ "$EUID" -ne 0 ]; then
            sudo $PKG_UPDATE > /dev/null 2>&1
            sudo $PKG_INSTALL golang > /dev/null 2>&1
        else
            $PKG_UPDATE > /dev/null 2>&1
            $PKG_INSTALL golang > /dev/null 2>&1
        fi
    fi
    if ! command -v go &> /dev/null; then
        echo -e " ${RED}✗ Failed to install Go. Install manually: https://go.dev/dl/${NC}"
        exit 1
    fi
    echo -e " ${GREEN}✓ Go installed${NC}"
else
    echo -e " ${GREEN}✓ Go already installed${NC}"
fi

GO_VERSION=$(go version | sed -nE 's/.*go([0-9]+\.[0-9]+).*/\1/p')
[ -z "$GO_VERSION" ] && GO_VERSION="0.0"
echo -e " ${YELLOW}➤${NC} ${GREEN}Go version:${NC} $GO_VERSION"

if ! awk -v ver="$GO_VERSION" 'BEGIN{if(ver+0 < 1.21) exit 1; exit 0}'; then
    echo -e " ${RED}✗ Go 1.21+ required. Current: $GO_VERSION${NC}"
    exit 1
fi
echo

export GO111MODULE=on
export CGO_ENABLED=0

echo -e " ${YELLOW}➤${NC} ${GREEN}Resetting module files...${NC}"
rm -rf go.mod go.sum
echo -e " ${GREEN}✓ Done${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}go mod init...${NC}"
go mod init main > /dev/null 2>&1
echo -e " ${GREEN}✓ Done${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}Fetching dependencies (utls + x/net + x/crypto + x/sys)...${NC}"
go get github.com/refraction-networking/utls@latest > /dev/null 2>&1 || {
    echo -e " ${RED}✗ utls fetch failed${NC}"; exit 1;
}
go get golang.org/x/net@latest > /dev/null 2>&1 || {
    echo -e " ${RED}✗ x/net fetch failed${NC}"; exit 1;
}
go get golang.org/x/crypto@latest > /dev/null 2>&1 > /dev/null
go get golang.org/x/sys@latest > /dev/null 2>&1 > /dev/null
echo -e " ${GREEN}✓ Dependencies fetched${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}go mod tidy...${NC}"
if ! go mod tidy 2>&1 | tail -5; then
    echo -e " ${RED}✗ go mod tidy failed${NC}"
    exit 1
fi
echo -e " ${GREEN}✓ Tidy complete${NC}"
echo

echo -e "${CYAN}${SEP}${NC}"
echo -e "${WHITE}  COMPILATION${NC}"
echo -e "${CYAN}${SEP}${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}Building...${NC}"
BUILD_OUTPUT=$(go build -o main main.go 2>&1)
BUILD_CODE=$?

if [ $BUILD_CODE -ne 0 ]; then
    echo -e " ${RED}✗ Build failed${NC}"
    while IFS= read -r line; do
        echo -e "   ${RED}→${NC} $line"
    done <<< "$BUILD_OUTPUT"
    echo
    echo -e " ${YELLOW}➤${NC} Main files left intact for debugging (main.go, go.mod, go.sum)"
    exit 1
fi

chmod +x main
echo -e " ${GREEN}✓ Build success${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}Cleaning main.go / go.mod / go.sum...${NC}"
rm -f main.go go.mod go.sum
echo -e " ${GREEN}✓ Cleanup done${NC}"
echo

echo -e "${CYAN}${SEP}${NC}"
echo -e "${WHITE}  SETUP COMPLETE${NC}"
echo -e "${CYAN}${SEP}${NC}"
echo
echo -e " ${GREEN}►${NC} Run: ${YELLOW}./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]${NC}"
echo
exit 0