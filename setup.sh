#!/bin/bash

# ----------------------------------------
# GO DOS TOOL SETUP (HTTP/2 + HTTP/1.1 ONLY)
# ----------------------------------------

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Separator line
SEP="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

clear
echo -e "${CYAN}${SEP}${NC}"
echo -e "${WHITE}  DENIAL SERVICE OF GO${NC}"
echo -e "${CYAN}${SEP}${NC}"
echo

# Download main.go from GitHub
echo -e " ${YELLOW}➤${NC} ${GREEN}Downloading main.go...${NC}"
wget -q https://raw.githubusercontent.com/cyrenxxxxx/GO-DoS/refs/heads/main/main.go

# Check if download successful
if [ ! -f "main.go" ]; then
    echo -e " ${RED}✗ Error: Failed to download main.go${NC}"
    exit 1
else
    echo -e " ${GREEN}✓ Download complete${NC}"
fi

# FIX: Ensure utls import is correct and REMOVE crypto/tls
echo -e " ${YELLOW}➤${NC} ${GREEN}Checking imports...${NC}"

# REMOVE crypto/tls if it exists (THIS IS THE CRITICAL FIX)
if grep -q '"crypto/tls"' main.go; then
    sed -i '/"crypto\/tls"/d' main.go
    echo -e " ${GREEN}✓ Removed crypto/tls import${NC}"
else
    echo -e " ${GREEN}✓ No crypto/tls import found${NC}"
fi

# Ensure utls has proper alias
if grep -q 'utls.*github.com/refraction-networking/utls' main.go; then
    echo -e " ${GREEN}✓ utls import already correct${NC}"
else
    # Fix utls import to include alias
    sed -i 's|"github.com/refraction-networking/utls"|utls "github.com/refraction-networking/utls"|g' main.go
    echo -e " ${GREEN}✓ Fixed utls import with alias${NC}"
fi

echo

# Check OS and package manager
if [ -d "/data/data/com.termux" ]; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System detected:${NC} Termux"
    PKG_MGR="pkg"
elif command -v apt &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System detected:${NC} Debian/Ubuntu"
    PKG_MGR="apt"
elif command -v pacman &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System detected:${NC} Arch Linux"
    PKG_MGR="pacman -S"
elif command -v yum &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System detected:${NC} CentOS/RHEL"
    PKG_MGR="yum"
elif command -v dnf &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System detected:${NC} Fedora"
    PKG_MGR="dnf"
elif command -v brew &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}System detected:${NC} macOS"
    PKG_MGR="brew"
else
    echo -e " ${YELLOW}➤${NC} ${YELLOW}Unknown OS, assuming Linux with apt${NC}"
    PKG_MGR="apt"
fi

echo

# Check and install Go
if ! command -v go &> /dev/null; then
    echo -e " ${YELLOW}➤${NC} ${GREEN}Installing Go...${NC}"
    case "$PKG_MGR" in
        "apt"|"pkg")
            $PKG_MGR update > /dev/null 2>&1
            $PKG_MGR install -y golang > /dev/null 2>&1
            ;;
        "pacman -S")
            pacman -S --noconfirm go > /dev/null 2>&1
            ;;
        "yum"|"dnf")
            $PKG_MGR install -y golang > /dev/null 2>&1
            ;;
        "brew")
            brew install go > /dev/null 2>&1
            ;;
    esac
    
    if command -v go &> /dev/null; then
        echo -e " ${GREEN}✓ Go installed successfully${NC}"
    else
        echo -e " ${RED}✗ Failed to install Go${NC}"
    fi
else
    echo -e " ${GREEN}✓ Go already installed${NC}"
fi

# Check Go version
GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' 2>/dev/null || echo "0.0")
echo -e " ${YELLOW}➤${NC} ${GREEN}Go version:${NC} $GO_VERSION"

# Simple version check without bc
if [[ "$GO_VERSION" < "1.21" ]] && [[ "$GO_VERSION" != "0.0" ]]; then
    echo -e " ${RED}✗ Go 1.21+ required. Current: $GO_VERSION${NC}"
    exit 1
fi

echo

# Set Go environment
export GO111MODULE=on
export CGO_ENABLED=0

# Clean old module files
echo -e " ${YELLOW}➤${NC} ${GREEN}Cleaning old module files...${NC}"
rm -rf go.mod go.sum
echo -e " ${GREEN}✓ Cleanup complete${NC}"
echo

echo -e " ${YELLOW}➤${NC} ${GREEN}Initializing Go module...${NC}"
go mod init main > /dev/null 2>&1
echo -e " ${GREEN}✓ Module initialized${NC}"

echo

# Download dependencies (specific versions)
echo -e " ${YELLOW}➤${NC} ${GREEN}Downloading dependencies...${NC}"
go get golang.org/x/net@v0.24.0 > /dev/null 2>&1
go get golang.org/x/crypto@v0.22.0 > /dev/null 2>&1
go get golang.org/x/sys@v0.19.0 > /dev/null 2>&1
go get github.com/refraction-networking/utls@v1.6.0 > /dev/null 2>&1
echo -e " ${GREEN}✓ Dependencies downloaded${NC}"

echo

# Tidy up
echo -e " ${YELLOW}➤${NC} ${GREEN}Running go mod tidy...${NC}"
go mod tidy > /dev/null 2>&1
echo -e " ${GREEN}✓ Tidy complete${NC}"

echo
echo -e "${CYAN}${SEP}${NC}"
echo -e "${WHITE}  COMPILATION PROCESS${NC}"
echo -e "${CYAN}${SEP}${NC}"
echo

# Compile with retry mechanism
echo -e " ${YELLOW}➤${NC} ${GREEN}Compiling...${NC}"
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    echo -ne " ${YELLOW}Attempt $((RETRY_COUNT+1))/$MAX_RETRIES...${NC} "
    
    # Capture build output
    BUILD_OUTPUT=$(go build -o main main.go 2>&1)
    BUILD_EXIT_CODE=$?
    
    if [ $BUILD_EXIT_CODE -eq 0 ]; then
        chmod +x main
        echo -e "${GREEN}✓ Success!${NC}"
        echo
        
        # Cleanup
        echo -e " ${YELLOW}➤${NC} ${GREEN}Cleaning up...${NC}"
        rm -f main.go go.mod go.sum
        echo -e " ${GREEN}✓ Cleanup complete${NC}"        
        echo
        echo -e "${CYAN}${SEP}${NC}"
        echo -e "${WHITE}  SETUP COMPLETE${NC}"
        echo -e "${CYAN}${SEP}${NC}"
        echo
        echo -e " ${GREEN}►${NC} Run: ${YELLOW}./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]${NC}"
        echo
        exit 0
    else
        echo -e "${RED}✗ Failed${NC}"
        if [ -n "$BUILD_OUTPUT" ]; then
            echo -e " ${RED}Error details:${NC}"
            while IFS= read -r line; do
                echo -e "   ${RED}→${NC} $line"
            done <<< "$BUILD_OUTPUT"
        fi
    fi
    
    RETRY_COUNT=$((RETRY_COUNT+1))
    
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        echo -e " ${YELLOW}⟲ Retrying... (Attempt $((RETRY_COUNT+1))/$MAX_RETRIES)${NC}"
        
        # Fix common issues on each retry
        case $RETRY_COUNT in
            1)
                echo -e "   ${BLUE}→ Running go mod download...${NC}"
                go mod download > /dev/null 2>&1
                ;;
            2)
                echo -e "   ${BLUE}→ Cleaning module cache...${NC}"
                go clean -modcache > /dev/null 2>&1
                go get -u ./... > /dev/null 2>&1
                go mod tidy -go=1.21 > /dev/null 2>&1
                ;;
        esac
        echo
    fi
done

# If all retries failed, try with -mod=mod
echo -e " ${YELLOW}➤${NC} ${YELLOW}Last resort: Using -mod=mod flag...${NC}"
LAST_RESORT_OUTPUT=$(go build -mod=mod -o main main.go 2>&1)
LAST_RESORT_CODE=$?

if [ $LAST_RESORT_CODE -eq 0 ]; then
    chmod +x main
    echo -e " ${GREEN}✓ Compilation successful with -mod=mod!${NC}"
    echo
    echo -e " ${YELLOW}➤${NC} ${GREEN}Cleaning up...${NC}"
    rm -f main.go go.mod go.sum
    echo -e " ${GREEN}✓ Cleanup complete${NC}"
    
    echo
    echo -e "${CYAN}${SEP}${NC}"
    echo -e "${WHITE}  SETUP COMPLETE${NC}"
    echo -e "${CYAN}${SEP}${NC}"
    echo
    echo -e " ${GREEN}►${NC} Run: ${YELLOW}./main <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]${NC}"
    echo
    exit 0
else
    if [ -n "$LAST_RESORT_OUTPUT" ]; then
        echo -e " ${RED}Final error:${NC}"
        while IFS= read -r line; do
            echo -e "   ${RED}→${NC} $line"
        done <<< "$LAST_RESORT_OUTPUT"
    fi
fi

echo
echo -e "${CYAN}${SEP}${NC}"
echo -e "${WHITE}  SETUP FAILED${NC}"
echo -e "${CYAN}${SEP}${NC}"
echo

# If everything failed
echo -e " ${RED}✗ All compilation attempts failed!${NC}"
echo
echo -e " ${YELLOW}➤${NC} ${GREEN}Try running these commands manually:${NC}"
echo
echo -e "   ${BLUE}1.${NC} go mod init main"
echo -e "   ${BLUE}2.${NC} go get golang.org/x/net@v0.24.0"
echo -e "   ${BLUE}3.${NC} go get golang.org/x/crypto@v0.22.0"
echo -e "   ${BLUE}4.${NC} go get golang.org/x/sys@v0.19.0"
echo -e "   ${BLUE}5.${NC} go get github.com/refraction-networking/utls@v1.6.0"
echo -e "   ${BLUE}6.${NC} go mod tidy"
echo -e "   ${BLUE}7.${NC} go build -o main main.go"
echo

rm -f main.go
exit 1