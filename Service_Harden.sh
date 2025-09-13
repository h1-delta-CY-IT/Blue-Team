#!/bin/bash
# -----------------------------------------
# Comprehensive Blue Team Cleanup & Hardening Script
# Works on Debian/Ubuntu and Fedora/RHEL
# Author: ChatGPT, Adapted for CTF
# Last Updated: 2025-09-12
# -----------------------------------------

set -euo pipefail

# -----------------------------
# Setup secure directories
# -----------------------------
WORKDIR="/var/lib/.hardening"
mkdir -p "$WORKDIR"/{quarantine,logs}
chmod 700 "$WORKDIR"
LOGFILE="$WORKDIR/logs/cleanup_$(date +%F_%T).log"
exec > >(tee -a "$LOGFILE") 2>&1

# -----------------------------
# User-provided files
# -----------------------------
INDICATORS_FILE="./indicators.txt"
# optional, list of suspicious filenames or process names
KEEP_FILE="./keep.txt"              # optional, extra services to preserve
HASHES_FILE="./hashes.txt"          # optional, known bad file hashes
DRY_RUN=1                           # default dry-run, use --apply to enforce

# -----------------------------
# Detect distro
# -----------------------------
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="$ID"
else
    DISTRO="unknown"
fi

log() { echo "[$(date +%F_%T)] $*"; }

# -----------------------------
# Safelist services by distro
# -----------------------------
declare -a KEEP_SERVICES
case "$DISTRO" in
    ubuntu|debian)
        KEEP_SERVICES=("sshd" "apache2" "mysql" "vsftpd" "proftpd" "systemd" "cron")
        ;;
    fedora|rhel|centos)
        KEEP_SERVICES=("sshd" "httpd" "mariadbd" "vsftpd" "proftpd" "systemd" "crond")
        ;;
    *)
        KEEP_SERVICES=("sshd" "systemd" "cron")
        ;;
esac

# Merge with extra keep.txt if exists
if [[ -f "$KEEP_FILE" ]]; then
    mapfile -t EXTRA_KEEP < "$KEEP_FILE"
    KEEP_SERVICES+=("${EXTRA_KEEP[@]}")
fi

# -----------------------------
# Helper functions
# -----------------------------
is_keep_service() {
    local proc="$1"
    for s in "${KEEP_SERVICES[@]}"; do
        [[ "$proc" == "$s" ]] && return 0
    done
    return 1
}

quarantine_file() {
    local file="$1"
    [[ -e "$file" ]] || return
    local base
    base=$(basename "$file")
    local dest="$WORKDIR/quarantine/${base}_$(date +%s)"
    if [[ $DRY_RUN -eq 1 ]]; then
        log "DRY-RUN: would quarantine $file -> $dest"
    else
        log "Quarantining $file -> $dest"
        mv -f "$file" "$dest" 2>/dev/null || cp -a "$file" "$dest" && rm -f "$file"
        chmod 600 "$dest"
    fi
}

kill_process() {
    local pid="$1" comm="$2"
    if is_keep_service "$comm"; then
        log "SAFEGUARD: Skipping kill of $comm (PID $pid)"
    else
        if [[ $DRY_RUN -eq 1 ]]; then
            log "DRY-RUN: would kill $comm (PID $pid)"
        else
            log "Killing suspicious process: $comm (PID $pid)"
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
}

check_hash() {
    local file="$1"
    [[ -f "$file" ]] || return
    local sha
    sha=$(sha256sum "$file" | awk '{print $1}')
    for h in "${HASHES[@]}"; do
        if [[ "$sha" == "$h" ]]; then
            quarantine_file "$file"
        fi
    done
}

# -----------------------------
# Argument parsing
# -----------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--indicators) INDICATORS_FILE="$2"; shift 2 ;;
        -h|--hashes) HASHES_FILE="$2"; shift 2 ;;
        --apply|--yes) DRY_RUN=0; shift ;;
        --quiet) exec &>/dev/null; shift ;;
        --help) echo "Usage: $0 [-i indicators.txt] [--hashes hashes.txt] [--apply] [--quiet]"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# -----------------------------
# Load indicators & hashes
# -----------------------------
INDICATORS=()
if [[ -f "$INDICATORS_FILE" ]]; then
    mapfile -t INDICATORS < "$INDICATORS_FILE"
fi

HASHES=()
if [[ -f "$HASHES_FILE" ]]; then
    mapfile -t HASHES < "$HASHES_FILE"
fi

log "[*] Loaded ${#INDICATORS[@]} indicators and ${#HASHES[@]} hashes"

# -----------------------------
# Step 1: Filesystem scan
# -----------------------------
log "[*] Scanning filesystem..."
SCAN_PATHS=("/etc" "/usr" "/bin" "/sbin" "/lib" "/tmp" "/var" "/home")
for path in "${SCAN_PATHS[@]}"; do
    if [[ -d "$path" ]]; then
        while IFS= read -r -d '' file; do
            base=$(basename "$file")
            for ind in "${INDICATORS[@]}"; do
                if [[ "$base" == *"$ind"* ]]; then
                    quarantine_file "$file"
                fi
            done
            check_hash "$file"
        done < <(find "$path" -type f -print0 2>/dev/null)
    fi
done

# -----------------------------
# Step 2: Running process scan
# -----------------------------
log "[*] Scanning processes..."
while read -r pid comm; do
    for ind in "${INDICATORS[@]}"; do
        if [[ "$comm" == *"$ind"* ]]; then
            kill_process "$pid" "$comm"
        fi
    done
done < <(ps -eo pid=,comm=)

# Heuristic: kill suspicious processes in /tmp or /var/tmp
log "[*] Scanning for suspicious process paths..."
while read -r pid comm path; do
    if [[ "$path" =~ ^/tmp|^/var/tmp ]]; then
        kill_process "$pid" "$comm"
    fi
done < <(ps -eo pid=,comm=,args= | awk '{print $1,$2,$3}')

# -----------------------------
# Step 3: Network listeners scan
# -----------------------------
log "[*] Checking listening ports..."
if command -v ss >/dev/null 2>&1; then
    netlist=$(ss -tulpn 2>/dev/null)
else
    netlist=$(netstat -tulpn 2>/dev/null || true)
fi
while read -r pid comm; do
    for ind in "${INDICATORS[@]}"; do
        if [[ "$comm" == *"$ind"* ]]; then
            kill_process "$pid" "$comm"
        fi
    done
done < <(echo "$netlist" | awk 'NR>1 {gsub(/[^0-9]/,"",$6); print $6, $7}' || true)

# -----------------------------
# Step 4: Persistence scan
# -----------------------------
log "[*] Scanning for cron/systemd persistence..."
CRON_DIRS=("/etc/cron.*" "/var/spool/cron" "/etc/crontab")
for f in ${CRON_DIRS[@]}; do
    if [[ -e "$f" ]]; then
        for ind in "${INDICATORS[@]}"; do
            matches=$(grep -rl "$ind" "$f" 2>/dev/null || true)
            for m in $matches; do
                quarantine_file "$m"
            done
        done
    fi
done

# Systemd timers
for t in $(systemctl list-timers --all --no-pager --no-legend | awk '{print $1}'); do
    for ind in "${INDICATORS[@]}"; do
        if [[ "$t" == *"$ind"* ]]; then
            if [[ $DRY_RUN -eq 1 ]]; then
                log "DRY-RUN: would disable timer $t"
            else
                log "Disabling suspicious timer $t"
                systemctl disable --now "$t" 2>/dev/null || true
            fi
        fi
    done
done

# -----------------------------
# Step 5: Report
# -----------------------------
log "[+] Cleanup complete. DRY_RUN=$DRY_RUN"
log "[+] Quarantine folder: $WORKDIR/quarantine"
log "[+] Log file: $LOGFILE"
log "[+] Critical services preserved: ${KEEP_SERVICES[*]}"
