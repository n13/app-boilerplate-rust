#!/usr/bin/env python3
"""Send a GetPubkey APDU to Speculos and print the Dilithium public key."""
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

# Connect to Speculos APDU proxy
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
print(f"Connected to Speculos on {HOST}:{PORT}")

# Build GetPubkey APDU (CLA=0xE0, INS=0x05, P1=0x00 no display, P2=0x00)
# BIP32 path: m/44'/189189'/0'/0'/0'
path = struct.pack('>BIIIII',
    5,           # 5 components
    0x8000002C,  # 44'
    0x8002E305,  # 189189'
    0x80000000,  # 0'
    0x80000000,  # 0'
    0x80000000,  # 0'
)

apdu = bytes([0xE0, 0x05, 0x00, 0x00, len(path)]) + path
print(f"Sending APDU: {apdu.hex()}")

# Send: 4-byte big-endian length prefix + APDU
s.sendall(struct.pack('>I', len(apdu)) + apdu)

# Read response: 4-byte length prefix + data + 2-byte status word
raw_len = s.recv(4)
resp_len = struct.unpack('>I', raw_len)[0]
resp = b''
while len(resp) < resp_len:
    chunk = s.recv(resp_len - len(resp))
    if not chunk:
        break
    resp += chunk

status = struct.unpack('>H', resp[-2:])[0]
data = resp[:-2]

print(f"\nStatus: 0x{status:04X} ({'OK' if status == 0x9000 else 'ERROR'})")
print(f"Response length: {len(data)} bytes")

if status == 0x9000 and len(data) >= 2:
    pk_len = struct.unpack('>H', data[:2])[0]
    pk = data[2:]
    print(f"Public key length: {pk_len}")
    print(f"Public key bytes received: {len(pk)}")
    print(f"Public key (hex): {pk.hex()}")
else:
    print(f"Raw response: {data.hex()}")

s.close()
