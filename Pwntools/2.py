from pwn import *

# Set architecture, os and log level
context(arch="amd64", os="linux", log_level="info")

# Load the ELF file and execute it as a new process.
challenge_path = "/challenge/pwntools-tutorials-level1.0"
p = process(challenge_path)

# Pack 0xdeadbeef as 32-bit little-endian, then add newline for fgets()
payload = p32(0xdeadbeef) + b'\n'
# Send the payload after the string ":)\n###\n" is found.
p.sendafter(":)\n###\n", payload)

# Receive flag from the process
flag = p.recvline()
print(f"flag is: {flag}")
