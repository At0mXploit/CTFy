from pwn import *

# Set architecture, os and log level
context(arch="amd64", os="linux", log_level="info")

# Load the ELF file and execute it as a new process.
challenge_path = "/challenge/pwntools-tutorials-level1.1"
p = process(challenge_path)

# Construct payload step by step
payload = b'p'                    # buf[0] = 'p' (ASCII)
payload += p8(0x15)               # buf[1] = 0x15 (hex value)
payload += p32(123456789)         # bytes 2-5 = 123456789 as 32-bit little-endian
payload += b'Bypass Me:)'         # bytes 6-16 = string "Bypass Me:)"
payload += b'\n'                  # newline for fgets()

# Send the payload after the string ":)\n###\n" is found.
p.sendafter(":)\n###\n", payload)

# Receive flag from the process
flag = p.recvline()
print(f"flag is: {flag}")
