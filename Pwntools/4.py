from pwn import *

def print_lines(io):
    info("Printing io received lines")
    while True:
        try:
            line = io.recvline()
            success(line.decode())
        except EOFError:
            break

# Set architecture, os and log level
context(arch="amd64", os="linux", log_level="info")

# Load the ELF file and execute it as a new process.
challenge_path = "/challenge/pwntools-tutorials-level2.0"

p = process(challenge_path)

# Assembly code to set rax = 0x12345678
assembly_code = """
mov rax, 0x12345678
"""

# Send the payload after the string "(up to 0x1000 bytes): \n" is found.
# Note: The prompt in the example says "Please give me your assembly in bytes"
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
