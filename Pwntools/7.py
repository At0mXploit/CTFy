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
challenge_path = "/challenge/pwntools-tutorials-level2.3"
p = process(challenge_path)

# Assembly code to copy 8 bytes from 0x404000 to 0x405000
# We can use a register as an intermediary to transfer the data
# 
# Steps:
# 1. Load 8 bytes from [0x404000] into a register (e.g., rax)
# 2. Store the value from the register to [0x405000]

assembly_code = """
mov rax, [0x404000]
mov [0x405000], rax
"""

# Alternative approach using absolute addressing:
# assembly_code = """
# mov rax, 0x404000
# mov rbx, [rax]
# mov rax, 0x405000
# mov [rax], rbx
# """

# Send the payload after the prompt
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
