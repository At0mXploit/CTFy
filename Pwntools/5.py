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
challenge_path = "/challenge/pwntools-tutorials-level2.1"

p = process(challenge_path)

# Assembly code to exchange rax and rbx
# Using xchg instruction
assembly_code = """
xchg rax, rbx
"""

# Alternative solution using a temporary register:
# assembly_code = """
# mov rcx, rax
# mov rax, rbx
# mov rbx, rcx
# """

# Send the payload after the prompt
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
