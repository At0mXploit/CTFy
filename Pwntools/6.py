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
challenge_path = "/challenge/pwntools-tutorials-level2.2"
p = process(challenge_path)

# Assembly code to calculate: rax = rax % rbx + rcx - rsi
# We need to be careful with the order of operations
# Option 1: Use a temporary register to avoid clobbering values

assembly_code = """
mov r8, rax
mov rax, r8
xor rdx, rdx
div rbx
mov rax, rdx
add rax, rcx
sub rax, rsi
"""

# Alternative: Since rdx is already 0, we can try:
# assembly_code = """
# div rbx
# add rdx, rcx
# sub rdx, rsi
# mov rax, rdx
# """

# Send the payload after the prompt
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
