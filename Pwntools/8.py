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
challenge_path = "/challenge/pwntools-tutorials-level2.4"
p = process(challenge_path)

# Assembly code to compute: top_of_stack = top_of_stack - rbx
# Using push and pop as preferred by the challenge
#
# Steps:
# 1. Pop the top value of the stack into a register (e.g., rax)
# 2. Subtract rbx from that register
# 3. Push the result back onto the stack

assembly_code = """
pop rax
sub rax, rbx
push rax
"""

# Send the payload after the prompt
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
