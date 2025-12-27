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
challenge_path = "/challenge/pwntools-tutorials-level2.6"
p = process(challenge_path)

# Assembly code to compute: rax = sum from 1 to rcx
# 
# Pseudocode:
# rax = 0
# for (i = 1; i <= rcx; i++):
#     rax += i
#
# Steps:
# 1. Initialize rax to 0 (accumulator)
# 2. Initialize a counter (rbx) to 1
# 3. Loop: add counter to rax, increment counter
# 4. Continue until counter > rcx

assembly_code = """
xor rax, rax
mov rbx, 1
loop_start:
cmp rbx, rcx
jg loop_end
add rax, rbx
inc rbx
jmp loop_start
loop_end:
"""

# Alternative approach using rcx as the counter (counts down):
# assembly_code = """
# xor rax, rax
# mov rbx, rcx
# loop_start:
# cmp rbx, 0
# je loop_end
# add rax, rbx
# dec rbx
# jmp loop_start
# loop_end:
# """

# Send the payload after the prompt
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
