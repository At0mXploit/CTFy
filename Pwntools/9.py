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
challenge_path = "/challenge/pwntools-tutorials-level2.5"
p = process(challenge_path)

# Assembly code to compute: top_of_stack = abs(top_of_stack)
# 
# Logic (if statement):
# if (value < 0):
#     value = -value
# 
# Steps:
# 1. Pop the top value into a register
# 2. Check if it's negative (test the sign bit)
# 3. If negative, negate it
# 4. Push the result back

assembly_code = """
pop rax
cmp rax, 0
jge positive
neg rax
positive:
push rax
"""

# Alternative approach using conditional move:
# assembly_code = """
# pop rax
# mov rbx, rax
# neg rbx
# cmp rax, 0
# cmovl rax, rbx
# push rax
# """

# Send the payload after the prompt
p.sendafter("Please give me your assembly in bytes", asm(assembly_code))

print_lines(p)
