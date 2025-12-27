from pwn import *

# Set architecture, os and log level
context(arch="amd64", os="linux", log_level="debug")

# Load the ELF file and execute it as a new process
challenge_path = "/challenge/pwntools-tutorials-level3.0"
p = process(challenge_path)

# Wait for the initial message
p.recvuntil(b"We have a magic notebook for you:")

# Create notebook at index 0 with content "hello "
info("Creating notebook 0 with 'hello '")
p.recvuntil(b"Choice >> ")
p.sendline(b"1")  # Create
p.recvuntil(b"Input your notebook index:")
p.sendline(b"0")  # Index 0
p.recvuntil(b"Input your notebook content:")
p.send(b"hello \x00")  # Content with null terminator

# Create notebook at index 1 with content "world,"
info("Creating notebook 1 with 'world,'")
p.recvuntil(b"Choice >> ")
p.sendline(b"1")  # Create
p.recvuntil(b"Input your notebook index:")
p.sendline(b"1")  # Index 1
p.recvuntil(b"Input your notebook content:")
p.send(b"world,\x00")  # Content with null terminator

# Edit notebook at index 1 to set status to ABANDONED
info("Editing notebook 1 to ABANDONED status")
p.recvuntil(b"Choice >> ")
p.sendline(b"2")  # Edit
p.recvuntil(b"Input your notebook index:")
p.sendline(b"1")  # Index 1

# Create notebook at index 3 with content "magic "
info("Creating notebook 3 with 'magic '")
p.recvuntil(b"Choice >> ")
p.sendline(b"1")  # Create
p.recvuntil(b"Input your notebook index:")
p.sendline(b"3")  # Index 3
p.recvuntil(b"Input your notebook content:")
p.send(b"magic \x00")  # Content with null terminator

# Create notebook at index 5 with content "notebook"
info("Creating notebook 5 with 'notebook'")
p.recvuntil(b"Choice >> ")
p.sendline(b"1")  # Create
p.recvuntil(b"Input your notebook index:")
p.sendline(b"5")  # Index 5
p.recvuntil(b"Input your notebook content:")
p.send(b"notebook\x00")  # Content with null terminator

# Edit notebook at index 5 to set status to ABANDONED
info("Editing notebook 5 to ABANDONED status")
p.recvuntil(b"Choice >> ")
p.sendline(b"2")  # Edit
p.recvuntil(b"Input your notebook index:")
p.sendline(b"5")  # Index 5

# Select option 5 (Gift for You) to trigger bypass_me() and read flag
info("Selecting option 5 to get the flag")
p.recvuntil(b"Choice >> ")
p.sendline(b"5")  # Gift for You

# Receive all remaining output
flag_output = p.recvall(timeout=2)
success("Output received:")
print(flag_output.decode())

p.close()
